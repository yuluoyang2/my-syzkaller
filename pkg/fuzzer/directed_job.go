// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"slices"
	"sort"
	"sync/atomic"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

const (
	directedNeedRuns = 3
	directedMaxRuns  = 20
)

// directedTriage carries one program-level coverage confirmation. C triage and
// K verification share it, so a mutation is admitted and rewarded at most once.
type directedTriage struct {
	// witness is the K witness observed for the confirmed StableCover.
	witness corpus.DirectedWitness
	// witnesses is the union of the item's old K obligations and witness.
	witnesses []corpus.DirectedWitness
	parent    string

	covers    [][]uint64
	stable    []uint64
	confirmed bool
	settled   bool
	savedK    atomic.Bool
	// failed stops further minimization replays. It does not invalidate the
	// original program's already confirmed coverage or its settled reward.
	failed atomic.Bool
}

type directedRun struct {
	cover  []uint64
	signal signal.Signal
}

func (fuzzer *Fuzzer) directedCoverage() *corpus.DirectedCoverage {
	if fuzzer.Config == nil || fuzzer.Config.Corpus == nil {
		return nil
	}
	return fuzzer.Config.Corpus.DirectedCoverage()
}

func (fuzzer *Fuzzer) directedCandidate(p *prog.Prog, res *queue.Result) corpus.DirectedWitness {
	if !fuzzer.Config.IsDirect {
		return corpus.DirectedWitness{}
	}
	cov := fuzzer.directedCoverage()
	if cov == nil {
		return corpus.DirectedWitness{}
	}
	pcs, ok := directedRunCover(p, res)
	if !ok {
		return corpus.DirectedWitness{}
	}
	return fuzzer.Config.Corpus.DirectedWitness(pcs)
}

func (fuzzer *Fuzzer) newDirectedTriage(p *prog.Prog, parent string,
	witness corpus.DirectedWitness) *directedTriage {
	ret := &directedTriage{parent: parent, witness: witness}
	item := fuzzer.Config.Corpus.Item(hash.String(p.Serialize()))
	if item != nil && item.Directed != nil {
		for _, w := range item.Directed.Witnesses {
			w.PCs = slices.Clone(w.PCs)
			ret.witnesses = append(ret.witnesses, w)
		}
	}
	return ret
}

func (job *triageJob) directedFinalize() bool {
	d := job.directed
	if d == nil || len(d.covers) < directedNeedRuns {
		return false
	}
	d.stable = intersectCover(d.covers[:directedNeedRuns])
	d.confirmed = true
	d.witness = job.fuzzer.Config.Corpus.DirectedWitness(d.stable)
	if !d.witness.Empty() && !containsWitness(d.witnesses, d.witness) {
		w := d.witness
		w.PCs = slices.Clone(w.PCs)
		d.witnesses = append(d.witnesses, w)
	}
	return true
}

func (job *triageJob) settleDirected(pcs []uint64) {
	d := job.directed
	if d == nil || d.settled {
		return
	}
	d.settled = true
	job.fuzzer.recordDirectedGain(d.parent, pcs)
}

func (fuzzer *Fuzzer) recordDirectedGain(parent string, pcs []uint64) {
	if fuzzer.directedCoverage() == nil {
		return
	}
	if parent != "" {
		fuzzer.Config.Corpus.RecordDirectedGain(parent, pcs)
	} else if len(pcs) != 0 {
		// Generated programs and re-confirmed corpus seeds establish the
		// discovery baseline, but do not reward a parent mutation.
		fuzzer.Config.Corpus.RestoreDirectedGainHistory(pcs)
	}
}

func (job *triageJob) saveDirected(p *prog.Prog, call int, cover []uint64,
	stableSignal, newSignal signal.Signal) bool {
	d := job.directed
	if d == nil {
		return false
	}
	input := corpus.NewInput{
		Prog:     p,
		Call:     call,
		Signal:   stableSignal,
		Cover:    cover,
		RawCover: cover,
	}
	if !d.confirmed {
		// C and K are independent admission reasons. Keep the verified C
		// program without claiming that its missing/truncated K cover is zero.
		if newSignal.Empty() {
			return false
		}
		job.fuzzer.Config.Corpus.Save(input)
		return true
	}
	ok := job.fuzzer.Config.Corpus.SaveDirected(input, cover, d.witness, newSignal)
	if ok && !d.witness.Empty() {
		d.savedK.Store(true)
	}
	return ok
}

// minimizeDirected normalizes a program while preserving both C signal
// (including priority) and every K witness. It re-executes the candidate and
// uses only three valid, program-level StableCover runs.
func (job *triageJob) minimizeDirected(call int, info *triageCall) (
	*prog.Prog, int, []uint64, signal.Signal) {
	job.info.Logf("[call #%d] directed minimize started", call)
	originalCall := call
	mode := prog.MinimizeCorpus
	if job.fuzzer.Config.PatchTest {
		mode = prog.MinimizeCallsOnly
	}
	var lastCover []uint64
	var lastSignal signal.Signal
	p, call := prog.Minimize(job.p, call, mode, func(p1 *prog.Prog, call1 int) bool {
		if job.directed.failed.Load() {
			return false
		}
		runs := job.directedConfirm(p1, call1, info.errno)
		if len(runs) < directedNeedRuns {
			return false
		}
		stable := intersectCover(runCovers(runs))
		for _, w := range job.directed.witnesses {
			if !job.fuzzer.directedCoverage().Satisfies(stable, w) {
				job.info.Logf("[call #%d] directed minimization loses K witness", call)
				return false
			}
		}
		stableSignal := intersectSignal(runs)
		if info.newStableSignal.Intersection(stableSignal).Len() != info.newStableSignal.Len() {
			job.info.Logf("[call #%d] directed minimization loses C signal", call)
			return false
		}
		lastCover, lastSignal = stable, stableSignal
		job.info.Logf("[call #%d] directed minimization step success (|calls| = %d)",
			call, len(p1.Calls))
		return true
	})
	if job.directed.failed.Load() {
		// A crash/hang in a simplification does not invalidate the original
		// program's previously confirmed C/K witnesses.
		return job.p, originalCall, job.directed.stable, info.stableSignal
	}
	if lastCover == nil {
		lastCover, lastSignal = job.directed.stable, info.stableSignal
	}
	return p, call, lastCover, lastSignal
}

// saveDirectedOnly handles K-only programs, which have no C triage call.
func (job *triageJob) saveDirectedOnly() bool {
	d := job.directed
	if d == nil || !d.confirmed || d.witness.Empty() {
		return false
	}
	cover := d.stable
	p := job.p
	if len(d.witnesses) != 0 && !d.failed.Load() {
		mode := prog.MinimizeCorpus
		if job.fuzzer.Config.PatchTest {
			mode = prog.MinimizeCallsOnly
		}
		p2, _ := prog.Minimize(p, -1, mode, func(p1 *prog.Prog, _ int) bool {
			if job.directed.failed.Load() {
				return false
			}
			runs := job.directedConfirm(p1, -1, 0)
			if len(runs) < directedNeedRuns {
				return false
			}
			stable := intersectCover(runCovers(runs))
			for _, w := range d.witnesses {
				if !job.fuzzer.directedCoverage().Satisfies(stable, w) {
					return false
				}
			}
			cover = stable
			return true
		})
		p = p2
	}
	if d.failed.Load() {
		p, cover = job.p, d.stable
	}
	if job.saveDirected(p, -1, cover, nil, nil) {
		return true
	}
	return false
}

func (job *triageJob) directedConfirm(p *prog.Prog, call int, oldErrno int32) []directedRun {
	var runs []directedRun
	for attempts := 0; attempts < directedMaxRuns && len(runs) < directedNeedRuns; attempts++ {
		req := &queue.Request{
			Prog:     p,
			ExecOpts: setFlags(flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagCollectSignal),
			Stat:     job.fuzzer.statExecMinimize,
		}
		if call >= 0 {
			req.ReturnAllSignal = []int{call}
		}
		// Internal confirmation must not create another C/K triage job for
		// progress that this job has not yet committed to the corpus.
		res := job.execute(req, progInTriage)
		if res.Stop() {
			if res.Status == queue.ExecFailure && job.fuzzer.ctx.Err() == nil {
				continue
			}
			job.directed.failed.Store(true)
			return nil
		}
		cover, ok := directedRunCover(p, res)
		if !ok {
			continue
		}
		if call >= 0 && !reexecutionSuccess(res.Info, oldErrno, call) {
			continue
		}
		runs = append(runs, directedRun{
			cover:  cover,
			signal: getSignalAndCover(p, res.Info, call),
		})
	}
	return runs
}

func runCovers(runs []directedRun) [][]uint64 {
	ret := make([][]uint64, 0, len(runs))
	for _, run := range runs {
		ret = append(ret, run.cover)
	}
	return ret
}

func intersectSignal(runs []directedRun) signal.Signal {
	if len(runs) < directedNeedRuns {
		return nil
	}
	ret := runs[0].signal
	for _, run := range runs[1:directedNeedRuns] {
		ret = ret.Intersection(run.signal)
	}
	return ret
}

func directedRunCover(p *prog.Prog, res *queue.Result) ([]uint64, bool) {
	if res.Status != queue.Success || res.Info == nil || len(res.Info.Calls) != len(p.Calls) {
		return nil, false
	}
	for _, call := range res.Info.Calls {
		if !validDirectedCall(call) {
			return nil, false
		}
	}
	// Extra coverage is written with CallFlag::NONE, so only its overflow bit
	// can be checked here.
	if res.Info.Extra != nil && res.Info.Extra.Flags&flatrpc.CallFlagCoverageOverflow != 0 {
		return nil, false
	}
	set := make(map[uint64]struct{})
	for _, call := range res.Info.Calls {
		for _, pc := range call.Cover {
			set[pc] = struct{}{}
		}
	}
	if res.Info.Extra != nil {
		for _, pc := range res.Info.Extra.Cover {
			set[pc] = struct{}{}
		}
	}
	ret := make([]uint64, 0, len(set))
	for pc := range set {
		ret = append(ret, pc)
	}
	sort.Slice(ret, func(i, j int) bool { return ret[i] < ret[j] })
	return ret, true
}

func validDirectedCall(call *flatrpc.CallInfo) bool {
	const want = flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished
	return call != nil && call.Flags&want == want &&
		call.Flags&flatrpc.CallFlagCoverageOverflow == 0
}

func intersectCover(covers [][]uint64) []uint64 {
	if len(covers) < directedNeedRuns {
		return nil
	}
	seen := make(map[uint64]struct{}, len(covers[0]))
	for _, pc := range covers[0] {
		seen[pc] = struct{}{}
	}
	for _, cover := range covers[1:directedNeedRuns] {
		next := make(map[uint64]struct{}, len(seen))
		for pc := range seen {
			if _, ok := slices.BinarySearch(cover, pc); ok {
				next[pc] = struct{}{}
			}
		}
		seen = next
	}
	ret := make([]uint64, 0, len(seen))
	for pc := range seen {
		ret = append(ret, pc)
	}
	sort.Slice(ret, func(i, j int) bool { return ret[i] < ret[j] })
	return ret
}

func containsWitness(witnesses []corpus.DirectedWitness, w corpus.DirectedWitness) bool {
	return slices.ContainsFunc(witnesses, func(prev corpus.DirectedWitness) bool {
		return prev.Level == w.Level && prev.DepthLevel == w.DepthLevel &&
			prev.MinCount == w.MinCount && slices.Equal(prev.PCs, w.PCs)
	})
}
