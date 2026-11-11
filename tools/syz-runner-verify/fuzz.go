// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
)

// targetSpec is the subset of target.json that the fuzz mode needs.
// tools/syz-direct-cover uses the same file for report generation.
type targetSpec struct {
	TargetFunc string `json:"target_func"`
	Path       string `json:"path"`
	CloseFuncs []struct {
		Func string `json:"func"`
	} `json:"close_funcs"`
}

// targetSet holds the call-site PCs of the target function and of the nearby
// functions. KCOV output is translated to call-site PCs before the lookup, so
// both sides speak the same address space.
type targetSet struct {
	funcName string
	path     string
	targetPC map[uint64]struct{}
	nearbyPC map[uint64]struct{}
}

func buildTargetSet(cfg *mgrconfig.Config, file string) (*targetSet, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read target JSON: %w", err)
	}
	var spec targetSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parse target JSON: %w", err)
	}
	spec.Path = filepath.ToSlash(filepath.Clean(spec.Path))
	if spec.TargetFunc == "" || spec.Path == "." || filepath.IsAbs(spec.Path) {
		return nil, fmt.Errorf("target JSON: target_func and a relative source path are required")
	}
	modules := []*vminfo.KernelModule{{Path: filepath.Join(cfg.KernelObj, cfg.SysTarget.KernelObject)}}
	rg, err := cover.MakeReportGenerator(cfg, modules)
	if err != nil {
		return nil, fmt.Errorf("load vmlinux coverage: %w", err)
	}
	ts := &targetSet{
		funcName: spec.TargetFunc,
		path:     spec.Path,
		targetPC: make(map[uint64]struct{}),
		nearbyPC: make(map[uint64]struct{}),
	}
	nearbyNames := make(map[string]bool)
	for _, f := range spec.CloseFuncs {
		if f.Func != "" {
			nearbyNames[f.Func] = true
		}
	}
	targetSyms := 0
	for _, s := range rg.Symbols {
		if s.Module == nil || s.Module.Name != "" || s.Unit == nil {
			continue // only vmlinux; module addresses are unknown
		}
		switch {
		case s.Name == spec.TargetFunc && s.Unit.Name == spec.Path:
			targetSyms++
			addPCs(ts.targetPC, s.PCs)
		case nearbyNames[s.Name]:
			addPCs(ts.nearbyPC, s.PCs)
		}
	}
	if targetSyms == 0 || len(ts.targetPC) == 0 {
		return nil, fmt.Errorf("target %q in %q has no KCOV-instrumented vmlinux symbol (%d matches)",
			spec.TargetFunc, spec.Path, targetSyms)
	}
	// A nearby function can be the target itself; keep the two priorities disjoint.
	for pc := range ts.targetPC {
		delete(ts.nearbyPC, pc)
	}
	return ts, nil
}

func addPCs(dst map[uint64]struct{}, pcs []uint64) {
	for _, pc := range pcs {
		dst[pc] = struct{}{}
	}
}

// blockResult is the coverage observed by one execution block (N runs of one
// program). newTarget/newNearby are computed against the global seen sets.
type blockResult struct {
	execs     int
	failures  int
	crashed   bool
	perCall   map[int]map[uint64]struct{}
	target    map[uint64]struct{}
	nearby    map[uint64]struct{}
	newTarget map[uint64]struct{}
	newNearby map[uint64]struct{}
}

type fuzzEvent struct {
	Time      string `json:"time"`
	Kind      string `json:"kind"`
	Program   string `json:"program,omitempty"`
	Parent    string `json:"parent,omitempty"`
	Anchor    int    `json:"anchor_call"`
	Execs     int    `json:"execs"`
	NewTarget int    `json:"new_target_pcs"`
	NewNearby int    `json:"new_nearby_pcs"`
	SeenPCs   int    `json:"seen_target_pcs"`
	Note      string `json:"note,omitempty"`
}

type fuzzRun struct {
	ctx context.Context
	rm  *aflow.RunnerManager
	cfg *mgrconfig.Config
	ts  *targetSet

	outdir string
	execs  int
	chunk  int
	rnd    *rand.Rand
	ct     *prog.ChoiceTable
	seeds  []*prog.Prog
	events *json.Encoder

	union      map[uint64]struct{}
	seenTarget map[uint64]struct{}
	seenNearby map[uint64]struct{}
	crashSeen  int
	saturated  bool
}

func runFuzz(ctx context.Context, cfg *mgrconfig.Config, rm *aflow.RunnerManager,
	target *prog.Target, seeds []*prog.Prog) error {
	ts, err := buildTargetSet(cfg, *flagTarget)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "target: %v (%v), %v KCOV-instrumented PCs; nearby: %v PCs\n",
		ts.funcName, ts.path, len(ts.targetPC), len(ts.nearbyPC))

	if err := os.MkdirAll(*flagOutDir, 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	fd, err := os.OpenFile(filepath.Join(*flagOutDir, "fuzz.jsonl"),
		os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("create event log: %w", err)
	}
	defer fd.Close()

	seed := *flagRandSeed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	f := &fuzzRun{
		ctx:        ctx,
		rm:         rm,
		cfg:        cfg,
		ts:         ts,
		outdir:     *flagOutDir,
		execs:      *flagExecs,
		chunk:      max(1, *flagVMs**flagProcs),
		rnd:        rand.New(rand.NewSource(seed)),
		ct:         target.BuildChoiceTable(seeds, nil),
		seeds:      seeds,
		events:     json.NewEncoder(fd),
		union:      make(map[uint64]struct{}),
		seenTarget: make(map[uint64]struct{}),
		seenNearby: make(map[uint64]struct{}),
	}
	defer f.writeCoverUnion()
	f.logf("fuzz mode: %v execs per program, %v concurrent slots, random seed %v",
		f.execs, f.chunk, seed)

	// Anchor per parent program: the call whose arguments are worth mutating.
	// It is recomputed from each accepted block's actual per-call coverage.
	anchors := make(map[string]int)
	// Seed programs keep stable names so a reset draw always lands on a program
	// whose anchor was already computed.
	seedNames := make([]string, len(seeds))
	for i, seed := range seeds {
		seedNames[i] = f.saveProg(fmt.Sprintf("seed_%02d", i), seed)
	}

	// Baseline: characterize every seed and locate its anchor call. Seeds are
	// assumed to reach the target function, so this is not a reachability check.
	// Each block also gives the seed a chance to crash on its own.
	parent, parentName := seeds[0], seedNames[0]
	bestSeen := -1
	for i, seed := range seeds {
		res, err := f.execBlock(seed, seedNames[i])
		if err != nil {
			return err
		}
		anchors[seedNames[i]] = f.pickAnchor(res)
		f.logBlock("baseline", seedNames[i], "", anchors[seedNames[i]], res)
		if res.crashed {
			return nil
		}
		if len(res.target) == 0 {
			// Seeds are supposed to reach the target function; zero target PCs
			// usually means a wrong target.json, a wrong kernel build, or a seed
			// that no longer reaches the function.
			f.logf("WARNING: seed %v hit no target-function PCs; mutation has no gradient from it",
				seedNames[i])
		}
		if seen := len(res.target); seen > bestSeen {
			parent, parentName, bestSeen = seed, seedNames[i], seen
		}
	}
	f.checkSaturation()

	for block := 1; ; block++ {
		if err := f.ctx.Err(); err != nil {
			f.logf("stopping: %v", err)
			return nil
		}
		// A crash report can arrive just after a block finished; catch it before
		// spending another full block on a pool that already found the bug.
		if len(f.rm.RecentCrashes()) > f.crashSeen {
			f.saveCrash(parent, parentName)
			return nil
		}
		base, baseName := parent, parentName
		if f.rnd.Float64() < *flagResetProb {
			i := f.rnd.Intn(len(seeds))
			base, baseName = seeds[i], seedNames[i]
		}
		cand := f.mutate(base, anchors[baseName])
		if cand == nil {
			continue // mutation produced an identical program, try another draw
		}
		candName := fmt.Sprintf("cand_%04d", block) + ".syz"
		res, err := f.execBlock(cand, candName)
		if err != nil {
			return err
		}
		f.logBlock("mutant", candName, baseName, anchors[baseName], res)
		if res.crashed {
			// execBlock saved the program and report; the run is over.
			return nil
		}
		if len(res.newTarget) != 0 {
			// Keep only candidates that advanced the target function.
			f.saveProg(strings.TrimSuffix(candName, ".syz"), cand)
			parent, parentName = cand, candName
			anchors[candName] = f.pickAnchor(res)
			f.checkSaturation()
		}
	}
}

func (f *fuzzRun) logf(format string, args ...any) {
	fmt.Fprintf(out, format+"\n", args...)
}

func (f *fuzzRun) logEvent(ev fuzzEvent) {
	ev.Time = time.Now().Format(time.RFC3339)
	if err := f.events.Encode(ev); err != nil {
		log.Logf(0, "failed to write fuzz event: %v", err)
	}
}

func (f *fuzzRun) logBlock(kind, progName, parentName string, anchor int, res *blockResult) {
	ev := fuzzEvent{
		Kind:      kind,
		Program:   progName,
		Parent:    parentName,
		Anchor:    anchor,
		Execs:     res.execs,
		NewTarget: len(res.newTarget),
		NewNearby: len(res.newNearby),
		SeenPCs:   len(f.seenTarget),
	}
	if res.crashed {
		ev.Note = "crash"
	}
	f.logEvent(ev)
	crashNote := ""
	if res.crashed {
		crashNote = " CRASH"
	}
	f.logf("%s %v: %v execs, %v failed, %v target PCs (%v new), %v nearby PCs (%v new)%v",
		kind, progName, res.execs, res.failures,
		len(res.target), len(res.newTarget), len(res.nearby), len(res.newNearby), crashNote)
}

// execBlock runs p n times across the whole VM pool, in chunks sized to the
// pool. Executions are submitted concurrently: the concurrency is what matters
// for timing-dependent bugs, while the total count is what matters for coverage.
func (f *fuzzRun) execBlock(p *prog.Prog, progName string) (*blockResult, error) {
	res := &blockResult{
		perCall:   make(map[int]map[uint64]struct{}),
		target:    make(map[uint64]struct{}),
		nearby:    make(map[uint64]struct{}),
		newTarget: make(map[uint64]struct{}),
		newNearby: make(map[uint64]struct{}),
	}
	for done := 0; done < f.execs; done += f.chunk {
		if f.ctx.Err() != nil {
			break
		}
		size := min(f.chunk, f.execs-done)
		batch := make([]*prog.Prog, size)
		for i := range batch {
			batch[i] = p
		}
		crashesBefore := len(f.rm.RecentCrashes())
		results, err := f.rm.SubmitBatch(f.ctx, batch)
		if err != nil {
			if f.ctx.Err() != nil {
				return res, nil // time budget exhausted mid-block
			}
			return nil, err
		}
		for _, r := range results {
			if r == nil {
				res.failures++
				continue
			}
			switch r.Status {
			case queue.Success:
				res.execs++
			case queue.Crashed:
				res.crashed = true
			default:
				res.failures++
			}
			if r.Info == nil {
				continue
			}
			for j, call := range r.Info.Calls {
				f.collectCall(res, j, call.Cover)
			}
			if r.Info.Extra != nil {
				f.collectCall(res, -1, r.Info.Extra.Cover)
			}
		}
		if res.crashed || len(f.rm.RecentCrashes()) > crashesBefore {
			res.crashed = true
			f.saveCrash(p, progName)
			break
		}
	}
	for pc := range res.target {
		if _, ok := f.seenTarget[pc]; !ok {
			res.newTarget[pc] = struct{}{}
		}
		f.seenTarget[pc] = struct{}{}
	}
	for pc := range res.nearby {
		if _, ok := f.seenNearby[pc]; !ok {
			res.newNearby[pc] = struct{}{}
		}
		f.seenNearby[pc] = struct{}{}
	}
	return res, nil
}

func (f *fuzzRun) collectCall(res *blockResult, call int, cover []uint64) {
	if len(cover) == 0 {
		return
	}
	pcs := f.translate(cover)
	if res.perCall[call] == nil {
		res.perCall[call] = make(map[uint64]struct{})
	}
	for _, pc := range pcs {
		f.union[pc] = struct{}{}
		res.perCall[call][pc] = struct{}{}
		if _, ok := f.ts.targetPC[pc]; ok {
			res.target[pc] = struct{}{}
		} else if _, ok := f.ts.nearbyPC[pc]; ok {
			res.nearby[pc] = struct{}{}
		}
	}
}

// translate always produces call-site PCs. Unlike the verification mode, fuzz
// mode has no -raw option: its PC sets are matched against call-site addresses
// from the kernel backend, so an untranslated PC would never match.
func (f *fuzzRun) translate(cover []uint64) []uint64 {
	return backend.PreviousInstructionPCs(f.cfg.SysTarget, f.cfg.Type, cover)
}

// pickAnchor returns the call that covers the most target PCs, then nearby
// PCs, and falls back to the last call.
func (f *fuzzRun) pickAnchor(res *blockResult) int {
	bestCall, bestScore := -1, 0
	for call, pcs := range res.perCall {
		if call < 0 {
			continue
		}
		score := 0
		for pc := range pcs {
			if _, ok := f.ts.targetPC[pc]; ok {
				score += 100
			} else if _, ok := f.ts.nearbyPC[pc]; ok {
				score++
			}
		}
		if score > bestScore {
			bestCall, bestScore = call, score
		}
	}
	if bestCall >= 0 {
		return bestCall
	}
	return -1 // caller falls back to the last call
}

// mutate builds one candidate from base. It returns nil if several attempts
// produce an identical program (nothing to execute).
func (f *fuzzRun) mutate(base *prog.Prog, anchor int) *prog.Prog {
	baseData := base.Serialize()
	for range 8 {
		p := base.Clone()
		if f.rnd.Float64() < *flagStructProb {
			p.MutateWithOpts(f.rnd, prog.RecommendedCalls, f.ct, nil, f.seeds, prog.DefaultMutateOpts)
		} else {
			call := anchor
			if call < 0 || call >= len(p.Calls) {
				call = len(p.Calls) - 1
			}
			if call < 0 {
				continue
			}
			p.MutateCallArgOpts(f.rnd, call, f.ct, 2,
				prog.MutateOpts{SkipResourceArgs: true, MutateArgCount: 2})
		}
		if !bytes.Equal(p.Serialize(), baseData) {
			return p
		}
	}
	return nil
}

func (f *fuzzRun) saveProg(tag string, p *prog.Prog) string {
	name := tag + ".syz"
	if err := os.WriteFile(filepath.Join(f.outdir, name), p.Serialize(), 0644); err != nil {
		log.Logf(0, "failed to save program %v: %v", name, err)
	}
	return name
}

// saveCrash persists the program that was executing and every crash report
// collected so far. All executors run programs submitted by this tool, so each
// report is attributable to the current block; reports that were already
// written by an earlier block are not repeated.
func (f *fuzzRun) saveCrash(p *prog.Prog, progName string) {
	idx := f.crashSeen
	fmt.Fprintf(out, "=== crash while executing %v; saving program and report\n", progName)
	f.saveProg(fmt.Sprintf("crash_%04d", idx), p)
	reports := f.rm.RecentCrashes()
	for ; f.crashSeen < len(reports); f.crashSeen++ {
		rep := reports[f.crashSeen]
		name := filepath.Join(f.outdir, fmt.Sprintf("crash_%04d.txt", f.crashSeen))
		text := fmt.Sprintf("title: %v\nprogram: %v\n\n%s\n", rep.Title, progName, rep.Report)
		if err := os.WriteFile(name, []byte(text), 0644); err != nil {
			log.Logf(0, "failed to save crash report %v: %v", name, err)
		}
		fmt.Fprintf(out, "crash title: %v\n", rep.Title)
	}
}

// writeCoverUnion persists every call-site PC seen during the fuzz run, in the
// same format as -coverfile in verification mode, so syz-direct-cover can be
// run against the result.
func (f *fuzzRun) writeCoverUnion() {
	if *flagCover == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(*flagCover), 0755); err != nil {
		log.Logf(0, "failed to create coverfile directory: %v", err)
		return
	}
	pcs := make([]uint64, 0, len(f.union))
	for pc := range f.union {
		pcs = append(pcs, pc)
	}
	slices.Sort(pcs)
	var buf strings.Builder
	for _, pc := range pcs {
		fmt.Fprintf(&buf, "0x%x\n", pc)
	}
	if err := os.WriteFile(*flagCover, []byte(buf.String()), 0644); err != nil {
		log.Logf(0, "failed to write coverfile %v: %v", *flagCover, err)
		return
	}
	fmt.Fprintf(out, "=== wrote %v unique PCs to %v\n", len(pcs), *flagCover)
}

// checkSaturation reports when every target-function callback point has been
// seen. Mutation still continues: a crash is not a coverage event, so a fully
// covered function can still be triggered, but there is no longer a coverage
// gradient to guide the search.
func (f *fuzzRun) checkSaturation() {
	if f.saturated || len(f.seenTarget) < len(f.ts.targetPC) {
		return
	}
	f.saturated = true
	f.logf("WARNING: all %v target-function PCs are covered; mutation has no coverage gradient left",
		len(f.ts.targetPC))
	f.logEvent(fuzzEvent{Kind: "saturated", SeenPCs: len(f.seenTarget)})
}
