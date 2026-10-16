// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"cmp"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"sync"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/prog"
)

const (
	directTierCap        = 32
	directTemplateBase   = 100
	directTemplateRare   = 100
	templateMinRuns      = 3
	templateMinNeedHits  = 2
	directMinMaxExecs    = 64
	directCandidateTries = 2
	directPendingTotal   = 60
	directPendingPerPC   = 4
)

var directTiers = []struct {
	name   string
	weight int
}{
	{"A", 16},
	{"B", 8},
	{"C", 4},
	{"D", 2},
}

type directCandidateKind string

const (
	directCallCandidate  directCandidateKind = "call"
	directExtraCandidate directCandidateKind = "extra"
)

// directPool keeps one exemplar program per syscall-name sequence.
// Cold-start chains have no coverage. Corpus prefixes are scored by focus tier,
// then by how rare their tier PCs are, then by length.
type directPool struct {
	mu         sync.Mutex
	byKey      map[string]*directTemplate
	byTier     map[string][]*directTemplate
	pcCount    map[uint64]int
	minRunning bool

	// pending holds programs that matched a focus area on the triggering cover.
	// They enter byKey only after a fresh execution reproduces stable focus PCs.
	pending      map[string]*directCandidate
	pendingOrder map[string][]*directCandidate
	pendingPC    map[uint64]int
	attempts     map[string]directAttempt
}

type directAttempt struct {
	tries    int
	tierRank int
}

type directCandidate struct {
	id       string
	kind     directCandidateKind
	prog     *prog.Prog
	hit      int
	tier     string
	tierRank int
	pcs      map[uint64]struct{}
	tries    int
	length   int
}

type directTemplate struct {
	key      string
	kind     directCandidateKind
	seq      []string
	prog     *prog.Prog
	hitCall  int
	tier     string
	tierRank int
	pcs      map[uint64]struct{}
	length   int
	cold     bool
}

type pickedTemplate struct {
	prog *prog.Prog
	hit  int
	kind directCandidateKind
}

// DirectTemplateInfo is a read-only view of a template currently used by the fuzzer.
type DirectTemplateInfo struct {
	ID       string
	Tier     string
	Cold     bool
	Kind     string
	Sequence string
	HitCall  string
	Calls    int
	CoverPCs int
}

type DirectTemplateSnapshot struct {
	Templates []DirectTemplateInfo
	Pending   int
	Verifying bool
	Cold      int
	Verified  int
}

func (fuzzer *Fuzzer) DirectTemplates() DirectTemplateSnapshot {
	if fuzzer.templates == nil {
		return DirectTemplateSnapshot{}
	}
	return fuzzer.templates.snapshot()
}

func (fuzzer *Fuzzer) DirectTemplateProgram(id string) ([]byte, bool) {
	if fuzzer.templates == nil {
		return nil, false
	}
	return fuzzer.templates.program(id)
}

func (pool *directPool) snapshot() DirectTemplateSnapshot {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	snapshot := DirectTemplateSnapshot{
		Pending:   len(pool.pending),
		Verifying: pool.minRunning,
	}
	for _, t := range pool.byKey {
		hitCall := "whole program"
		if t.hitCall >= 0 && t.hitCall < len(t.seq) {
			hitCall = fmt.Sprintf("#%d %s", t.hitCall, t.seq[t.hitCall])
		}
		snapshot.Templates = append(snapshot.Templates, DirectTemplateInfo{
			ID:       hash.String(t.key),
			Tier:     t.tier,
			Cold:     t.cold,
			Kind:     string(t.kind),
			Sequence: strings.Join(t.seq, " → "),
			HitCall:  hitCall,
			Calls:    t.length,
			CoverPCs: len(t.pcs),
		})
		if t.cold {
			snapshot.Cold++
		} else {
			snapshot.Verified++
		}
	}
	slices.SortFunc(snapshot.Templates, func(a, b DirectTemplateInfo) int {
		if n := cmp.Compare(directTierRank(a.Tier), directTierRank(b.Tier)); n != 0 {
			return n
		}
		if a.Cold != b.Cold {
			if a.Cold {
				return 1
			}
			return -1
		}
		if n := cmp.Compare(a.Sequence, b.Sequence); n != 0 {
			return n
		}
		return cmp.Compare(a.Kind, b.Kind)
	})
	return snapshot
}

func (pool *directPool) program(id string) ([]byte, bool) {
	pool.mu.Lock()
	var p *prog.Prog
	for _, t := range pool.byKey {
		if t.prog != nil && hash.String(t.key) == id {
			p = t.prog.Clone()
			break
		}
	}
	pool.mu.Unlock()
	if p == nil {
		return nil, false
	}
	return p.Serialize(), true
}

func newDirectPool() *directPool {
	return &directPool{
		byKey:        make(map[string]*directTemplate),
		byTier:       make(map[string][]*directTemplate),
		pcCount:      make(map[uint64]int),
		pending:      make(map[string]*directCandidate),
		pendingOrder: make(map[string][]*directCandidate),
		pendingPC:    make(map[uint64]int),
		attempts:     make(map[string]directAttempt),
	}
}

func (pool *directPool) addCold(target *prog.Target, chains [][]string, ct *prog.ChoiceTable, rs rand.Source) (int, []string) {
	var errs []string
	added := 0
	for _, names := range chains {
		p, err := target.GenerateSequence(rs, ct, names)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		t := templateFromProg(p, "D", true, nil)
		if pool.upsert(t) > 0 {
			added++
		}
	}
	return added, errs
}

func (pool *directPool) sync(c *corpus.Corpus) int {
	if c == nil {
		return 0
	}
	added := 0
	for _, item := range c.Items() {
		if pool.offer(c, corpus.NewInput{
			Prog: item.Prog, Call: item.Call, Cover: item.Cover,
		}) {
			added++
		}
	}
	return added
}

func (pool *directPool) offer(c *corpus.Corpus, input corpus.NewInput) bool {
	if c == nil || input.Prog == nil || input.Call < -1 || input.Call >= len(input.Prog.Calls) {
		return false
	}
	class, pcs := c.BestFocus(input.Cover)
	if class == "" || len(pcs) == 0 {
		return false
	}
	kind := directCallCandidate
	var candidateProg *prog.Prog
	hit := input.Call
	if input.Call >= 0 {
		candidateProg = input.Prog.Prefix(input.Call)
		hit = len(candidateProg.Calls) - 1
	} else {
		candidateProg = input.Prog.Clone()
		kind = directExtraCandidate
	}
	cand := &directCandidate{
		id:       hash.String(kind, candidateProg.Serialize(), input.Call),
		kind:     kind,
		prog:     candidateProg,
		hit:      hit,
		tier:     class,
		tierRank: directTierRank(class),
		pcs:      pcSet(pcs),
		length:   len(candidateProg.Calls),
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return pool.queueCandidate(cand)
}

func (pool *directPool) count() int {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return len(pool.byKey)
}

func (pool *directPool) pick(r *rand.Rand) *pickedTemplate {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	tierWeight := 0
	for _, tier := range directTiers {
		if len(pool.byTier[tier.name]) != 0 {
			tierWeight += tier.weight
		}
	}
	if tierWeight == 0 {
		return nil
	}
	tierGoal := r.Intn(tierWeight)
	var list []*directTemplate
	for _, tier := range directTiers {
		if len(pool.byTier[tier.name]) == 0 {
			continue
		}
		if tierGoal -= tier.weight; tierGoal < 0 {
			list = pool.byTier[tier.name]
			break
		}
	}

	total := 0
	weights := make([]int, len(list))
	for i, t := range list {
		weights[i] = t.weight(pool.pcCount)
		total += weights[i]
	}
	if total == 0 {
		return nil
	}
	goal := r.Intn(total)
	chosen := list[len(list)-1]
	for i, w := range weights {
		if goal -= w; goal < 0 {
			chosen = list[i]
			break
		}
	}
	hit := chosen.hitCall
	if chosen.kind == directCallCandidate && (hit < 0 || hit >= len(chosen.prog.Calls)) {
		hit = len(chosen.prog.Calls) - 1
	}
	return &pickedTemplate{prog: chosen.prog.Clone(), hit: hit, kind: chosen.kind}
}

func (pool *directPool) mutateOpts(p *prog.Prog) (prog.MutateOpts, bool) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	names := callNames(p)
	var best *directTemplate
	for _, t := range pool.byKey {
		if len(t.seq) == 0 || len(t.seq) > len(names) {
			continue
		}
		if !slices.Equal(t.seq, names[:len(t.seq)]) {
			continue
		}
		if betterTemplateMatch(t, best) {
			best = t
		}
	}
	if best == nil {
		return prog.MutateOpts{}, false
	}
	opts := prog.DefaultMutateOpts
	opts.SpliceWeight = 10
	opts.MutateArgWeight = 200
	opts.PrefixLen = len(best.seq)
	opts.PreferCall = best.hitCall
	if best.kind == directExtraCandidate {
		// Extra coverage is program-level, so there is no justified preferred call.
		opts.PreferCall = -1
	} else if opts.PreferCall < 0 || opts.PreferCall >= opts.PrefixLen {
		opts.PreferCall = opts.PrefixLen - 1
	}
	return opts, true
}

// betterTemplateMatch prefers a longer syscall prefix, then a higher tier.
// At the same length and tier, a call-attributed template wins over an Extra
// template because only the call template has a real triggering call.
func betterTemplateMatch(t, best *directTemplate) bool {
	if best == nil || len(t.seq) > len(best.seq) {
		return true
	}
	if len(t.seq) < len(best.seq) {
		return false
	}
	if t.tierRank != best.tierRank {
		return t.tierRank < best.tierRank
	}
	return best.kind == directExtraCandidate && t.kind == directCallCandidate
}

func (fuzzer *Fuzzer) mutateOptsFor(p *prog.Prog) prog.MutateOpts {
	if !fuzzer.Config.IsDirect || fuzzer.templates == nil {
		return prog.DefaultMutateOpts
	}
	if opts, ok := fuzzer.templates.mutateOpts(p); ok {
		return opts
	}
	return prog.DefaultMutateOpts
}

func (fuzzer *Fuzzer) refreshDirect() {
	if fuzzer.templates == nil || !fuzzer.Config.Coverage {
		return
	}
	if job := fuzzer.templates.takeDirectJob(); job != nil {
		fuzzer.startJob(fuzzer.statJobsTemplate, job)
	}
}

func (fuzzer *Fuzzer) offerDirectCandidate(input corpus.NewInput) {
	if !fuzzer.Config.IsDirect || fuzzer.templates == nil || fuzzer.Config.Corpus == nil {
		return
	}
	fuzzer.templates.offer(fuzzer.Config.Corpus, input)
}

func genDirectProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *queue.Request {
	if !fuzzer.Config.IsDirect || fuzzer.templates == nil {
		return nil
	}
	picked := fuzzer.templates.pick(rnd)
	if picked == nil {
		return nil
	}
	p := picked.prog
	mutateCall := picked.hit
	if picked.kind == directExtraCandidate && len(p.Calls) != 0 {
		// Extra coverage cannot be attributed to one call. Vary the mutation
		// anchor instead of consistently blaming the last call in the program.
		mutateCall = rnd.Intn(len(p.Calls))
	}
	p.MutateCallArg(rnd, mutateCall, fuzzer.ChoiceTable(), 2)
	if extra := rnd.Intn(3); extra > 0 {
		p.AppendGeneratedCalls(rnd, extra, fuzzer.ChoiceTable())
	}
	return &queue.Request{
		Prog:     p,
		ExecOpts: setFlags(flatrpc.ExecFlagCollectSignal),
		Stat:     fuzzer.statExecGenerate,
	}
}

func pendingCap(tier string) int {
	if i := directTierRank(tier); i < len(directTiers) {
		return directTiers[i].weight * 2
	}
	return 0
}

func (pool *directPool) queueCandidate(cand *directCandidate) bool {
	if pool.coveredByVerified(cand) {
		return false
	}
	if st, ok := pool.attempts[cand.id]; ok {
		cand.tries = st.tries
		if cand.tierRank < st.tierRank && cand.tries >= directCandidateTries {
			cand.tries = directCandidateTries - 1
		} else if cand.tries >= directCandidateTries {
			return false
		}
	}
	var displaced *directCandidate
	if old := pool.pending[cand.id]; old != nil {
		if cand.tierRank >= old.tierRank {
			return false
		}
		cand.tries = old.tries
		pool.dropPending(old)
		displaced = old
	}
	return pool.insertPending(cand, displaced)
}

func (pool *directPool) coveredByVerified(cand *directCandidate) bool {
	key := templateKey(cand.kind, callNames(cand.prog))
	old := pool.byKey[key]
	if old == nil || old.cold || cand.tierRank < old.tierRank {
		return false
	}
	for pc := range cand.pcs {
		if _, ok := old.pcs[pc]; !ok {
			return false
		}
	}
	return true
}

func (pool *directPool) insertPending(cand, displaced *directCandidate) bool {
	var dropped []*directCandidate
	restore := func() {
		for i := len(dropped) - 1; i >= 0; i-- {
			pool.addPending(dropped[i])
		}
		if displaced != nil {
			pool.addPending(displaced)
		}
	}
	for pool.pendingBlocked(cand) {
		victim := pool.worstBlocker(cand)
		if victim == nil || !cand.betterThan(victim, pool) {
			restore()
			return false
		}
		pool.dropPending(victim)
		dropped = append(dropped, victim)
	}
	pool.addPending(cand)
	for i := len(dropped) - 1; i >= 0; i-- {
		if !pool.pendingBlocked(dropped[i]) {
			pool.addPending(dropped[i])
		}
	}
	return true
}

func (pool *directPool) pendingBlocked(cand *directCandidate) bool {
	if pendingCap(cand.tier) == 0 || len(pool.pendingOrder[cand.tier]) >= pendingCap(cand.tier) {
		return true
	}
	if len(pool.pending) >= directPendingTotal {
		return true
	}
	for pc := range cand.pcs {
		if pool.pendingPC[pc] >= directPendingPerPC {
			return true
		}
	}
	return false
}

func (pool *directPool) worstBlocker(cand *directCandidate) *directCandidate {
	var worst *directCandidate
	consider := func(item *directCandidate) {
		if item != nil && (worst == nil || worst.betterThan(item, pool)) {
			worst = item
		}
	}
	for pc := range cand.pcs {
		if pool.pendingPC[pc] >= directPendingPerPC {
			for _, item := range pool.pending {
				if _, ok := item.pcs[pc]; ok {
					consider(item)
				}
			}
		}
	}
	if worst != nil {
		return worst
	}
	if len(pool.pendingOrder[cand.tier]) >= pendingCap(cand.tier) || pendingCap(cand.tier) == 0 {
		for _, item := range pool.pendingOrder[cand.tier] {
			consider(item)
		}
	}
	if worst == nil && len(pool.pending) >= directPendingTotal {
		for _, item := range pool.pending {
			consider(item)
		}
	}
	return worst
}

func (pool *directPool) addPending(cand *directCandidate) {
	pool.pending[cand.id] = cand
	pool.pendingOrder[cand.tier] = append(pool.pendingOrder[cand.tier], cand)
	for pc := range cand.pcs {
		pool.pendingPC[pc]++
	}
}

func (pool *directPool) dropPending(cand *directCandidate) {
	delete(pool.pending, cand.id)
	pool.pendingOrder[cand.tier] = slices.DeleteFunc(pool.pendingOrder[cand.tier], func(item *directCandidate) bool {
		return item.id == cand.id
	})
	for pc := range cand.pcs {
		if pool.pendingPC[pc]--; pool.pendingPC[pc] <= 0 {
			delete(pool.pendingPC, pc)
		}
	}
}

// bgPCCount returns how many templates and pending candidates cover pc,
// excluding cand itself (and excluding other when cand is a new candidate
// competing to replace other in pending).
func (pool *directPool) bgPCCount(cand, other *directCandidate, pc uint64) int {
	n := pool.pcCount[pc] + pool.pendingPC[pc]
	if cand != nil && pool.pending[cand.id] == cand {
		if _, ok := cand.pcs[pc]; ok && n > 0 {
			n--
		}
	} else if other != nil && pool.pending[other.id] == other {
		if _, ok := other.pcs[pc]; ok && n > 0 {
			n--
		}
	}
	return n
}

func (cand *directCandidate) score(other *directCandidate, pool *directPool) (fresh, unique bool, rare int) {
	for pc := range cand.pcs {
		bg := pool.bgPCCount(cand, other, pc)
		fresh = fresh || bg == 0
		unique = unique || bg <= 1
		rare += directTemplateRare / (bg + 1)
	}
	return
}

func (a *directCandidate) betterThan(b *directCandidate, pool *directPool) bool {
	if a.tierRank != b.tierRank {
		return a.tierRank < b.tierRank
	}
	aFresh, aUnique, aRare := a.score(b, pool)
	bFresh, bUnique, bRare := b.score(a, pool)
	if aFresh != bFresh {
		return aFresh
	}
	if aUnique != bUnique {
		return aUnique
	}
	if aRare != bRare {
		return aRare > bRare
	}
	if a.length != b.length {
		return a.length < b.length
	}
	return a.id < b.id
}

func (pool *directPool) takeDirectJob() *directMinJob {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.minRunning {
		return nil
	}
	var chosen *directCandidate
	for _, tier := range directTiers {
		list := pool.pendingOrder[tier.name]
		if len(list) == 0 {
			continue
		}
		chosen = list[0]
		for _, cand := range list[1:] {
			if cand.betterThan(chosen, pool) {
				chosen = cand
			}
		}
		break
	}
	if chosen == nil {
		return nil
	}
	pool.dropPending(chosen)
	pool.minRunning = true
	return &directMinJob{
		cand: chosen,
		info: &JobInfo{
			Name:  chosen.prog.String(),
			Type:  JobTemplate,
			Calls: slices.Clone(callNames(chosen.prog)),
		},
	}
}

func (pool *directPool) endMin() {
	pool.mu.Lock()
	pool.minRunning = false
	pool.mu.Unlock()
}

func (pool *directPool) failCandidate(cand *directCandidate) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	tries := cand.tries + 1
	pool.attempts[cand.id] = directAttempt{tries: tries, tierRank: cand.tierRank}
	if tries >= directCandidateTries {
		return
	}
	cand.tries = tries
	if pool.pending[cand.id] != nil || pool.coveredByVerified(cand) {
		return
	}
	pool.insertPending(cand, nil)
}

func (pool *directPool) publishVerified(id string, tierRank int, kind directCandidateKind,
	p *prog.Prog, hit int, class string, pcs map[uint64]struct{}) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	pool.attempts[id] = directAttempt{tries: directCandidateTries, tierRank: tierRank}
	t := newTemplate(p, class, false, pcs, kind)
	t.hitCall = hit
	pool.upsertLocked(t)
}

type directMinJob struct {
	cand *directCandidate
	info *JobInfo
}

func (job *directMinJob) getInfo() *JobInfo {
	return job.info
}

func (job *directMinJob) run(fuzzer *Fuzzer) {
	defer fuzzer.templates.endMin()
	execs := 0
	covers, stopped := collectHitCovers(fuzzer, job.cand.prog, job.cand.kind,
		job.cand.hit, &execs, job.info)
	if stopped {
		return
	}
	class, pcs := classifyStable(fuzzer.Config.Corpus, covers)
	if class == "" {
		fuzzer.templates.failCandidate(job.cand)
		return
	}
	p, hit := job.cand.prog, job.cand.hit
	stopped = false
	p, hit = prog.Minimize(p, hit, prog.MinimizeCallsOnly, func(p1 *prog.Prog, call1 int) bool {
		if stopped || !directBudgetAllows(execs) {
			return false
		}
		ok, stop := reproducesPCs(fuzzer, p1, job.cand.kind, call1, pcs, &execs, job.info)
		if stop {
			stopped = true
			return false
		}
		return ok
	})
	if stopped {
		return
	}
	if p != job.cand.prog {
		finalCovers, stopped := collectHitCovers(fuzzer, p, job.cand.kind, hit, &execs, job.info)
		if stopped {
			return
		}
		class, pcs = classifyStable(fuzzer.Config.Corpus, finalCovers)
		if class == "" {
			fuzzer.templates.failCandidate(job.cand)
			return
		}
	}
	fuzzer.templates.publishVerified(job.cand.id, directTierRank(class),
		job.cand.kind, p, hit, class, pcs)
}

func directBudgetAllows(execs int) bool {
	return execs+templateMinRuns+templateMinRuns <= directMinMaxExecs
}

func execDirectCover(fuzzer *Fuzzer, p *prog.Prog, kind directCandidateKind,
	call int, execs *int, info *JobInfo) ([]uint64, bool) {
	res := fuzzer.execute(fuzzer.smashQueue, &queue.Request{
		Prog:     p,
		ExecOpts: setFlags(flatrpc.ExecFlagCollectCover),
		Stat:     fuzzer.statExecMinimize,
	})
	*execs++
	if info != nil {
		info.Execs.Add(1)
	}
	if res.Stop() {
		return nil, true
	}
	return candidateCover(res.Info, kind, call), false
}

func collectHitCovers(fuzzer *Fuzzer, p *prog.Prog, kind directCandidateKind,
	hit int, execs *int, info *JobInfo) ([][]uint64, bool) {
	covers := make([][]uint64, 0, templateMinRuns)
	for range templateMinRuns {
		if *execs >= directMinMaxExecs {
			break
		}
		cov, stop := execDirectCover(fuzzer, p, kind, hit, execs, info)
		if stop {
			return covers, true
		}
		covers = append(covers, cov)
	}
	return covers, false
}

func reproducesPCs(fuzzer *Fuzzer, p *prog.Prog, kind directCandidateKind,
	call int, need map[uint64]struct{}, execs *int, info *JobInfo) (bool, bool) {
	if p == nil || len(p.Calls) == 0 || len(need) == 0 {
		return false, false
	}
	hits := make(map[uint64]int, len(need))
	for run := 0; run < templateMinRuns; run++ {
		if *execs >= directMinMaxExecs {
			return false, false
		}
		cov, stop := execDirectCover(fuzzer, p, kind, call, execs, info)
		if stop {
			return false, true
		}
		for pc := range pcSet(cov) {
			if _, ok := need[pc]; ok {
				hits[pc]++
			}
		}
		remaining := templateMinRuns - run - 1
		for pc := range need {
			if hits[pc]+remaining < templateMinNeedHits {
				return false, false
			}
		}
	}
	return true, false
}

func candidateCover(info *flatrpc.ProgInfo, kind directCandidateKind, call int) []uint64 {
	if info == nil {
		return nil
	}
	if kind == directExtraCandidate {
		if info.Extra == nil {
			return nil
		}
		return info.Extra.Cover
	}
	if call < 0 || call >= len(info.Calls) || info.Calls[call] == nil {
		return nil
	}
	return info.Calls[call].Cover
}

func stableFromCovers(covers [][]uint64) []uint64 {
	counts := make(map[uint64]int)
	for _, cover := range covers {
		for pc := range pcSet(cover) {
			counts[pc]++
		}
	}
	var out []uint64
	for pc, n := range counts {
		if n >= templateMinNeedHits {
			out = append(out, pc)
		}
	}
	return out
}

func classifyStable(c *corpus.Corpus, covers [][]uint64) (string, map[uint64]struct{}) {
	stable := stableFromCovers(covers)
	if c == nil || len(stable) == 0 {
		return "", nil
	}
	class, got := c.BestFocus(stable)
	if class == "" || len(got) == 0 {
		return "", nil
	}
	return class, pcSet(got)
}

func (pool *directPool) upsert(t *directTemplate) int {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return pool.upsertLocked(t)
}

func (pool *directPool) upsertLocked(t *directTemplate) int {
	fresh := 0
	if old := pool.byKey[t.key]; old != nil {
		if !templateBetter(t, old, pool.pcCount) {
			return 0
		}
		pool.unlink(old)
	} else {
		fresh = 1
	}
	pool.link(t)
	pool.evict(t.tier)
	if _, ok := pool.byKey[t.key]; !ok {
		return 0
	}
	return fresh
}

func (pool *directPool) link(t *directTemplate) {
	pool.byKey[t.key] = t
	pool.byTier[t.tier] = append(pool.byTier[t.tier], t)
	for pc := range t.pcs {
		pool.pcCount[pc]++
	}
}

func (pool *directPool) unlink(t *directTemplate) {
	delete(pool.byKey, t.key)
	pool.byTier[t.tier] = slices.DeleteFunc(pool.byTier[t.tier], func(item *directTemplate) bool {
		return item == t
	})
	for pc := range t.pcs {
		if pool.pcCount[pc]--; pool.pcCount[pc] <= 0 {
			delete(pool.pcCount, pc)
		}
	}
}

func (pool *directPool) evict(tier string) {
	for len(pool.byTier[tier]) > directTierCap {
		list := pool.byTier[tier]
		worst := 0
		worstScore := list[0].weight(pool.pcCount)
		for i := 1; i < len(list); i++ {
			score := list[i].weight(pool.pcCount)
			if score < worstScore {
				worst = i
				worstScore = score
			}
		}
		pool.unlink(list[worst])
	}
}

func (t *directTemplate) weight(pcCount map[uint64]int) int {
	return t.weightReplacing(t, pcCount)
}

func (t *directTemplate) weightReplacing(old *directTemplate, pcCount map[uint64]int) int {
	rare := 0
	for pc := range t.pcs {
		n := pcCount[pc] + 1
		if old != nil {
			if _, ok := old.pcs[pc]; ok {
				n = pcCount[pc]
			}
		}
		if n < 1 {
			n = 1
		}
		rare += directTemplateRare / n
	}
	score := directTemplateBase + rare - t.length
	if score < 1 {
		return 1
	}
	return score
}

func templateBetter(a, b *directTemplate, pcCount map[uint64]int) bool {
	if a.tierRank != b.tierRank {
		return a.tierRank < b.tierRank
	}
	if a.cold != b.cold {
		return !a.cold
	}
	ar, br := a.weightReplacing(b, pcCount), b.weight(pcCount)
	if ar != br {
		return ar > br
	}
	return a.key < b.key
}

func templateFromProg(p *prog.Prog, class string, cold bool, pcs []uint64) *directTemplate {
	return templateFromProgKind(p, class, cold, pcs, directCallCandidate)
}

func templateFromProgKind(p *prog.Prog, class string, cold bool, pcs []uint64,
	kind directCandidateKind) *directTemplate {
	return newTemplate(p, class, cold, pcSet(pcs), kind)
}

func newTemplate(p *prog.Prog, class string, cold bool, pcs map[uint64]struct{},
	kind directCandidateKind) *directTemplate {
	names := callNames(p)
	hit := len(p.Calls) - 1
	if kind == directExtraCandidate {
		hit = -1
	}
	return &directTemplate{
		key:      templateKey(kind, names),
		kind:     kind,
		seq:      names,
		prog:     p,
		hitCall:  hit,
		tier:     class,
		tierRank: directTierRank(class),
		pcs:      pcs,
		length:   len(p.Calls),
		cold:     cold,
	}
}

func pcSet(pcs []uint64) map[uint64]struct{} {
	set := make(map[uint64]struct{}, len(pcs))
	for _, pc := range pcs {
		set[pc] = struct{}{}
	}
	return set
}

func directTierRank(class string) int {
	for i, tier := range directTiers {
		if tier.name == class {
			return i
		}
	}
	return len(directTiers)
}

func callNames(p *prog.Prog) []string {
	names := make([]string, len(p.Calls))
	for i, c := range p.Calls {
		names[i] = c.Meta.Name
	}
	return names
}

func templateKey(kind directCandidateKind, names []string) string {
	return string(kind) + "\x00" + strings.Join(names, "\x00")
}
