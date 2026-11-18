// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"context"
	"slices"
	"sort"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/signal"
)

// DirectedLevel orders the disjoint coverage regions, not sampling buckets.
type DirectedLevel uint8

const (
	DirectedOther DirectedLevel = iota
	DirectedSubsystem
	DirectedFile
	DirectedClose
	DirectedTarget
	directedLevels
)

func (level DirectedLevel) Weight() float64 {
	return [...]float64{0, 0.125, 0.25, 0.5, 1}[level]
}

// DirectedCoverage is immutable after construction. PCs must use the same
// canonical, next-instruction addresses as executor coverage.
type DirectedCoverage struct {
	regions [directedLevels]map[uint64]struct{}
	levels  map[uint64]DirectedLevel
}

func NewDirectedCoverage(target, closeFuncs, file, subsystem []uint64) *DirectedCoverage {
	ret := &DirectedCoverage{levels: make(map[uint64]DirectedLevel)}
	sets := [directedLevels][]uint64{nil, subsystem, file, closeFuncs, target}
	for level := DirectedTarget; level > DirectedOther; level-- {
		ret.regions[level] = make(map[uint64]struct{})
		for _, pc := range sets[level] {
			if _, exists := ret.levels[pc]; exists {
				continue
			}
			ret.levels[pc] = level
			ret.regions[level][pc] = struct{}{}
		}
	}
	return ret
}

func (cov *DirectedCoverage) Level(pc uint64) DirectedLevel {
	return cov.levels[pc]
}

func (cov *DirectedCoverage) Counts(pcs []uint64) (DirectedLevel, [directedLevels]int) {
	var counts [directedLevels]int
	var level DirectedLevel
	seen := make(map[uint64]struct{}, len(pcs))
	for _, pc := range pcs {
		if _, ok := seen[pc]; ok {
			continue
		}
		seen[pc] = struct{}{}
		l := cov.Level(pc)
		counts[l]++
		level = max(level, l)
	}
	return level, counts
}

func (cov *DirectedCoverage) Depth(pcs []uint64, level DirectedLevel) float64 {
	if level == DirectedOther || level >= directedLevels || len(cov.regions[level]) == 0 {
		return 0
	}
	_, counts := cov.Counts(pcs)
	return float64(counts[level]) / float64(len(cov.regions[level]))
}

func (cov *DirectedCoverage) Score(pcs []uint64) float64 {
	level, _ := cov.Counts(pcs)
	// Level is the base score, depth is a fraction of that level's own range.
	// This keeps every target seed above every close seed, etc., while still
	// making depth meaningful inside a level.
	return level.Weight() * (1 + 0.5*cov.Depth(pcs, level))
}

// DirectedWitness records only K obligations. C is checked separately using
// stable signal, including priority. MinCount fixes the depth denominator to
// this build's immutable DepthLevel region without floating-point thresholds.
type DirectedWitness struct {
	Level      DirectedLevel
	DepthLevel DirectedLevel
	MinCount   int
	PCs        []uint64
}

func (w DirectedWitness) Empty() bool {
	return w.Level == DirectedOther && w.MinCount == 0 && len(w.PCs) == 0
}

func (cov *DirectedCoverage) Satisfies(pcs []uint64, w DirectedWitness) bool {
	level, counts := cov.Counts(pcs)
	if level < w.Level {
		return false
	}
	if w.MinCount != 0 && (w.DepthLevel == DirectedOther ||
		w.DepthLevel >= directedLevels || counts[w.DepthLevel] < w.MinCount) {
		return false
	}
	var observed cover.Cover
	observed.Merge(pcs)
	for _, pc := range w.PCs {
		if _, ok := observed[pc]; !ok {
			return false
		}
	}
	return true
}

// DirectedInput belongs to this exact program version. StableCover must never
// be a union of independently confirmed batches or inherited from its parent.
type DirectedInput struct {
	StableCover []uint64
	Witnesses   []DirectedWitness
}

func cloneDirected(inp *DirectedInput) *DirectedInput {
	if inp == nil {
		return nil
	}
	ret := &DirectedInput{StableCover: slices.Clone(inp.StableCover)}
	for _, w := range inp.Witnesses {
		w.PCs = slices.Clone(w.PCs)
		ret.Witnesses = append(ret.Witnesses, w)
	}
	return ret
}

type directedSeedStats struct {
	gain      float64
	mutations uint64
}

type directedState struct {
	coverage *DirectedCoverage
	maxLevel DirectedLevel
	maxCount [directedLevels]int
	covered  cover.Cover
	gainSeen cover.Cover
	stats    map[string]*directedSeedStats
	sampler  directedSampler
}

func NewDirectedCorpus(ctx context.Context, updates chan<- NewItemEvent, cov *DirectedCoverage) *Corpus {
	ret := NewMonitoredCorpus(ctx, updates)
	ret.directed = &directedState{
		coverage: cov,
		stats:    make(map[string]*directedSeedStats),
	}
	return ret
}

func (corpus *Corpus) DirectedCoverage() *DirectedCoverage {
	if corpus.directed == nil {
		return nil
	}
	return corpus.directed.coverage
}

func (corpus *Corpus) DirectedWitness(pcs []uint64) DirectedWitness {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return corpus.directedWitnessLocked(pcs)
}

func (corpus *Corpus) directedWitnessLocked(pcs []uint64) DirectedWitness {
	d := corpus.directed
	if d == nil {
		return DirectedWitness{}
	}
	level, counts := d.coverage.Counts(pcs)
	// Other is a gain category, never a K admission reason.
	if level == DirectedOther {
		return DirectedWitness{}
	}
	var w DirectedWitness
	if level > d.maxLevel {
		w.Level = level
	}
	if counts[level] > d.maxCount[level] {
		w.DepthLevel, w.MinCount = level, counts[level]
	}
	for _, pc := range pcs {
		if d.coverage.Level(pc) == level {
			if _, ok := d.covered[pc]; !ok {
				w.PCs = append(w.PCs, pc)
			}
		}
	}
	slices.Sort(w.PCs)
	w.PCs = slices.Compact(w.PCs)
	return w
}

// SaveDirected rechecks admission against the live corpus under the same lock
// as insertion. Concurrent confirmations cannot all claim the same K progress.
func (corpus *Corpus) SaveDirected(inp NewInput, pcs []uint64, original DirectedWitness,
	newSignal signal.Signal) bool {
	pcs = slices.Clone(pcs)
	slices.Sort(pcs)
	pcs = slices.Compact(pcs)
	var update *NewItemEvent
	corpus.mu.Lock()
	defer func() {
		corpus.mu.Unlock()
		if update != nil {
			corpus.sendUpdate(*update)
		}
	}()
	d := corpus.directed
	if d == nil || !d.coverage.Satisfies(pcs, original) {
		return false
	}
	w := corpus.directedWitnessLocked(pcs)
	newC := newSignal.Intersection(corpus.signal).Len() != newSignal.Len()
	if !newC && w.Empty() {
		return false
	}
	meta := &DirectedInput{StableCover: slices.Clone(pcs)}
	data := inp.Prog.Serialize()
	sig := hash.String(data)
	if old := corpus.progsMap[sig]; old != nil && old.Directed != nil {
		meta.Witnesses = cloneDirected(old.Directed).Witnesses
		for _, prev := range meta.Witnesses {
			if !d.coverage.Satisfies(pcs, prev) {
				// A different confirmed batch cannot replace old obligations by
				// unioning incompatible raw coverage. C may still be updated.
				if !newC {
					return false
				}
				meta = cloneDirected(old.Directed)
				w, original = DirectedWitness{}, DirectedWitness{}
				break
			}
		}
	}
	for _, next := range []DirectedWitness{original, w} {
		if !next.Empty() && !slices.ContainsFunc(meta.Witnesses, func(prev DirectedWitness) bool {
			return prev.Level == next.Level && prev.DepthLevel == next.DepthLevel &&
				prev.MinCount == next.MinCount && slices.Equal(prev.PCs, next.PCs)
		}) {
			next.PCs = slices.Clone(next.PCs)
			meta.Witnesses = append(meta.Witnesses, next)
		}
	}
	inp.Directed = meta
	event := corpus.saveLocked(inp, data, sig)
	update = &event
	return true
}

func (d *directedState) addCover(pcs []uint64) {
	level, counts := d.coverage.Counts(pcs)
	d.maxLevel = max(d.maxLevel, level)
	for l := DirectedSubsystem; l < directedLevels; l++ {
		d.maxCount[l] = max(d.maxCount[l], counts[l])
	}
	d.covered.Merge(pcs)
}

func (corpus *Corpus) updateDirectedLocked(sig string, rebuild bool) {
	d := corpus.directed
	if d == nil {
		return
	}
	item := corpus.progsMap[sig]
	if d.stats[sig] == nil {
		prior := 0.1
		if len(d.stats) != 0 {
			prior = 0
			for _, stats := range d.stats {
				prior += stats.gain
			}
			prior = min(0.2, max(0.05, prior/float64(len(d.stats))))
		}
		d.stats[sig] = &directedSeedStats{gain: prior}
	}
	if rebuild {
		corpus.rebuildDirectedLocked()
		return
	}
	if item.Directed != nil {
		d.addCover(item.Directed.StableCover)
	}
	d.sampler.set(sig, corpus.directedScoreLocked(item))
}

func (corpus *Corpus) directedScoreLocked(item *Item) float64 {
	k := 0.0
	if item.Directed != nil {
		k = corpus.directed.coverage.Score(item.Directed.StableCover)
	}
	// G is a bounded tie-breaker inside the K level. It must never let a
	// lower level seed cross into a higher level's score range.
	return k * (1 + 0.1*corpus.directed.stats[item.Sig].gain)
}

func (corpus *Corpus) rebuildDirectedLocked() {
	d := corpus.directed
	d.maxLevel, d.maxCount, d.covered = 0, [directedLevels]int{}, nil
	d.sampler = directedSampler{}
	keys := make([]string, 0, len(corpus.progsMap))
	for sig := range corpus.progsMap {
		keys = append(keys, sig)
	}
	slices.Sort(keys)
	for _, sig := range keys {
		item := corpus.progsMap[sig]
		if item.Directed != nil {
			d.addCover(item.Directed.StableCover)
		}
		d.sampler.set(sig, corpus.directedScoreLocked(item))
	}
	for sig := range d.stats {
		if corpus.progsMap[sig] == nil {
			delete(d.stats, sig)
		}
	}
}

// RecordDirectedGain is called once per mutation by its confirmation owner.
// The gain discovery ledger and the parent's EMA are updated atomically.
// A nil cover is a zero-reward attempt, not confirmed empty K coverage.
func (corpus *Corpus) RecordDirectedGain(parent string, pcs []uint64) {
	var changed bool
	corpus.mu.Lock()
	defer func() {
		corpus.mu.Unlock()
		if changed {
			corpus.sendUpdate(NewItemEvent{StateOnly: true})
		}
	}()
	d := corpus.directed
	if d == nil {
		return
	}
	var delta [directedLevels]int
	newPCs := d.gainSeen.MergeDiff(pcs)
	for _, pc := range newPCs {
		delta[d.coverage.Level(pc)]++
	}
	if stats := d.stats[parent]; stats != nil {
		h := func(n int) float64 { return float64(n) / float64(n+1) }
		reward := (8*h(delta[DirectedTarget]) + 4*h(delta[DirectedClose]) +
			2*h(delta[DirectedFile]) + h(delta[DirectedSubsystem]) + 0.2*h(delta[DirectedOther])) / 15.2
		stats.gain = 0.7*stats.gain + 0.3*reward
		stats.mutations++
		if item := corpus.progsMap[parent]; item != nil {
			d.sampler.set(parent, corpus.directedScoreLocked(item))
		}
	}
	changed = len(newPCs) != 0
}

func (corpus *Corpus) DirectedGainHistory() []uint64 {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	if corpus.directed == nil {
		return nil
	}
	return corpus.directed.gainSeen.Serialize()
}

func (corpus *Corpus) RestoreDirectedGainHistory(pcs []uint64) {
	corpus.mu.Lock()
	changed := corpus.directed != nil && len(corpus.directed.gainSeen.MergeDiff(pcs)) != 0
	corpus.mu.Unlock()
	if changed {
		corpus.sendUpdate(NewItemEvent{StateOnly: true})
	}
}

// minimizeDirectedLocked preserves C priority representatives, then covers all
// K witnesses. Obligations are transferred to the chosen carrier so a later
// minimization cannot silently forget a removed seed's reason.
func (corpus *Corpus) minimizeDirectedLocked(inputs []signal.Context) map[string]*Item {
	ret := make(map[string]*Item)
	for _, ctx := range signal.Minimize(inputs) {
		item := ctx.(*Item)
		ret[item.Sig] = item
	}
	candidates := make([]*Item, 0, len(inputs))
	for _, ctx := range inputs {
		candidates = append(candidates, ctx.Context.(*Item))
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if len(a.Prog.Calls) != len(b.Prog.Calls) {
			return len(a.Prog.Calls) < len(b.Prog.Calls)
		}
		return corpus.directedScoreLocked(a) > corpus.directedScoreLocked(b)
	})
	for _, source := range candidates {
		if source.Directed == nil {
			continue
		}
		for _, w := range source.Directed.Witnesses {
			var carrier *Item
			for _, candidate := range candidates {
				if candidate.Directed == nil ||
					!corpus.directed.coverage.Satisfies(candidate.Directed.StableCover, w) {
					continue
				}
				if ret[candidate.Sig] != nil {
					carrier = ret[candidate.Sig]
					break
				}
				if carrier == nil {
					carrier = candidate
				}
			}
			if carrier == nil {
				// Never drop an obligation on an inconsistent snapshot.
				carrier = source
			}
			copyItem := *carrier
			copyItem.Directed = cloneDirected(carrier.Directed)
			if !slices.ContainsFunc(copyItem.Directed.Witnesses, func(prev DirectedWitness) bool {
				return prev.Level == w.Level && prev.DepthLevel == w.DepthLevel &&
					prev.MinCount == w.MinCount && slices.Equal(prev.PCs, w.PCs)
			}) {
				w.PCs = slices.Clone(w.PCs)
				copyItem.Directed.Witnesses = append(copyItem.Directed.Witnesses, w)
			}
			ret[carrier.Sig] = &copyItem
		}
	}
	corpus.preserveDirectedTargetPCs(ret, candidates)
	return ret
}

// preserveDirectedTargetPCs keeps at least one last carrier for every target
// PC that the pre-minimization corpus had. K witnesses protect new PCs, but an
// older target PC still needs a seed that can reproduce it.
func (corpus *Corpus) preserveDirectedTargetPCs(ret map[string]*Item, candidates []*Item) {
	d := corpus.directed
	if d == nil {
		return
	}
	covered := make(map[uint64]struct{})
	for _, item := range ret {
		if item.Directed != nil {
			for _, pc := range item.Directed.StableCover {
				covered[pc] = struct{}{}
			}
		}
	}
	for pc := range d.covered {
		if d.coverage.Level(pc) != DirectedTarget {
			continue
		}
		if _, ok := covered[pc]; ok {
			continue
		}
		var carrier *Item
		for _, candidate := range candidates {
			if candidate.Directed == nil {
				continue
			}
			if _, ok := slices.BinarySearch(candidate.Directed.StableCover, pc); ok {
				carrier = candidate
				break
			}
		}
		if carrier == nil {
			continue
		}
		if existing := ret[carrier.Sig]; existing != nil && existing.Directed != nil {
			// Never replace witnesses transferred to an already retained carrier.
			carrier = existing
		}
		copyItem := *carrier
		copyItem.Directed = cloneDirected(carrier.Directed)
		ret[carrier.Sig] = &copyItem
		for _, coveredPC := range carrier.Directed.StableCover {
			covered[coveredPC] = struct{}{}
		}
	}
}
