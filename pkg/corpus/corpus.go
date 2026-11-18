// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package corpus manages syzkaller test program corpora, signal tracking, and corpus minimization.
package corpus

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

// Corpus object represents a set of syzkaller-found programs that
// cover the kernel up to the currently reached frontiers.
type Corpus struct {
	ctx      context.Context
	mu       sync.RWMutex
	progsMap map[string]*Item
	signal   signal.Signal
	cover    cover.Cover
	updates  chan<- NewItemEvent

	*ProgramsList
	StatProgs  *stat.Val
	StatSignal *stat.Val
	StatCover  *stat.Val

	focusAreas []*focusAreaState
	directed   *directedState
}

type focusAreaState struct {
	FocusArea
	*ProgramsList
}

type FocusArea struct {
	Name     string // can be empty
	CoverPCs map[uint64]struct{}
	Weight   float64
}

func (fa *FocusArea) inAreaPCs(cover []uint64) int {
	var count int
	for _, pc := range cover {
		if _, ok := fa.CoverPCs[pc]; ok {
			count++
		}
	}
	return count
}

func NewCorpus(ctx context.Context) *Corpus {
	return NewMonitoredCorpus(ctx, nil)
}

func NewMonitoredCorpus(ctx context.Context, updates chan<- NewItemEvent) *Corpus {
	return NewFocusedCorpus(ctx, updates, nil)
}

func NewFocusedCorpus(ctx context.Context, updates chan<- NewItemEvent, areas []FocusArea) *Corpus {
	corpus := &Corpus{
		ctx:          ctx,
		progsMap:     make(map[string]*Item),
		updates:      updates,
		ProgramsList: &ProgramsList{},
	}
	corpus.StatProgs = stat.New("corpus", "Number of test programs in the corpus", stat.Console,
		stat.Link("/corpus"), stat.Graph("corpus"), stat.LenOf(&corpus.progsMap, &corpus.mu))
	corpus.StatSignal = stat.New("signal", "Fuzzing signal in the corpus",
		stat.LenOf(&corpus.signal, &corpus.mu))
	corpus.StatCover = stat.New("coverage", "Source coverage in the corpus", stat.Console,
		stat.Link("/cover"), stat.Prometheus("syz_corpus_cover"), stat.LenOf(&corpus.cover, &corpus.mu))
	for _, area := range areas {
		obj := &ProgramsList{}
		if len(area.CoverPCs) == 0 {
			obj = corpus.ProgramsList
		} else if len(areas) > 1 && area.Name != "" {
			stat.New("corpus ["+area.Name+"]",
				fmt.Sprintf("Corpus programs of the focus area %q", area.Name),
				stat.Console, stat.Graph("corpus"),
				stat.LenOf(&obj.progs, &corpus.mu))
		}
		corpus.focusAreas = append(corpus.focusAreas, &focusAreaState{
			FocusArea: area, ProgramsList: obj,
		})
	}
	return corpus
}

// ItemUpdate represents an update to a corpus item.
// A single program may be relevant for multiple syscalls.
type ItemUpdate struct {
	Call     int
	RawCover []uint64
}

// Items are immutable. Updates publish a copy, including directed metadata.
type Item struct {
	Sig      string
	Call     int
	Prog     *prog.Prog
	HasAny   bool
	Signal   signal.Signal
	Cover    []uint64
	Updates  []ItemUpdate
	Directed *DirectedInput

	areas map[*focusAreaState]struct{}
}

func (item Item) StringCall() string {
	return item.Prog.CallName(item.Call)
}

type NewInput struct {
	Prog     *prog.Prog
	Call     int
	Signal   signal.Signal
	Cover    []uint64
	RawCover []uint64
	Directed *DirectedInput
}

type NewItemEvent struct {
	Sig       string
	Exists    bool
	ProgData  []byte
	NewCover  []uint64
	StateOnly bool // directed gain history changed without a new corpus program
}

func (corpus *Corpus) Save(inp NewInput) {
	progData := inp.Prog.Serialize()
	sig := hash.String(progData)
	corpus.mu.Lock()
	update := corpus.saveLocked(inp, progData, sig)
	corpus.mu.Unlock()
	corpus.sendUpdate(update)
}

// sendUpdate may block. Callers must release mu before publishing, since the
// update consumer can read a corpus snapshot while processing an earlier event.
func (corpus *Corpus) sendUpdate(update NewItemEvent) {
	if corpus.updates != nil {
		select {
		case <-corpus.ctx.Done():
		case corpus.updates <- update:
		}
	}
}

func (corpus *Corpus) saveLocked(inp NewInput, progData []byte, sig string) NewItemEvent {
	update := ItemUpdate{Call: inp.Call, RawCover: slices.Clone(inp.RawCover)}
	old, exists := corpus.progsMap[sig]
	var item *Item
	if exists {
		newSignal := old.Signal.Copy()
		newSignal.Merge(inp.Signal)
		var newCover cover.Cover
		newCover.Merge(old.Cover)
		newCover.Merge(inp.Cover)
		item = &Item{
			Sig: sig, Prog: old.Prog, Call: old.Call, HasAny: old.HasAny,
			Signal: newSignal, Cover: newCover.Serialize(), Updates: slices.Clone(old.Updates),
			areas: maps.Clone(old.areas), Directed: cloneDirected(old.Directed),
		}
		if len(item.Updates) < 32 {
			item.Updates = append(item.Updates, update)
		}
	} else {
		item = &Item{
			Sig: sig, Call: inp.Call, Prog: inp.Prog, HasAny: inp.Prog.ContainsAny(),
			Signal: inp.Signal, Cover: inp.Cover, Updates: []ItemUpdate{update},
		}
	}
	if inp.Directed != nil {
		item.Directed = cloneDirected(inp.Directed)
	}
	corpus.progsMap[sig] = item
	corpus.applyFocusAreas(item)
	if !exists {
		corpus.saveProgram(inp.Prog, len(inp.Signal))
	}
	corpus.updateDirectedLocked(sig, exists)
	corpus.signal.Merge(inp.Signal)
	newCover := corpus.cover.MergeDiff(inp.Cover)
	return NewItemEvent{Sig: sig, Exists: exists, ProgData: progData, NewCover: newCover}
}

func (corpus *Corpus) applyFocusAreas(item *Item) {
	for _, area := range corpus.focusAreas {
		if len(area.CoverPCs) == 0 {
			continue
		}
		if _, ok := item.areas[area]; ok {
			continue
		}
		prio := area.inAreaPCs(item.Cover)
		if prio == 0 {
			continue
		}
		area.saveProgram(item.Prog, prio)
		if item.areas == nil {
			item.areas = make(map[*focusAreaState]struct{})
		}
		item.areas[area] = struct{}{}
	}
}

func (corpus *Corpus) Signal() signal.Signal {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return corpus.signal.Copy()
}

func (corpus *Corpus) Items() []*Item {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	ret := make([]*Item, 0, len(corpus.progsMap))
	for _, item := range corpus.progsMap {
		ret = append(ret, item)
	}
	return ret
}

func (corpus *Corpus) Item(sig string) *Item {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return corpus.progsMap[sig]
}

type CallCov struct {
	Count int
	Cover cover.Cover
}

func (corpus *Corpus) CallCover() map[string]*CallCov {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	calls := make(map[string]*CallCov)
	for _, inp := range corpus.progsMap {
		call := inp.StringCall()
		if calls[call] == nil {
			calls[call] = new(CallCov)
		}
		calls[call].Count++
		calls[call].Cover.Merge(inp.Cover)
	}
	return calls
}

func (corpus *Corpus) ProgsPerArea() map[string]int {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	ret := map[string]int{}
	for _, item := range corpus.focusAreas {
		ret[item.Name] = len(item.progs)
	}
	return ret
}

func (corpus *Corpus) Cover() []uint64 {
	corpus.mu.RLock()
	defer corpus.mu.RUnlock()
	return corpus.cover.Serialize()
}
