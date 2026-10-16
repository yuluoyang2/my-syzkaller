// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"fmt"
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/prog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testProg(t *testing.T) *prog.Prog {
	t.Helper()
	target, err := prog.GetTarget("test", "64")
	require.NoError(t, err)
	return target.Generate(rand.NewSource(1), 4, target.BuildChoiceTable(nil, nil))
}

func TestDirectTemplateSnapshot(t *testing.T) {
	p := testProg(t)
	pool := newDirectPool()
	pool.upsert(templateFromProg(p.Clone(), "D", true, nil))

	snapshot := pool.snapshot()
	require.Len(t, snapshot.Templates, 1)
	assert.Equal(t, 1, snapshot.Cold)
	assert.Zero(t, snapshot.Verified)
	assert.True(t, snapshot.Templates[0].Cold)
	program, ok := pool.program(snapshot.Templates[0].ID)
	require.True(t, ok)
	assert.Equal(t, p.Serialize(), program)

	pool.publishVerified("candidate", directTierRank("A"), directCallCandidate,
		p.Clone(), len(p.Calls)-1, "A", map[uint64]struct{}{10: {}})
	snapshot = pool.snapshot()
	require.Len(t, snapshot.Templates, 1)
	assert.Zero(t, snapshot.Cold)
	assert.Equal(t, 1, snapshot.Verified)
	assert.Equal(t, "A", snapshot.Templates[0].Tier)
	assert.Equal(t, 1, snapshot.Templates[0].CoverPCs)
	assert.False(t, snapshot.Templates[0].Cold)
}

func TestDirectTierCapDropsLongest(t *testing.T) {
	pool := newDirectPool()
	for i := 0; i < directTierCap+1; i++ {
		pool.upsert(&directTemplate{
			key:      fmt.Sprintf("k%d", i),
			seq:      []string{fmt.Sprintf("c%d", i)},
			tier:     "A",
			tierRank: 0,
			pcs:      map[uint64]struct{}{uint64(i + 1): {}},
			length:   i + 1,
		})
	}
	assert.Equal(t, directTierCap, pool.count())
	_, ok := pool.byKey[fmt.Sprintf("k%d", directTierCap)]
	assert.False(t, ok)
}

func TestDirectSameSequenceKeepsShorter(t *testing.T) {
	long := &directTemplate{
		key: "same", seq: []string{"a"}, tier: "D", tierRank: 3,
		pcs: map[uint64]struct{}{1: {}}, length: 5,
	}
	short := &directTemplate{
		key: "same", seq: []string{"a"}, tier: "D", tierRank: 3,
		pcs: map[uint64]struct{}{1: {}}, length: 2,
	}
	pool := newDirectPool()
	assert.Equal(t, 1, pool.upsert(long))
	assert.Equal(t, 0, pool.upsert(short))
	assert.Equal(t, 2, pool.byKey["same"].length)

	kept := &directTemplate{
		key: "min", seq: []string{"b"}, tier: "D", tierRank: 3,
		pcs: map[uint64]struct{}{2: {}}, length: 2,
	}
	longer := &directTemplate{
		key: "min", seq: []string{"b"}, tier: "D", tierRank: 3,
		pcs: map[uint64]struct{}{2: {}}, length: 6,
	}
	pool.upsert(kept)
	pool.upsert(longer)
	assert.Equal(t, 2, pool.byKey["min"].length)

	higher := &directTemplate{
		key: "min", seq: []string{"b"}, tier: "A", tierRank: 0,
		pcs: map[uint64]struct{}{9: {}}, length: 4,
	}
	pool.upsert(higher)
	assert.Equal(t, "A", pool.byKey["min"].tier)
}

func TestDirectPickUsesTierWeights(t *testing.T) {
	p := testProg(t)
	require.GreaterOrEqual(t, len(p.Calls), 4)
	pool := newDirectPool()
	for i, tier := range []string{"A", "B", "C", "D"} {
		tmpl := templateFromProg(p.Clone(), tier, false, []uint64{uint64(i + 1)})
		tmpl.key = tier
		tmpl.hitCall = i
		pool.upsert(tmpl)
	}
	rnd := rand.New(rand.NewSource(1))
	counts := make([]int, 4)
	const iterations = 30000
	for range iterations {
		picked := pool.pick(rnd)
		require.NotNil(t, picked)
		counts[picked.hit]++
	}
	for i, weight := range []float64{16, 8, 4, 2} {
		assert.InDelta(t, weight/30, float64(counts[i])/iterations, 0.02)
	}
}

func TestDirectPickScoresWithinTier(t *testing.T) {
	p := testProg(t)
	require.GreaterOrEqual(t, len(p.Calls), 2)
	pool := newDirectPool()
	rare := templateFromProg(p.Clone(), "D", false, []uint64{1})
	rare.key = "rare"
	rare.hitCall = 0
	common := templateFromProg(p.Clone(), "D", false, []uint64{2})
	common.key = "common"
	common.hitCall = 1
	pool.upsert(rare)
	pool.upsert(common)
	pool.pcCount[2] = 4

	counts := make([]int, 2)
	rnd := rand.New(rand.NewSource(2))
	for range 10000 {
		counts[pool.pick(rnd).hit]++
	}
	assert.Greater(t, counts[0], counts[1])
}

func TestDirectColdStaysUntilVerified(t *testing.T) {
	p := testProg(t)
	pool := newDirectPool()
	cold := templateFromProg(p.Clone(), "D", true, nil)
	pool.upsert(cold)
	c := corpus.NewFocusedCorpus(context.Background(), nil, []corpus.FocusArea{
		{Name: "A", CoverPCs: map[uint64]struct{}{10: {}}, Weight: 16},
		{Name: "D", CoverPCs: map[uint64]struct{}{40: {}}, Weight: 2},
	})
	input := corpus.NewInput{Prog: p, Call: len(p.Calls) - 1, Cover: []uint64{40}}
	assert.True(t, pool.offer(c, input))
	assert.False(t, pool.offer(c, input))
	assert.True(t, pool.byKey[cold.key].cold)
	assert.Len(t, pool.pending, 1)

	verified := p.Prefix(len(p.Calls) - 1)
	pool.publishVerified("verified", directTierRank("D"), directCallCandidate,
		verified, len(verified.Calls)-1, "D",
		map[uint64]struct{}{40: {}})
	updated := pool.byKey[cold.key]
	assert.False(t, updated.cold)
	assert.Equal(t, map[uint64]struct{}{40: {}}, updated.pcs)

	pool.publishVerified("verified-a", directTierRank("A"), directCallCandidate,
		verified, len(verified.Calls)-1, "A",
		map[uint64]struct{}{10: {}})
	assert.Equal(t, "A", pool.byKey[cold.key].tier)
	assert.Equal(t, map[uint64]struct{}{10: {}}, pool.byKey[cold.key].pcs)
}

func TestDirectAllColdChainsUngeneratableFallsBack(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	require.NoError(t, err)
	ct := target.BuildChoiceTable(nil, map[*prog.Syscall]bool{
		target.SyscallMap["test$res0"]: true,
	})
	pool := newDirectPool()
	rnd := rand.New(rand.NewSource(1))
	added, errs := pool.addCold(target, [][]string{
		{"not_a_syscall"},
		{"disabled0"},
		{"serialize3"},
		{"test$int"},
	}, ct, rnd)
	assert.Equal(t, 0, added)
	assert.Len(t, errs, 4)
	assert.Equal(t, 0, pool.count())

	fuzzer := &Fuzzer{
		Config:    &Config{IsDirect: true},
		templates: pool,
	}
	assert.Nil(t, genDirectProgRequest(fuzzer, rnd))
}

func TestDirectMutateOptsGate(t *testing.T) {
	p := testProg(t)
	pool := newDirectPool()
	tmpl := templateFromProg(p.Clone(), "A", false, []uint64{1})
	pool.upsert(tmpl)
	fuzzer := &Fuzzer{Config: &Config{}, templates: pool}

	opts := fuzzer.mutateOptsFor(p)
	assert.Equal(t, prog.DefaultMutateOpts.SpliceWeight, opts.SpliceWeight)
	assert.Equal(t, prog.DefaultMutateOpts.MutateArgWeight, opts.MutateArgWeight)

	fuzzer.Config.IsDirect = true
	opts = fuzzer.mutateOptsFor(p)
	assert.Equal(t, 10, opts.SpliceWeight)
	assert.Equal(t, 200, opts.MutateArgWeight)
	assert.Equal(t, prog.DefaultMutateOpts.InsertWeight, opts.InsertWeight)
	assert.Equal(t, prog.DefaultMutateOpts.RemoveCallWeight, opts.RemoveCallWeight)
	assert.Equal(t, len(p.Calls), opts.PrefixLen)

	other := testProg(t)
	other.Calls = nil
	opts = fuzzer.mutateOptsFor(other)
	assert.Equal(t, prog.DefaultMutateOpts.SpliceWeight, opts.SpliceWeight)
}

func TestDirectMutateOptsPrefersCallTemplate(t *testing.T) {
	p := testProg(t)
	require.GreaterOrEqual(t, len(p.Calls), 2)
	pool := newDirectPool()
	callTmpl := templateFromProgKind(p.Clone(), "A", false, []uint64{10}, directCallCandidate)
	extraTmpl := templateFromProgKind(p.Clone(), "A", false, []uint64{30}, directExtraCandidate)
	pool.upsert(extraTmpl)
	pool.upsert(callTmpl)
	fuzzer := &Fuzzer{Config: &Config{IsDirect: true}, templates: pool}

	opts := fuzzer.mutateOptsFor(p)
	assert.Equal(t, len(p.Calls)-1, opts.PreferCall)
	assert.Equal(t, len(p.Calls), opts.PrefixLen)

	longer := newDirectPool()
	short := templateFromProgKind(p.Prefix(0), "A", false, []uint64{10}, directCallCandidate)
	extraLong := templateFromProgKind(p.Clone(), "A", false, []uint64{30}, directExtraCandidate)
	longer.upsert(short)
	longer.upsert(extraLong)
	fuzzer.templates = longer
	opts = fuzzer.mutateOptsFor(p)
	assert.Equal(t, -1, opts.PreferCall)
	assert.Equal(t, len(p.Calls), opts.PrefixLen)
}

func TestDirectPendingPriority(t *testing.T) {
	p := testProg(t)
	require.GreaterOrEqual(t, len(p.Calls), 2)
	pool := newDirectPool()
	c := corpus.NewFocusedCorpus(context.Background(), nil, []corpus.FocusArea{
		{Name: "A", CoverPCs: map[uint64]struct{}{10: {}}, Weight: 16},
		{Name: "B", CoverPCs: map[uint64]struct{}{20: {}}, Weight: 8},
	})
	assert.True(t, pool.offer(c, corpus.NewInput{Prog: p, Call: 0, Cover: []uint64{20}}))
	assert.True(t, pool.offer(c, corpus.NewInput{Prog: p, Call: len(p.Calls) - 1, Cover: []uint64{10}}))
	job := pool.takeDirectJob()
	require.NotNil(t, job)
	assert.Equal(t, "A", job.cand.tier)
	assert.Nil(t, pool.takeDirectJob())
	pool.endMin()
	next := pool.takeDirectJob()
	require.NotNil(t, next)
	assert.Equal(t, "B", next.cand.tier)
	pool.endMin()

	// Within the same tier, a candidate with a unique PC must beat two shorter
	// candidates that duplicate the same PC.
	target, err := prog.GetTarget("test", "64")
	require.NoError(t, err)
	ct := target.BuildChoiceTable(nil, nil)
	c2 := corpus.NewFocusedCorpus(context.Background(), nil, []corpus.FocusArea{
		{Name: "A", CoverPCs: map[uint64]struct{}{10: {}, 11: {}}, Weight: 16},
	})
	dup1 := target.Generate(rand.NewSource(10), 1, ct)
	dup2 := target.Generate(rand.NewSource(11), 2, ct)
	uniq := target.Generate(rand.NewSource(12), 4, ct)
	assert.True(t, pool.offer(c2, corpus.NewInput{Prog: dup1, Call: len(dup1.Calls) - 1, Cover: []uint64{10}}))
	assert.True(t, pool.offer(c2, corpus.NewInput{Prog: dup2, Call: len(dup2.Calls) - 1, Cover: []uint64{10}}))
	assert.True(t, pool.offer(c2, corpus.NewInput{Prog: uniq, Call: len(uniq.Calls) - 1, Cover: []uint64{11}}))
	picked := pool.takeDirectJob()
	require.NotNil(t, picked)
	assert.Equal(t, map[uint64]struct{}{11: {}}, picked.cand.pcs)
}

func TestDirectPublishKeepsOwnPCs(t *testing.T) {
	p := testProg(t)
	pool := newDirectPool()
	tmpl := templateFromProg(p.Clone(), "A", false, []uint64{10})
	pool.upsert(tmpl)
	other := p.Clone()
	pool.publishVerified("other", directTierRank("A"), directCallCandidate,
		other, len(other.Calls)-1, "A",
		map[uint64]struct{}{11: {}})
	assert.Equal(t, map[uint64]struct{}{10: {}}, pool.byKey[tmpl.key].pcs)

	// A verified template covering strictly more PCs on the same sequence replaces the exemplar.
	richer := p.Clone()
	pool.publishVerified("richer", directTierRank("A"), directCallCandidate,
		richer, len(richer.Calls)-1, "A",
		map[uint64]struct{}{10: {}, 11: {}})
	assert.Equal(t, map[uint64]struct{}{10: {}, 11: {}}, pool.byKey[tmpl.key].pcs)
}

func TestDirectOfferSkipsCoveredByVerified(t *testing.T) {
	p := testProg(t)
	pool := newDirectPool()
	c := corpus.NewFocusedCorpus(context.Background(), nil, []corpus.FocusArea{
		{Name: "A", CoverPCs: map[uint64]struct{}{10: {}, 11: {}}, Weight: 16},
		{Name: "B", CoverPCs: map[uint64]struct{}{20: {}}, Weight: 8},
	})
	verified := templateFromProg(p.Clone(), "B", false, []uint64{20})
	pool.upsert(verified)

	// Same sequence and subset PCs at the same tier should be skipped before entering pending.
	assert.False(t, pool.offer(c, corpus.NewInput{
		Prog: p, Call: len(p.Calls) - 1, Cover: []uint64{20},
	}))
	assert.Empty(t, pool.pending)

	// Hitting a higher tier on the same sequence should still be queued.
	assert.True(t, pool.offer(c, corpus.NewInput{
		Prog: p, Call: len(p.Calls) - 1, Cover: []uint64{10},
	}))
	assert.Len(t, pool.pending, 1)
}

func TestDirectPendingCaps(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	require.NoError(t, err)
	ct := target.BuildChoiceTable(nil, nil)
	c := corpus.NewFocusedCorpus(context.Background(), nil, []corpus.FocusArea{
		{Name: "D", CoverPCs: map[uint64]struct{}{1: {}, 2: {}, 3: {}, 4: {}, 5: {}}, Weight: 2},
	})
	pool := newDirectPool()
	for i := 0; i < 4; i++ {
		p := target.Generate(rand.NewSource(int64(i+1)), i+1, ct)
		assert.True(t, pool.offer(c, corpus.NewInput{
			Prog: p, Call: len(p.Calls) - 1, Cover: []uint64{uint64(i + 1)},
		}))
	}
	longest := target.Generate(rand.NewSource(5), 5, ct)
	assert.False(t, pool.offer(c, corpus.NewInput{
		Prog: longest, Call: len(longest.Calls) - 1, Cover: []uint64{5},
	}))
	assert.Len(t, pool.pending, 4)
	lengths := map[int]bool{}
	for _, cand := range pool.pending {
		lengths[cand.length] = true
	}
	assert.True(t, lengths[4])
	assert.False(t, lengths[5])

	pool = newDirectPool()
	for i := 0; i < directPendingPerPC+1; i++ {
		p := target.Generate(rand.NewSource(int64(100+i)), 8-i, ct)
		pool.offer(c, corpus.NewInput{Prog: p, Call: len(p.Calls) - 1, Cover: []uint64{1}})
	}
	assert.Len(t, pool.pending, directPendingPerPC)
	var maxLen int
	for _, cand := range pool.pending {
		if cand.length > maxLen {
			maxLen = cand.length
		}
	}
	assert.Less(t, maxLen, 8)
}

func TestDirectCandidateCoverStrictlySeparatesExtra(t *testing.T) {
	info := &flatrpc.ProgInfo{
		Calls: []*flatrpc.CallInfo{
			{Cover: []uint64{10}},
			{Cover: []uint64{20}},
		},
		Extra: &flatrpc.CallInfo{Cover: []uint64{30}},
	}
	assert.Equal(t, []uint64{20}, candidateCover(info, directCallCandidate, 1))
	assert.Equal(t, []uint64{30}, candidateCover(info, directExtraCandidate, -1))
	assert.Empty(t, candidateCover(info, directCallCandidate, -1))
	assert.Empty(t, candidateCover(nil, directExtraCandidate, -1))
}

func TestDirectExtraCandidateKeepsWholeProgram(t *testing.T) {
	p := testProg(t)
	require.GreaterOrEqual(t, len(p.Calls), 2)
	pool := newDirectPool()
	c := corpus.NewFocusedCorpus(context.Background(), nil, []corpus.FocusArea{
		{Name: "A", CoverPCs: map[uint64]struct{}{30: {}}, Weight: 16},
	})
	assert.True(t, pool.offer(c, corpus.NewInput{Prog: p, Call: -1, Cover: []uint64{30}}))
	require.Len(t, pool.pending, 1)
	for _, cand := range pool.pending {
		assert.Equal(t, directExtraCandidate, cand.kind)
		assert.Equal(t, -1, cand.hit)
		assert.Equal(t, len(p.Calls), len(cand.prog.Calls))
	}
}

func TestDirectCallAndExtraTemplatesDoNotCollide(t *testing.T) {
	p := testProg(t)
	pool := newDirectPool()
	call := templateFromProgKind(p.Clone(), "A", false, []uint64{10}, directCallCandidate)
	extra := templateFromProgKind(p.Clone(), "A", false, []uint64{30}, directExtraCandidate)
	assert.Equal(t, 1, pool.upsert(call))
	assert.Equal(t, 1, pool.upsert(extra))
	assert.NotEqual(t, call.key, extra.key)
	assert.Equal(t, 2, pool.count())
}

func TestDirectSyncHighestTier(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	require.NoError(t, err)
	p := target.Generate(rand.NewSource(1), 3, target.BuildChoiceTable(nil, nil))
	require.NotEmpty(t, p.Calls)
	c := corpus.NewFocusedCorpus(context.Background(), nil, []corpus.FocusArea{
		{Name: "A", CoverPCs: map[uint64]struct{}{10: {}}, Weight: 16},
		{Name: "D", CoverPCs: map[uint64]struct{}{10: {}, 40: {}}, Weight: 2},
	})
	c.Save(corpus.NewInput{Prog: p, Call: 0, Cover: []uint64{10, 40}})
	pool := newDirectPool()
	assert.Equal(t, 1, pool.sync(c))
	assert.Equal(t, 0, pool.sync(c))
	assert.Equal(t, 0, pool.count())
	require.Len(t, pool.pending, 1)
	for _, cand := range pool.pending {
		assert.Equal(t, "A", cand.tier)
		assert.Equal(t, []string{p.Calls[0].Meta.Name}, callNames(cand.prog))
	}
}

func TestClassifyStableUsesReproducedTier(t *testing.T) {
	c := corpus.NewFocusedCorpus(context.Background(), nil, []corpus.FocusArea{
		{Name: "A", CoverPCs: map[uint64]struct{}{10: {}}, Weight: 16},
		{Name: "B", CoverPCs: map[uint64]struct{}{20: {}}, Weight: 8},
	})
	class, pcs := classifyStable(c, [][]uint64{{10, 20}, {20}, {20}})
	assert.Equal(t, "B", class)
	assert.Equal(t, map[uint64]struct{}{20: {}}, pcs)

	class, pcs = classifyStable(c, [][]uint64{{10, 20}, {10}, {10}})
	assert.Equal(t, "A", class)
	assert.Equal(t, map[uint64]struct{}{10: {}}, pcs)

	class, pcs = classifyStable(c, [][]uint64{{10}, {}, {}})
	assert.Empty(t, class)
	assert.Empty(t, pcs)
	assert.True(t, directBudgetAllows(58))
	assert.False(t, directBudgetAllows(59))
}
