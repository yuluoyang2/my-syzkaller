// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"testing"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testDirectedCoverage() *DirectedCoverage {
	return NewDirectedCoverage([]uint64{10, 11}, []uint64{20, 21, 10},
		[]uint64{30, 31, 32, 20}, []uint64{40, 41, 30})
}

func directedTestInput(t *testing.T, n int, sig signal.Signal) NewInput {
	t.Helper()
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)
	p, err := target.Deserialize(fmt.Appendf(nil, "test$int(%#x, 0x0, 0x0, 0x0, 0x0)", n), prog.Strict)
	require.NoError(t, err)
	return NewInput{Prog: p, Signal: sig}
}

func TestDirectedCoverage(t *testing.T) {
	cov := testDirectedCoverage()
	assert.Equal(t, DirectedTarget, cov.Level(10))
	assert.Equal(t, DirectedClose, cov.Level(20))
	assert.Equal(t, DirectedFile, cov.Level(30))
	assert.Equal(t, DirectedOther, cov.Level(100))
	assert.Equal(t, 0.5, cov.Depth([]uint64{10, 10}, DirectedTarget))
	assert.Zero(t, cov.Score([]uint64{100}))
	assert.InDelta(t, 1.25, cov.Score([]uint64{10, 20, 30, 40}), 1e-10)
	assert.Greater(t, cov.Score([]uint64{10}), cov.Score([]uint64{20})*1.1)
	assert.Greater(t, cov.Score([]uint64{20}), cov.Score([]uint64{30})*1.1)
	assert.Greater(t, cov.Score([]uint64{30}), cov.Score([]uint64{40})*1.1)
	w := DirectedWitness{DepthLevel: DirectedTarget, MinCount: 1}
	assert.False(t, cov.Satisfies([]uint64{30, 31, 32}, w), "file depth must not replace target depth")
	assert.True(t, cov.Satisfies([]uint64{10}, DirectedWitness{Level: DirectedFile}))
	assert.Zero(t, cov.Depth([]uint64{10}, DirectedOther))
	assert.Zero(t, NewDirectedCoverage([]uint64{10}, nil, nil, nil).Depth(nil, DirectedClose))
}

func TestDirectedOtherDoesNotAdmit(t *testing.T) {
	c := NewDirectedCorpus(context.Background(), nil, testDirectedCoverage())
	w := c.DirectedWitness([]uint64{100})
	assert.True(t, w.Empty())
	inp := directedTestInput(t, 0, nil)
	assert.False(t, c.SaveDirected(inp, []uint64{100}, w, nil))
	inp.Signal = signal.FromRaw([]uint64{500}, 3)
	assert.True(t, c.SaveDirected(inp, []uint64{100}, w, inp.Signal), "C-only admission remains valid")
}

func TestDirectedMinimizeTransfersWitnesses(t *testing.T) {
	c := NewDirectedCorpus(context.Background(), nil, testDirectedCoverage())
	first := directedTestInput(t, 1, nil)
	second := directedTestInput(t, 2, nil)
	require.True(t, c.SaveDirected(first, []uint64{10}, c.DirectedWitness([]uint64{10}), nil))
	require.True(t, c.SaveDirected(second, []uint64{10, 11}, c.DirectedWitness([]uint64{10, 11}), nil))
	c.Minimize(true)
	require.Len(t, c.Items(), 1)
	retained := c.Item(hash.String(second.Prog.Serialize()))
	require.NotNil(t, retained)
	count := len(retained.Directed.Witnesses)
	for range 5 {
		c.Minimize(true)
	}
	require.Len(t, c.Items(), 1)
	assert.Len(t, c.Items()[0].Directed.Witnesses, count, "transfers must not duplicate obligations")
	assert.NotNil(t, c.ChooseProgram(rand.New(rand.NewSource(0))))
}

func TestDirectedMinimizePreservesTargetLastCarrier(t *testing.T) {
	c := NewDirectedCorpus(context.Background(), nil, testDirectedCoverage())
	sig := signal.FromRaw([]uint64{500}, 3)
	first := directedTestInput(t, 1, sig)
	second := directedTestInput(t, 2, sig)
	require.True(t, c.SaveDirected(first, []uint64{10}, c.DirectedWitness([]uint64{10}), sig))
	require.True(t, c.SaveDirected(second, []uint64{11}, c.DirectedWitness([]uint64{11}), sig))
	c.Minimize(true)
	require.Len(t, c.Items(), 2, "both unique target PCs need a last carrier")
}

func TestDirectedMinimizePreservesSignalPriority(t *testing.T) {
	c := NewDirectedCorpus(context.Background(), nil, testDirectedCoverage())
	low := directedTestInput(t, 1, signal.FromRaw([]uint64{500}, 1))
	high := directedTestInput(t, 2, signal.FromRaw([]uint64{500}, 3))
	require.True(t, c.SaveDirected(low, []uint64{10}, c.DirectedWitness([]uint64{10}), low.Signal))
	require.True(t, c.SaveDirected(high, []uint64{10}, c.DirectedWitness([]uint64{10}), high.Signal))
	c.Minimize(true)
	require.Len(t, c.Items(), 1)
	assert.Equal(t, hash.String(high.Prog.Serialize()), c.Items()[0].Sig)
}

func TestDirectedGainAndHistory(t *testing.T) {
	c := NewDirectedCorpus(context.Background(), nil, testDirectedCoverage())
	inp := directedTestInput(t, 1, signal.FromRaw([]uint64{500}, 3))
	require.True(t, c.SaveDirected(inp, nil, DirectedWitness{}, inp.Signal))
	sig := hash.String(inp.Prog.Serialize())
	c.RecordDirectedGain(sig, []uint64{10, 10})
	gain := c.directed.stats[sig].gain
	assert.InDelta(t, 0.7*0.1+0.3*(4.0/15.2), gain, 1e-10)
	c.RecordDirectedGain(sig, []uint64{10})
	assert.InDelta(t, 0.7*gain, c.directed.stats[sig].gain, 1e-10)
	assert.EqualValues(t, 2, c.directed.stats[sig].mutations)
	c.Minimize(true)
	assert.ElementsMatch(t, []uint64{10}, c.DirectedGainHistory())
	c.RestoreDirectedGainHistory([]uint64{11})
	assert.ElementsMatch(t, []uint64{10, 11}, c.DirectedGainHistory())
}

func TestDirectedConcurrentGainIsUnique(t *testing.T) {
	c := NewDirectedCorpus(context.Background(), nil, testDirectedCoverage())
	var sigs []string
	for i := range 2 {
		inp := directedTestInput(t, i, signal.FromRaw([]uint64{uint64(500 + i)}, 3))
		require.True(t, c.SaveDirected(inp, nil, DirectedWitness{}, inp.Signal))
		sigs = append(sigs, hash.String(inp.Prog.Serialize()))
	}
	var wg sync.WaitGroup
	for _, sig := range sigs {
		wg.Go(func() { c.RecordDirectedGain(sig, []uint64{10}) })
	}
	wg.Wait()
	gain := c.directed.stats[sigs[0]].gain + c.directed.stats[sigs[1]].gain
	assert.InDelta(t, 2*0.07+0.3*(4.0/15.2), gain, 1e-10)
}

func TestDirectedSamplerUpdates(t *testing.T) {
	var sampler directedSampler
	for i := range 100 {
		sampler.set(fmt.Sprint(i), float64(i+1))
	}
	assert.Equal(t, 5050.0, sampler.sum(100))
	sampler.set("0", 101)
	assert.Equal(t, 5150.0, sampler.sum(100))
	for i := range 100 {
		sampler.set(fmt.Sprint(i), 0)
	}
	assert.Zero(t, sampler.sum(100))
	r := rand.New(rand.NewSource(0))
	for range 100 {
		assert.NotEmpty(t, sampler.choose(r))
	}
	var two directedSampler
	two.set("low", 1)
	two.set("high", 9)
	count := 0
	for range 20000 {
		if two.choose(r) == "high" {
			count++
		}
	}
	assert.InDelta(t, 0.12/2+0.88*0.9, float64(count)/20000, 0.02)

	var band directedSampler
	band.set("high", 1000)
	for i := range 100 {
		band.set(fmt.Sprint("low", i), 1)
	}
	count = 0
	for range 20000 {
		if band.choose(r) == "high" {
			count++
		}
	}
	assert.Greater(t, float64(count)/20000, 0.7,
		"the top score band must not be diluted by the long tail")
}
