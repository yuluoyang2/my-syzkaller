// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"context"
	"fmt"
	"math/rand"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func checkDirectedSampler(t *testing.T, s *directedSampler) {
	t.Helper()
	n := len(s.keys)
	require.Equal(t, s.topSize(), s.top.Len())
	require.Equal(t, n-s.topSize(), s.rest.Len())
	seen := make([]bool, n)
	for _, h := range []*directedScoreHeap{&s.top, &s.rest} {
		require.Same(t, s, h.owner)
		for pos, idx := range h.items {
			require.False(t, seen[idx], "duplicate heap entry")
			seen[idx] = true
			require.Equal(t, pos, s.positions[idx])
			require.Equal(t, h.minimum, s.inTop[idx])
			if pos > 0 {
				require.False(t, h.Less(pos, (pos-1)/2), "invalid indexed heap")
			}
		}
	}
	if n == 0 {
		return
	}
	want := slices.Clone(s.weights)
	slices.Sort(want)
	slices.Reverse(want)
	got := make([]float64, 0, s.top.Len())
	for _, idx := range s.top.items {
		got = append(got, s.weights[idx])
	}
	slices.Sort(got)
	slices.Reverse(got)
	require.Equal(t, want[:s.topSize()], got)
	seen = make([]bool, n)
	count := 0
	for weight, bucket := range s.buckets {
		require.NotEmpty(t, bucket)
		for pos, idx := range bucket {
			require.False(t, seen[idx], "duplicate boundary bucket entry")
			seen[idx] = true
			count++
			require.Equal(t, weight, s.weights[idx])
			require.Equal(t, pos, s.bucketPos[idx])
		}
	}
	require.Equal(t, n, count)
	total := 0.0
	for _, weight := range s.weights {
		total += weight
	}
	assert.InDelta(t, total, s.sum(n), 1e-7)
}

func TestDirectedSamplerIndexedTopUpdates(t *testing.T) {
	var s directedSampler
	r := rand.New(rand.NewSource(1))
	for i := range 256 {
		s.set(fmt.Sprint(i), float64(r.Intn(20)))
	}
	checkDirectedSampler(t, &s)
	for range 500 {
		s.set(s.keys[r.Intn(len(s.keys))], float64(r.Intn(20)))
		checkDirectedSampler(t, &s)
	}
	// Unchanged weights must not rebuild ranks or churn boundary membership.
	for _, key := range s.keys {
		s.set(key, s.weights[s.indices[key]])
	}
	checkDirectedSampler(t, &s)
}

func TestDirectedSamplerTopGrowth(t *testing.T) {
	var s directedSampler
	for i := range 7000 {
		s.set(fmt.Sprint(i), float64(i%17))
		switch i + 1 {
		case 1, 7, 8, 9, 999, 1000, 1100, 6399, 6400, 7000:
			checkDirectedSampler(t, &s)
		}
	}
	assert.Equal(t, directedTopMax, s.top.Len())
}

func TestDirectedSamplerEqualScoresAreFair(t *testing.T) {
	for _, weight := range []float64{0, 1} {
		t.Run(fmt.Sprint(weight), func(t *testing.T) {
			var s directedSampler
			for i := range 1000 {
				s.set(fmt.Sprintf("%04d", i), weight)
			}
			r := rand.New(rand.NewSource(2))
			firstTen := 0
			const draws = 100000
			for range draws {
				if s.indices[s.choose(r)] < 10 {
					firstTen++
				}
			}
			assert.InDelta(t, 0.01, float64(firstTen)/draws, 0.003,
				"a fixed first ten must not receive the exploitation budget")
		})
	}
}

func TestDirectedSamplerBoundaryTiesShareOnlyRemainingSlots(t *testing.T) {
	var s directedSampler
	s.set("high", 2)
	for i := range 99 {
		s.set(fmt.Sprint(i), 1)
	}
	r := rand.New(rand.NewSource(3))
	counts := make(map[string]int)
	const draws = 100000
	for range draws {
		counts[s.choose(r)]++
	}
	// Top has one strict high seed and seven slots shared fairly by 99 ties.
	wantHigh := directedEpsilon/100 + (1-directedEpsilon)*2/9
	wantLow := directedEpsilon/100 + (1-directedEpsilon)*7/(9*99)
	assert.InDelta(t, wantHigh, float64(counts["high"])/draws, 0.005)
	for i := range 99 {
		assert.InDelta(t, wantLow, float64(counts[fmt.Sprint(i)])/draws, 0.002)
	}
}

func TestDirectedSamplerRealScoreDistribution(t *testing.T) {
	groups := []struct {
		name  string
		count int
		score float64
		want  float64
	}{
		{"target", 1, 1.0605, 0.16012},
		{"close", 9, 0.53025, 0.72108},
		{"file", 90, 0.265125, 0.0108},
		{"subsystem", 900, 0.1325625, 0.108},
	}
	var s directedSampler
	groupOf := make(map[string]int)
	for group, spec := range groups {
		for i := range spec.count {
			key := fmt.Sprintf("%s-%d", spec.name, i)
			s.set(key, spec.score)
			groupOf[key] = group
		}
	}
	r := rand.New(rand.NewSource(4))
	counts := make([]int, len(groups))
	const draws = 100000
	for range draws {
		counts[groupOf[s.choose(r)]]++
	}
	for i, spec := range groups {
		assert.InDelta(t, spec.want, float64(counts[i])/draws, 0.005, spec.name)
	}
}

func TestDirectedSamplerMoreTargetsThanSlots(t *testing.T) {
	var s directedSampler
	for i := range 1000 {
		weight := 0.53025
		if i < 100 {
			weight = 1.0605
		}
		s.set(fmt.Sprintf("%04d", i), weight)
	}
	r := rand.New(rand.NewSource(5))
	counts := make([]int, 1000)
	const draws = 100000
	for range draws {
		counts[s.indices[s.choose(r)]]++
	}
	targets := 0
	for i := range 100 {
		targets += counts[i]
		assert.InDelta(t, 0.00892, float64(counts[i])/draws, 0.002,
			"equally scored targets must share the exploitation budget")
	}
	assert.InDelta(t, 0.892, float64(targets)/draws, 0.005)
}

func TestDirectedSamplerConcurrentCorpusSelection(t *testing.T) {
	c := NewDirectedCorpus(context.Background(), nil, testDirectedCoverage())
	var parent string
	for i := range 128 {
		inp := directedTestInput(t, i+1, signal.FromRaw([]uint64{uint64(1000 + i)}, 3))
		inp.Directed = &DirectedInput{StableCover: []uint64{10}}
		c.Save(inp)
		parent = hash.String(inp.Prog.Serialize())
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	var invalid atomic.Bool
	for i := range 16 {
		wg.Go(func() {
			r := rand.New(rand.NewSource(int64(i + 1)))
			<-start
			for range 200 {
				if c.ChooseProgram(r) == nil {
					invalid.Store(true)
				}
			}
		})
	}
	wg.Go(func() {
		<-start
		for range 500 {
			c.RecordDirectedGain(parent, nil)
		}
	})
	close(start)
	wg.Wait()
	assert.False(t, invalid.Load())
}

func BenchmarkDirectedSamplerUpdateAndChoose(b *testing.B) {
	for _, n := range []int{1000, 10000, 100000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			var s directedSampler
			for i := range n {
				s.set(fmt.Sprint(i), float64(i%17+1))
			}
			r := rand.New(rand.NewSource(6))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				key := s.keys[i%n]
				s.set(key, float64(i%19+1))
				s.choose(r)
			}
		})
	}
}
