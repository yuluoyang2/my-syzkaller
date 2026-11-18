// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"container/heap"
	"math"
	"math/rand"
)

const (
	directedTopFrac = 0.01
	directedTopMin  = 8
	directedTopMax  = 64
	directedEpsilon = 0.12
)

// directedSampler maintains the highest T weights with two indexed heaps.
// set is called under Corpus.mu's write lock and costs O(log N). choose is
// read-only and scans at most 64 entries, so concurrent corpus readers are safe.
// The Fenwick totals are retained independently of the rank partition.
// Do not copy an initialized sampler: its heaps refer back to their owner.
type directedSampler struct {
	keys    []string
	indices map[string]int
	weights []float64
	tree    []float64

	top       directedScoreHeap // minimum of the retained T largest weights
	rest      directedScoreHeap // maximum of all other weights
	positions []int
	inTop     []bool

	// A boundary score can have more tied seeds than remaining Top slots.
	// Keep its entire tie group, with O(1) insertion/removal and uniform draws.
	buckets   map[float64][]int
	bucketPos []int
}

func (s *directedSampler) sum(n int) float64 {
	ret := 0.0
	for n > 0 {
		ret += s.tree[n-1]
		n -= n & -n
	}
	return ret
}

func (s *directedSampler) topSize() int {
	n := len(s.keys)
	size := int(float64(n) * directedTopFrac)
	return min(n, directedTopMax, max(directedTopMin, size))
}

func (s *directedSampler) set(key string, weight float64) {
	if math.IsNaN(weight) || math.IsInf(weight, 0) || weight < 0 {
		panic("invalid directed sampling weight")
	}
	if s.indices == nil {
		s.indices = make(map[string]int)
		s.buckets = make(map[float64][]int)
		s.top = directedScoreHeap{owner: s, minimum: true}
		s.rest = directedScoreHeap{owner: s}
	}
	idx, exists := s.indices[key]
	if exists && s.weights[idx] == weight {
		return
	}
	if !exists {
		idx = len(s.keys)
		s.indices[key] = idx
		s.keys = append(s.keys, key)
		s.weights = append(s.weights, weight)
		s.positions = append(s.positions, -1)
		s.inTop = append(s.inTop, false)
		s.bucketPos = append(s.bucketPos, 0)
		n := idx + 1
		s.tree = append(s.tree, weight+s.sum(idx)-s.sum(n-(n&-n)))
		s.addBucket(idx)
		heap.Push(&s.rest, idx)
	} else {
		old := s.weights[idx]
		s.removeBucket(idx)
		s.weights[idx] = weight
		s.addBucket(idx)
		for n := idx + 1; n <= len(s.keys); n += n & -n {
			s.tree[n-1] += weight - old
		}
		if s.inTop[idx] {
			heap.Fix(&s.top, s.positions[idx])
		} else {
			heap.Fix(&s.rest, s.positions[idx])
		}
	}
	s.rebalance()
}

func (s *directedSampler) addBucket(idx int) {
	weight := s.weights[idx]
	s.bucketPos[idx] = len(s.buckets[weight])
	s.buckets[weight] = append(s.buckets[weight], idx)
}

func (s *directedSampler) removeBucket(idx int) {
	weight := s.weights[idx]
	bucket := s.buckets[weight]
	pos := s.bucketPos[idx]
	last := bucket[len(bucket)-1]
	bucket[pos] = last
	s.bucketPos[last] = pos
	bucket = bucket[:len(bucket)-1]
	if len(bucket) == 0 {
		delete(s.buckets, weight)
	} else {
		s.buckets[weight] = bucket
	}
}

func (s *directedSampler) rebalance() {
	size := s.topSize()
	for s.top.Len() < size {
		heap.Push(&s.top, heap.Pop(&s.rest))
	}
	for s.top.Len() > size {
		heap.Push(&s.rest, heap.Pop(&s.top))
	}
	for s.top.Len() != 0 && s.rest.Len() != 0 &&
		s.weights[s.rest.items[0]] > s.weights[s.top.items[0]] {
		low := heap.Pop(&s.top)
		high := heap.Pop(&s.rest)
		heap.Push(&s.top, high)
		heap.Push(&s.rest, low)
	}
}

func (s *directedSampler) choose(r *rand.Rand) string {
	n := len(s.keys)
	if n == 0 {
		return ""
	}
	if r.Float64() < directedEpsilon {
		return s.keys[r.Intn(n)]
	}
	total := 0.0
	for _, idx := range s.top.items {
		total += s.weights[idx]
	}
	if total <= 0 {
		// With no score evidence, do not invent a fixed elite by seed hash.
		return s.keys[r.Intn(n)]
	}
	cutoff := s.weights[s.top.items[0]]
	val := r.Float64() * total
	lastPositive := s.top.items[0]
	for _, idx := range s.top.items {
		if s.weights[idx] <= cutoff {
			continue
		}
		lastPositive = idx
		if val < s.weights[idx] {
			return s.keys[idx]
		}
		val -= s.weights[idx]
	}
	if cutoff > 0 {
		// The residual mass is remainingSlots * cutoff, not tieCount *
		// cutoff. Drawing uniformly from the whole boundary tie group has
		// the same marginal probabilities as randomly filling those slots
		// on every draw, without rebuilding or expanding Top to the tail.
		bucket := s.buckets[cutoff]
		return s.keys[bucket[r.Intn(len(bucket))]]
	}
	// Only possible through floating-point rounding at a zero-weight boundary.
	return s.keys[lastPositive]
}

type directedScoreHeap struct {
	owner   *directedSampler
	items   []int
	minimum bool
}

func (h directedScoreHeap) Len() int { return len(h.items) }

func (h directedScoreHeap) Less(i, j int) bool {
	a, b := h.items[i], h.items[j]
	wa, wb := h.owner.weights[a], h.owner.weights[b]
	if wa == wb {
		return a < b
	}
	if h.minimum {
		return wa < wb
	}
	return wa > wb
}

func (h directedScoreHeap) Swap(i, j int) {
	h.items[i], h.items[j] = h.items[j], h.items[i]
	h.owner.positions[h.items[i]] = i
	h.owner.positions[h.items[j]] = j
}

func (h *directedScoreHeap) Push(value any) {
	idx := value.(int)
	h.owner.positions[idx] = len(h.items)
	h.owner.inTop[idx] = h.minimum
	h.items = append(h.items, idx)
}

func (h *directedScoreHeap) Pop() any {
	last := len(h.items) - 1
	idx := h.items[last]
	h.items = h.items[:last]
	h.owner.positions[idx] = -1
	return idx
}
