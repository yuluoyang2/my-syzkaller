// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"testing"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/prog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDirectedRunCover(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	require.NoError(t, err)
	p, err := target.Deserialize([]byte("r0 = test$res0()\ntest$res1(r0)"), prog.Strict)
	require.NoError(t, err)

	info := &flatrpc.ProgInfo{
		Calls: []*flatrpc.CallInfo{
			{Flags: flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished, Cover: []uint64{5, 3}},
			{Flags: flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished, Cover: []uint64{4, 3}},
		},
		Extra: &flatrpc.CallInfo{Flags: 0, Cover: []uint64{9}},
	}
	res := &queue.Result{Status: queue.Success, Info: info}
	cover, ok := directedRunCover(p, res)
	require.True(t, ok)
	assert.Equal(t, []uint64{3, 4, 5, 9}, cover, "program-level cover is deduplicated and sorted")

	info.Calls[0].Flags = flatrpc.CallFlagFinished
	_, ok = directedRunCover(p, res)
	assert.False(t, ok, "a call that was not executed invalidates the sample")

	info.Calls[0].Flags = flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished | flatrpc.CallFlagCoverageOverflow
	_, ok = directedRunCover(p, res)
	assert.False(t, ok, "truncated coverage invalidates the sample")

	info.Calls[0].Flags = flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished
	info.Extra.Flags = flatrpc.CallFlagCoverageOverflow
	_, ok = directedRunCover(p, res)
	assert.False(t, ok, "extra coverage overflow invalidates the sample")

	res.Status = queue.Restarted
	_, ok = directedRunCover(p, res)
	assert.False(t, ok, "restarted execution is not a valid sample")
}

func TestIntersectCover(t *testing.T) {
	assert.Nil(t, intersectCover([][]uint64{{1}, {1}}))
	assert.Equal(t, []uint64{2, 3}, intersectCover([][]uint64{
		{1, 2, 3},
		{2, 3, 4},
		{2, 3, 5},
	}))
	assert.Empty(t, intersectCover([][]uint64{
		{1, 2},
		{2, 3},
		{3, 4},
	}))
}

func TestDirectedSaveStableCover(t *testing.T) {
	coverage := corpus.NewDirectedCoverage([]uint64{10}, []uint64{20}, []uint64{30}, []uint64{40})
	corpusObj := corpus.NewDirectedCorpus(context.Background(), nil, coverage)
	fuzzer := &Fuzzer{Config: &Config{Corpus: corpusObj, IsDirect: true}}
	p, err := prog.GetTarget("test", "64")
	require.NoError(t, err)
	program, err := p.Deserialize([]byte("test$int(0x0, 0x0, 0x0, 0x0, 0x0)"), prog.Strict)
	require.NoError(t, err)

	job := &triageJob{
		p:        program,
		fuzzer:   fuzzer,
		info:     &JobInfo{},
		directed: &directedTriage{covers: [][]uint64{{10, 20}, {10, 20}, {10, 20}}},
	}
	require.True(t, job.directedFinalize())
	require.True(t, job.saveDirected(program, 0, job.directed.stable, nil, nil))

	item := corpusObj.Item(hash.String(program.Serialize()))
	require.NotNil(t, item)
	require.NotNil(t, item.Directed)
	assert.Equal(t, []uint64{10, 20}, item.Directed.StableCover)
	require.NotEmpty(t, item.Directed.Witnesses)
	assert.Equal(t, corpus.DirectedTarget, item.Directed.Witnesses[0].Level)
}
