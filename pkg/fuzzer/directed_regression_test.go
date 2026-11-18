// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type directedTestExecutor func(*queue.Request)

func (exec directedTestExecutor) Submit(req *queue.Request) {
	exec(req)
}

func directedRegressionFuzzer(t *testing.T) (*Fuzzer, *corpus.Corpus, *prog.Prog) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	target, err := prog.GetTarget("test", "64")
	require.NoError(t, err)
	p, err := target.Deserialize([]byte("test$int(0x12345678, 0x0, 0x0, 0x0, 0x0)"), prog.Strict)
	require.NoError(t, err)
	c := corpus.NewDirectedCorpus(ctx, nil, corpus.NewDirectedCoverage([]uint64{10}, nil, nil, nil))
	f := NewFuzzer(ctx, &Config{
		Corpus: c, IsDirect: true, Coverage: true,
		EnabledCalls: map[*prog.Syscall]bool{target.SyscallMap["test$int"]: true},
	}, rand.New(rand.NewSource(1)), target)
	return f, c, p
}

func directedRegressionResult(p *prog.Prog, overflow bool) *queue.Result {
	info := &flatrpc.ProgInfo{}
	for range p.Calls {
		flags := flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished
		if overflow {
			flags |= flatrpc.CallFlagCoverageOverflow
		}
		info.Calls = append(info.Calls, &flatrpc.CallInfo{
			Flags: flags, Cover: []uint64{10}, Signal: []uint64{7},
		})
	}
	return &queue.Result{Status: queue.Success, Info: info}
}

func directedRegressionCall() *triageCall {
	return &triageCall{
		newSignal: signal.FromRaw([]uint64{7}, 3),
		signals:   [deflakeNeedRuns]signal.Signal{signal.FromRaw([]uint64{7}, 3)},
	}
}

func TestDirectedMinimizationDoesNotStartTriage(t *testing.T) {
	f, _, p := directedRegressionFuzzer(t)
	f.Cover.addRawMaxSignal([]uint64{7}, 3)
	job := &triageJob{
		p: p, fuzzer: f, info: &JobInfo{},
		directed: f.newDirectedTriage(p, "", corpus.DirectedWitness{}),
	}
	job.queue = directedTestExecutor(func(req *queue.Request) {
		req.Done(directedRegressionResult(req.Prog, false))
	})
	runs := job.directedConfirm(p, 0, 0)
	require.Len(t, runs, directedNeedRuns)
	assert.Never(t, func() bool {
		return f.statJobsTriage.Val() != 0
	}, 50*time.Millisecond, time.Millisecond, "internal replay must not create nested K triage")
}

func TestDirectedCoverFailurePreservesC(t *testing.T) {
	f, c, p := directedRegressionFuzzer(t)
	info := directedRegressionCall()
	job := &triageJob{
		p: p, flags: ProgMinimized | ProgSmashed,
		calls: map[int]*triageCall{0: info}, info: &JobInfo{},
		directed: f.newDirectedTriage(p, "", corpus.DirectedWitness{}),
	}
	execs := 0
	job.queue = directedTestExecutor(func(req *queue.Request) {
		execs++
		req.Done(directedRegressionResult(req.Prog, true))
	})
	job.run(f)
	require.False(t, info.newStableSignal.Empty())
	require.False(t, job.directed.confirmed)
	item := c.Item(hash.String(p.Serialize()))
	require.NotNil(t, item, "raw-cover overflow must not veto a stable C witness")
	assert.Nil(t, item.Directed, "missing K confirmation is not confirmed K=0")
	assert.Equal(t, info.newStableSignal.Len(), info.newStableSignal.Intersection(item.Signal).Len())
	assert.Empty(t, c.DirectedGainHistory())
	assert.LessOrEqual(t, execs, directedMaxRuns)
}

func TestDirectedTerminalKConfirmationPreservesCompletedC(t *testing.T) {
	for _, status := range []queue.Status{queue.Crashed, queue.Hanged} {
		t.Run(status.String(), func(t *testing.T) {
			f, c, p := directedRegressionFuzzer(t)
			info := directedRegressionCall()
			job := &triageJob{
				p: p, flags: ProgMinimized | ProgSmashed,
				calls: map[int]*triageCall{0: info}, info: &JobInfo{},
				directed: f.newDirectedTriage(p, "", corpus.DirectedWitness{}),
			}
			execs := 0
			job.queue = directedTestExecutor(func(req *queue.Request) {
				execs++
				if execs <= 2 {
					req.Done(directedRegressionResult(req.Prog, false))
				} else {
					req.Done(&queue.Result{Status: status})
				}
			})
			job.run(f)
			assert.Equal(t, 3, execs, "stop K confirmation at the first terminal result")
			require.False(t, job.directed.confirmed)
			require.False(t, info.newStableSignal.Empty())
			item := c.Item(hash.String(p.Serialize()))
			require.NotNil(t, item, "keep C decided before the terminal K sample")
			assert.Nil(t, item.Directed)
			assert.Empty(t, c.DirectedGainHistory())
		})
	}
}

func TestDirectedCoverRetriesDoNotExtendCWindow(t *testing.T) {
	f, c, p := directedRegressionFuzzer(t)
	info := directedRegressionCall()
	job := &triageJob{
		p: p, flags: ProgMinimized | ProgSmashed,
		calls: map[int]*triageCall{0: info}, info: &JobInfo{},
		directed: f.newDirectedTriage(p, "", corpus.DirectedWitness{}),
	}
	execs := 0
	job.queue = directedTestExecutor(func(req *queue.Request) {
		execs++
		res := directedRegressionResult(req.Prog, true)
		if execs <= deflakeMaxRuns {
			res.Info.Calls[0].Signal = nil
		}
		req.Done(res)
	})
	job.run(f)
	assert.Greater(t, execs, deflakeMaxRuns, "raw cover still gets its bounded retries")
	assert.Empty(t, info.newStableSignal, "signals outside C's deflake window are not stable C")
	assert.Empty(t, c.Items())
}

func TestDirectedMinimizationFailurePreservesOriginal(t *testing.T) {
	for _, status := range []queue.Status{queue.Crashed, queue.Hanged, queue.Success} {
		t.Run(status.String(), func(t *testing.T) {
			f, c, p := directedRegressionFuzzer(t)
			f.Cover.addRawMaxSignal([]uint64{7}, 3)
			job := &triageJob{
				p: p, calls: map[int]*triageCall{}, info: &JobInfo{},
				directed: f.newDirectedTriage(p, "", corpus.DirectedWitness{}),
			}
			execs := 0
			job.queue = directedTestExecutor(func(req *queue.Request) {
				execs++
				if execs <= directedNeedRuns {
					req.Done(directedRegressionResult(req.Prog, false))
					return
				}
				assert.Contains(t, c.DirectedGainHistory(), uint64(10), "settle original before minimizing")
				if status == queue.Success {
					res := directedRegressionResult(req.Prog, false)
					for _, call := range res.Info.Calls {
						call.Cover = []uint64{99}
					}
					req.Done(res)
				} else {
					req.Done(&queue.Result{Status: status})
				}
			})
			job.run(f)
			require.True(t, job.directed.confirmed)
			item := c.Item(hash.String(p.Serialize()))
			require.NotNil(t, item, "keep the original when simplification fails")
			assert.Equal(t, []uint64{10}, item.Directed.StableCover)
			assert.Equal(t, []uint64{10}, c.DirectedGainHistory())
			assert.True(t, job.directed.settled)
		})
	}
}

func TestDirectedCrashingCMinimizationPreservesPriority(t *testing.T) {
	f, c, p := directedRegressionFuzzer(t)
	p, err := p.Target.Deserialize([]byte(
		"test$int(0x2, 0x0, 0x0, 0x0, 0x0)\ntest$int(0x12345678, 0x0, 0x0, 0x0, 0x0)"), prog.Strict)
	require.NoError(t, err)
	f.Cover.addRawMaxSignal([]uint64{7}, 3)
	info := directedRegressionCall()
	job := &triageJob{
		p: p, flags: ProgSmashed, calls: map[int]*triageCall{1: info}, info: &JobInfo{},
		directed: f.newDirectedTriage(p, "", corpus.DirectedWitness{}),
	}
	execs := 0
	job.queue = directedTestExecutor(func(req *queue.Request) {
		execs++
		if execs <= directedNeedRuns {
			res := directedRegressionResult(req.Prog, false)
			res.Info.Calls[0].Signal = nil
			req.Done(res)
		} else {
			req.Done(&queue.Result{Status: queue.Crashed})
		}
	})
	job.run(f)
	require.Greater(t, execs, directedNeedRuns, "exercise a simplification, not just original verification")
	item := c.Item(hash.String(p.Serialize()))
	require.NotNil(t, item)
	assert.Equal(t, 1, item.Call)
	assert.Equal(t, info.newStableSignal.Len(), info.newStableSignal.Intersection(item.Signal).Len())
	assert.Equal(t, []uint64{10}, c.DirectedGainHistory())
}

func TestDirectedConfirmDoesNotRetryCrash(t *testing.T) {
	f, _, p := directedRegressionFuzzer(t)
	requests := queue.Plain()
	source := queue.Retry(requests)
	job := &triageJob{
		p: p, fuzzer: f, queue: requests, info: &JobInfo{},
		directed: f.newDirectedTriage(p, "", corpus.DirectedWitness{}),
	}
	done := make(chan []directedRun, 1)
	go func() { done <- job.directedConfirm(p, 0, 0) }()
	var req *queue.Request
	require.Eventually(t, func() bool {
		req = source.Next()
		return req != nil
	}, time.Second, time.Millisecond)
	assert.False(t, req.Important, "queue.Retry must not hide the first directed-validation crash")
	req.Done(&queue.Result{Status: queue.Crashed})
	select {
	case runs := <-done:
		assert.Empty(t, runs)
	case <-time.After(time.Second):
		t.Fatal("directed confirmation waited for a crash retry")
	}
	assert.Nil(t, source.Next())
	assert.True(t, job.directed.failed.Load())
}

func TestDirectedAuxiliaryCoverageFlags(t *testing.T) {
	for _, direct := range []bool{false, true} {
		for _, kind := range []string{"smash", "hints"} {
			t.Run(kind+map[bool]string{false: "/normal", true: "/directed"}[direct], func(t *testing.T) {
				f, _, p := directedRegressionFuzzer(t)
				f.Config.IsDirect = direct
				mutants, comparisons := 0, 0
				exec := directedTestExecutor(func(req *queue.Request) {
					flags := req.ExecOpts.ExecFlags
					if flags&flatrpc.ExecFlagCollectComps != 0 {
						comparisons++
						assert.Zero(t, flags&(flatrpc.ExecFlagCollectSignal|flatrpc.ExecFlagCollectCover))
						req.Done(&queue.Result{Info: &flatrpc.ProgInfo{Calls: []*flatrpc.CallInfo{{
							Comps: []*flatrpc.Comparison{{Pc: 100, Op1: 0x12345678, Op2: 0x76543210, IsConst: true}},
						}}}})
						return
					}
					mutants++
					assert.NotZero(t, flags&flatrpc.ExecFlagCollectSignal)
					assert.Equal(t, direct, flags&flatrpc.ExecFlagCollectCover != 0)
					req.Done(&queue.Result{Status: queue.Hanged})
				})
				if kind == "smash" {
					(&smashJob{p: p, exec: exec, info: &JobInfo{}}).run(f)
				} else {
					(&hintsJob{p: p, call: 0, exec: exec, info: &JobInfo{}}).run(f)
					assert.Equal(t, 3, comparisons)
				}
				assert.Positive(t, mutants, "exercise an actual mutation, not only comparison collection")
			})
		}
	}
}
