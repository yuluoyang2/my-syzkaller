// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/mgrconfig"
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

func TestGenDirectProgRequest(t *testing.T) {
	target, err := prog.GetTarget("linux", "amd64")
	require.NoError(t, err)
	fuzzer := NewFuzzer(t.Context(), &Config{
		Corpus:   corpus.NewCorpus(t.Context()),
		Coverage: true,
		IsDirect: true,
		DirectTargets: []mgrconfig.DirectTarget{{
			Target:  "ioctl$sock_netrom_SIOCADDRT",
			Related: []string{"syz_init_net_socket$netrom"},
		}},
	}, rand.New(rand.NewSource(1)), target)
	// Every request is generated from scratch, so each one has to carry the
	// target call last.
	for range 20 {
		req := genDirectProgRequest(fuzzer, rand.New(rand.NewSource(2)))
		require.NotNil(t, req)
		calls := req.Prog.Calls
		require.NotEmpty(t, calls)
		assert.Equal(t, "ioctl$sock_netrom_SIOCADDRT", calls[len(calls)-1].Meta.Name)
	}
}

func TestGenDirectProgRequestNoRelated(t *testing.T) {
	target, err := prog.GetTarget("linux", "amd64")
	require.NoError(t, err)
	fuzzer := NewFuzzer(t.Context(), &Config{
		Corpus:   corpus.NewCorpus(t.Context()),
		Coverage: true,
		IsDirect: true,
		DirectTargets: []mgrconfig.DirectTarget{{
			Target: "syz_emit_vhci",
		}},
	}, rand.New(rand.NewSource(1)), target)
	req := genDirectProgRequest(fuzzer, rand.New(rand.NewSource(2)))
	require.NotNil(t, req)
	calls := req.Prog.Calls
	require.NotEmpty(t, calls)
	assert.Equal(t, "syz_emit_vhci", calls[len(calls)-1].Meta.Name)
}

func TestGenDirectProgRequestDisabled(t *testing.T) {
	rnd := rand.New(rand.NewSource(1))
	assert.Nil(t, genDirectProgRequest(&Fuzzer{Config: &Config{}}, rnd))
	// IsDirect without targets is rejected by config validation, but the fuzzer
	// must not panic if it happens anyway.
	assert.Nil(t, genDirectProgRequest(&Fuzzer{Config: &Config{IsDirect: true}}, rnd))
}

// TestGenDirectProgRequestFallback covers a target that config validation let
// through but that the choice table excludes, e.g. because enabled_syscalls
// filtered it out. Generation fails and the caller falls back to a random
// program, so the request must be nil rather than a broken program.
func TestGenDirectProgRequestFallback(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	require.NoError(t, err)
	ct := target.BuildChoiceTable(nil, map[*prog.Syscall]bool{
		target.SyscallMap["test$res0"]: true,
	})
	fuzzer := &Fuzzer{
		Config: &Config{
			Corpus:        corpus.NewCorpus(t.Context()),
			IsDirect:      true,
			DirectTargets: []mgrconfig.DirectTarget{{Target: "test$int"}},
			EnabledCalls:  map[*prog.Syscall]bool{target.SyscallMap["test$res0"]: true},
		},
		target: target,
		ct:     ct,
	}
	assert.Nil(t, genDirectProgRequest(fuzzer, rand.New(rand.NewSource(1))))
}

func TestDirectMutateOptsGate(t *testing.T) {
	p := testProg(t)
	fuzzer := &Fuzzer{Config: &Config{}}

	opts := fuzzer.mutateOptsFor(p)
	assert.Equal(t, prog.DefaultMutateOpts.SpliceWeight, opts.SpliceWeight)
	assert.Equal(t, prog.DefaultMutateOpts.MutateArgWeight, opts.MutateArgWeight)

	fuzzer.Config.IsDirect = true
	fuzzer.directNames = map[string]struct{}{p.Calls[0].Meta.Name: {}}
	opts = fuzzer.mutateOptsFor(p)
	assert.Equal(t, 10, opts.SpliceWeight)
	assert.Equal(t, 200, opts.MutateArgWeight)
	assert.Equal(t, prog.DefaultMutateOpts.InsertWeight, opts.InsertWeight)
	assert.Equal(t, prog.DefaultMutateOpts.RemoveCallWeight, opts.RemoveCallWeight)
	assert.Equal(t, p.Calls[0], opts.TargetCall)

	other := testProg(t)
	other.Calls = nil
	opts = fuzzer.mutateOptsFor(other)
	assert.Equal(t, prog.DefaultMutateOpts.SpliceWeight, opts.SpliceWeight)
}

func TestDirectMutateOptsMatchesTargetByName(t *testing.T) {
	p := testProg(t)
	require.GreaterOrEqual(t, len(p.Calls), 3)
	fuzzer := &Fuzzer{Config: &Config{IsDirect: true}}
	// The target call is in the middle of the program, so only a name match can
	// find it.
	fuzzer.directNames = map[string]struct{}{"unrelated$call": {}, p.Calls[1].Meta.Name: {}}

	opts := fuzzer.mutateOptsFor(p)
	assert.Equal(t, p.Calls[1], opts.TargetCall)
	assert.True(t, opts.SkipResourceArgs)
	assert.Equal(t, 200, opts.MutateArgWeight)
	assert.Equal(t, 10, opts.SpliceWeight)
}

func TestDirectMutateOptsPicksLastTargetCall(t *testing.T) {
	p := testProg(t)
	require.GreaterOrEqual(t, len(p.Calls), 3)
	fuzzer := &Fuzzer{Config: &Config{IsDirect: true}}
	// Both calls 0 and 2 are targets; the deeper one is the one that matters.
	fuzzer.directNames = map[string]struct{}{p.Calls[0].Meta.Name: {}, p.Calls[2].Meta.Name: {}}

	opts := fuzzer.mutateOptsFor(p)
	assert.Equal(t, p.Calls[2], opts.TargetCall)
}

func TestDirectMutateOptsNoTargetMatch(t *testing.T) {
	p := testProg(t)
	fuzzer := &Fuzzer{Config: &Config{IsDirect: true}}
	fuzzer.directNames = map[string]struct{}{"definitely$not$here": {}}

	opts := fuzzer.mutateOptsFor(p)
	assert.Equal(t, prog.DefaultMutateOpts.MutateArgWeight, opts.MutateArgWeight)
	assert.False(t, opts.SkipResourceArgs)
	assert.Nil(t, opts.TargetCall)
	assert.Nil(t, opts.CompanionCall)
}

// fuzzPairProg builds r0 = test$res0(); test$res1(r0), where the consumer is
// the target. The producer is matched through the data dependency, not by name.
func fuzzPairProg(t *testing.T) *prog.Prog {
	t.Helper()
	target, err := prog.GetTarget("test", "64")
	require.NoError(t, err)
	p, err := target.Deserialize([]byte("r0 = test$res0()\ntest$res1(r0)"), prog.Strict)
	require.NoError(t, err)
	return p
}

func TestFindPairUsesDependency(t *testing.T) {
	p := fuzzPairProg(t)
	target, companion := findPair(p, map[string]struct{}{"test$res1": {}})
	require.NotNil(t, target)
	assert.Equal(t, "test$res1", target.Meta.Name)
	require.NotNil(t, companion, "companion must be found through the resource argument")
	assert.Equal(t, "test$res0", companion.Meta.Name)
}

func TestFindPairNoTarget(t *testing.T) {
	p := fuzzPairProg(t)
	target, companion := findPair(p, map[string]struct{}{"definitely$not$here": {}})
	assert.Nil(t, target)
	assert.Nil(t, companion)
}

// TestFindPairNoCompanion covers a target that consumes nothing, e.g. a
// pseudo-syscall: there is no companion to protect or mutate.
func TestFindPairNoCompanion(t *testing.T) {
	target, err := prog.GetTarget("test", "64")
	require.NoError(t, err)
	p, err := target.Deserialize([]byte("test$int(0x0, 0x0, 0x0, 0x0, 0x0)"), prog.Strict)
	require.NoError(t, err)
	targetCall, companion := findPair(p, map[string]struct{}{"test$int": {}})
	require.NotNil(t, targetCall)
	assert.Nil(t, companion)
}
