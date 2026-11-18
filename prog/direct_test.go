// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"testing"
)

func TestGenerateCallPair(t *testing.T) {
	target := InitTargetTest(t, "test", "64")
	ct := target.BuildChoiceTable(nil, nil)
	p, err := target.GenerateCallPair(rand.NewSource(1), ct, "test$int", "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range p.Calls {
		if c.Meta.Name == "test$int" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing test$int in %s", p.Serialize())
	}
	if _, err := target.GenerateCallPair(rand.NewSource(1), ct, "not_a_syscall", ""); err == nil {
		t.Fatal("expected unknown syscall error")
	}
	if _, err := target.GenerateCallPair(rand.NewSource(1), ct, "disabled0", ""); err == nil {
		t.Fatal("expected disabled syscall error")
	}
	if _, err := target.GenerateCallPair(rand.NewSource(1), ct, "serialize3", ""); err == nil {
		t.Fatal("expected no_generate syscall error")
	}
	if _, err := target.GenerateCallPair(rand.NewSource(1), ct, "test$int", "not_a_syscall"); err == nil {
		t.Fatal("expected unknown related syscall error")
	}
	restrictedCT := target.BuildChoiceTable(nil, map[*Syscall]bool{
		target.SyscallMap["test$res0"]: true,
	})
	if _, err := target.GenerateCallPair(rand.NewSource(1), restrictedCT, "test$int", ""); err == nil {
		t.Fatal("expected not-enabled syscall error")
	}
}

// TestGenerateCallPairBindsNetromFD checks the point of the pair generation:
// the target call's resource argument must refer to what the related call
// produced, not to a resource made by the random fill.
func TestGenerateCallPairBindsNetromFD(t *testing.T) {
	target := InitTargetTest(t, "linux", "amd64")
	ct := target.BuildChoiceTable(nil, nil)
	const (
		targetName  = "ioctl$sock_netrom_SIOCADDRT"
		relatedName = "syz_init_net_socket$netrom"
	)
	const runs = 100
	ok := 0
	for seed := int64(0); seed < runs; seed++ {
		p, err := target.GenerateCallPair(rand.NewSource(seed), ct, targetName, relatedName)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		var socket, ioctl *Call
		for _, c := range p.Calls {
			if socket == nil && c.Meta.Name == relatedName {
				socket = c
				continue
			}
			if socket != nil && c.Meta.Name == targetName {
				ioctl = c
			}
		}
		if socket == nil || ioctl == nil || socket.Ret == nil {
			t.Fatalf("seed %d: call pair not present:\n%s", seed, p.Serialize())
		}
		fd, isRes := ioctl.Args[0].(*ResultArg)
		if !isRes {
			t.Fatalf("seed %d: target fd is not a resource arg:\n%s", seed, p.Serialize())
		}
		if fd.Res != socket.Ret {
			t.Fatalf("seed %d: target fd is not the related socket:\n%s", seed, p.Serialize())
		}
		ok++
	}
	if ok != runs {
		t.Fatalf("only %d/%d programs bound the target fd", ok, runs)
	}
}

// TestGenerateCallPairNoRelated covers targets that need no companion call,
// e.g. a pseudo-syscall that takes no fd. The target still has to be generated
// as the last call, with its arguments filled by ordinary generation.
func TestGenerateCallPairNoRelated(t *testing.T) {
	target := InitTargetTest(t, "linux", "amd64")
	ct := target.BuildChoiceTable(nil, nil)
	for seed := int64(0); seed < 50; seed++ {
		p, err := target.GenerateCallPair(rand.NewSource(seed), ct, "syz_emit_vhci", "")
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		last := p.Calls[len(p.Calls)-1]
		if last.Meta.Name != "syz_emit_vhci" {
			t.Fatalf("seed %d: last call is %s:\n%s", seed, last.Meta.Name, p.Serialize())
		}
		if err := p.validate(); err != nil {
			t.Fatalf("seed %d: invalid program: %v\n%s", seed, err, p.Serialize())
		}
	}
}

func TestGenerateCallPairBoundsFill(t *testing.T) {
	target := InitTargetTest(t, "linux", "amd64")
	ct := target.BuildChoiceTable(nil, nil)
	// Random fill can expand into a few hundred resource constructors. It has
	// to be dropped instead of rejecting the program or pushing it past the
	// call limit, and dropping it must not leave dangling arg links or remove
	// the pair itself.
	for seed := int64(0); seed < 300; seed++ {
		p, err := target.GenerateCallPair(rand.NewSource(seed), ct,
			"ioctl$sock_netrom_SIOCADDRT", "syz_init_net_socket$netrom")
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if len(p.Calls) > RecommendedCalls {
			t.Fatalf("seed %d: generated %d calls, want at most %d",
				seed, len(p.Calls), RecommendedCalls)
		}
		if err := p.validate(); err != nil {
			t.Fatalf("seed %d: invalid program: %v\n%s", seed, err, p.Serialize())
		}
	}
}

func TestCheckCallPair(t *testing.T) {
	target := InitTargetTest(t, "linux", "amd64")
	if err := target.CheckCallPair("ioctl$sock_netrom_SIOCADDRT",
		"syz_init_net_socket$netrom"); err != nil {
		t.Fatalf("expected a valid pair: %v", err)
	}
	// The target does not consume anything the related call produces.
	if err := target.CheckCallPair("syz_init_net_socket$netrom",
		"ioctl$sock_netrom_SIOCADDRT"); err == nil {
		t.Fatal("expected an invalid pair")
	}
	if err := target.CheckCallPair("ioctl$sock_netrom_SIOCADDRT", "not_a_syscall"); err == nil {
		t.Fatal("expected an unknown syscall error")
	}
}

// TestChooseCallAvoidsPair checks that the generic argument mutation does not
// mostly land on the pair: the pair has its own branch, and starving the setup
// calls that produce its resources would make the pair unreachable.
func TestChooseCallAvoidsPair(t *testing.T) {
	target := InitTargetTest(t, "test", "64")
	p := target.Generate(rand.NewSource(1), 4, target.BuildChoiceTable(nil, nil))
	if len(p.Calls) < 3 {
		t.Fatal("need at least three calls")
	}
	r := newRand(target, rand.NewSource(1))
	opts := MutateOpts{TargetCall: p.Calls[0], CompanionCall: p.Calls[1]}
	const n = 500
	hits := make(map[int]int)
	for range n {
		hits[chooseCall(p, r, opts)]++
	}
	for _, idx := range []int{0, 1} {
		if hits[idx]*4 > n {
			t.Fatalf("pair call %d chosen %d/%d times, want at most a quarter", idx, hits[idx], n)
		}
	}
	if hits[2] == 0 {
		t.Fatalf("non-pair call never chosen: %v", hits)
	}
}

// pairProg builds a program with a resource producer and a consumer plus a few
// unrelated calls, so structural mutations have something to remove.
func pairProg(t *testing.T, target *Target) *Prog {
	t.Helper()
	p, err := target.Deserialize([]byte(`r0 = test$res0()
test$int(0x0, 0x0, 0x0, 0x0, 0x0)
test$str0(&(0x7f0000000000)='')
test$res1(r0)`), Strict)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	return p
}

// TestMutateKeepsPair runs the full mutation loop and checks that neither half
// of the pair can be dropped by the structural mutations.
func TestMutateKeepsPair(t *testing.T) {
	target := InitTargetTest(t, "test", "64")
	base := pairProg(t, target)
	enabled := map[*Syscall]bool{}
	for _, c := range base.Calls {
		enabled[c.Meta] = true
	}
	for _, name := range []string{"test$blob0", "test$array_int", "test$opt0"} {
		enabled[target.SyscallMap[name]] = true
	}
	ct := target.BuildChoiceTable(nil, enabled)
	for seed := int64(0); seed < 200; seed++ {
		p := base.Clone()
		opts := DefaultMutateOpts
		opts.TargetCall = p.Calls[3]    // test$res1
		opts.CompanionCall = p.Calls[0] // test$res0
		opts.SpliceWeight = 200         // exercise the trim path
		p.MutateWithOpts(rand.NewSource(seed), RecommendedCalls, ct, nil,
			[]*Prog{base, pairProg(t, target)}, opts)
		var producer, consumer bool
		for _, c := range p.Calls {
			producer = producer || c.Meta.Name == "test$res0"
			consumer = consumer || c.Meta.Name == "test$res1"
		}
		if !producer || !consumer {
			t.Fatalf("seed %d: mutation dropped the pair (producer=%v consumer=%v):\n%s",
				seed, producer, consumer, p.Serialize())
		}
	}
}

// TestInsertBeforeTarget checks that call insertion cannot append calls after
// the target, where they would only add dead code.
func TestInsertBeforeTarget(t *testing.T) {
	target := InitTargetTest(t, "test", "64")
	base := pairProg(t, target)
	enabled := map[*Syscall]bool{}
	for _, c := range base.Calls {
		enabled[c.Meta] = true
	}
	for _, name := range []string{"test$blob0", "test$array_int", "test$opt0"} {
		enabled[target.SyscallMap[name]] = true
	}
	ct := target.BuildChoiceTable(nil, enabled)
	inserted := 0
	for seed := int64(0); seed < 100; seed++ {
		p := base.Clone()
		opts := DefaultMutateOpts
		opts.TargetCall = p.Calls[3]
		ctx := &mutator{
			p:      p,
			r:      newRand(target, rand.NewSource(seed)),
			ncalls: RecommendedCalls,
			ct:     ct,
			opts:   opts,
		}
		before := len(p.Calls)
		if !ctx.insertCall() || len(p.Calls) == before {
			continue
		}
		inserted++
		if last := p.Calls[len(p.Calls)-1]; last.Meta.Name != "test$res1" {
			t.Fatalf("seed %d: target is not last after insert:\n%s", seed, p.Serialize())
		}
	}
	if inserted == 0 {
		t.Fatal("insertCall never inserted a call")
	}
}

// TestSquashSkipsPair checks that squashAny does not turn the pair's arguments
// into ANY, which would throw away the structure the target needs.
func TestSquashSkipsPair(t *testing.T) {
	target := InitTargetTest(t, "test", "64")
	ct := target.BuildChoiceTable(nil, nil)
	p, err := target.Deserialize([]byte(`test$array0(&(0x7f0000000000)={0x4, [@f0=0x7], 0x4})`), Strict)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	if len(p.complexPtrs()) == 0 {
		t.Fatal("call has no squashable pointer")
	}
	opts := DefaultMutateOpts
	opts.TargetCall = p.Calls[0]
	ctx := &mutator{
		p:      p,
		r:      newRand(target, rand.NewSource(1)),
		ncalls: RecommendedCalls,
		ct:     ct,
		opts:   opts,
	}
	// Squash may fail for other reasons (no blobs), so check the arguments are
	// untouched rather than the return value.
	ctx.squashAny()
	if p.Target.isAnyPtr(p.Calls[0].Args[0].Type()) {
		t.Fatalf("target argument was squashed:\n%s", p.Serialize())
	}
	// A non-pair call is still squashable.
	p2, err := target.Deserialize([]byte(`test$array0(&(0x7f0000000000)={0x4, [@f0=0x7], 0x4})
test$array0(&(0x7f0000000000)={0x4, [@f0=0x7], 0x4})`), Strict)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}
	opts.TargetCall = p2.Calls[0]
	ctx = &mutator{
		p:      p2,
		r:      newRand(target, rand.NewSource(1)),
		ncalls: RecommendedCalls,
		ct:     ct,
		opts:   opts,
	}
	ctx.squashAny()
	if !p2.Target.isAnyPtr(p2.Calls[1].Args[0].Type()) {
		t.Fatalf("non-pair argument was not squashed:\n%s", p2.Serialize())
	}
}
