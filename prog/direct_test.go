// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"testing"
)

func TestGenerateSequence(t *testing.T) {
	target := InitTargetTest(t, "test", "64")
	ct := target.BuildChoiceTable(nil, nil)
	p, err := target.GenerateSequence(rand.NewSource(1), ct, []string{"test$int"})
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
	if _, err := target.GenerateSequence(rand.NewSource(1), ct, []string{"not_a_syscall"}); err == nil {
		t.Fatal("expected unknown syscall error")
	}
	if _, err := target.GenerateSequence(rand.NewSource(1), ct, []string{"disabled0"}); err == nil {
		t.Fatal("expected disabled syscall error")
	}
	if _, err := target.GenerateSequence(rand.NewSource(1), ct, []string{"serialize3"}); err == nil {
		t.Fatal("expected no_generate syscall error")
	}
	restrictedCT := target.BuildChoiceTable(nil, map[*Syscall]bool{
		target.SyscallMap["test$res0"]: true,
	})
	if _, err := target.GenerateSequence(rand.NewSource(1), restrictedCT, []string{"test$int"}); err == nil {
		t.Fatal("expected not-enabled syscall error")
	}
	tooLong := make([]string, MaxCalls+1)
	for i := range tooLong {
		tooLong[i] = "test$int"
	}
	if _, err := target.GenerateSequence(rand.NewSource(1), ct, tooLong); err == nil {
		t.Fatal("expected an overlong syscall chain to be rejected")
	}
	before := len(p.Calls)
	p.AppendGeneratedCalls(rand.NewSource(2), 2, ct)
	if len(p.Calls) < before {
		t.Fatalf("append dropped calls: %d -> %d", before, len(p.Calls))
	}
}

func TestAppendGeneratedCallsLimit(t *testing.T) {
	target := InitTargetTest(t, "linux", "amd64")
	ct := target.BuildChoiceTable(nil, nil)
	p, err := target.GenerateSequence(rand.NewSource(0), ct, []string{
		"syz_init_net_socket$bt_l2cap", "bind$bt_l2cap", "listen", "syz_emit_vhci",
	})
	if err != nil {
		t.Fatal(err)
	}
	rnd := rand.New(rand.NewSource(1865))
	p.MutateCallArg(rnd, len(p.Calls)-1, ct, 2)
	extra := rnd.Intn(3)
	if extra == 0 {
		t.Fatal("test seed did not request appended calls")
	}
	p.AppendGeneratedCalls(rnd, extra, ct)
	if len(p.Calls) > RecommendedCalls {
		t.Fatalf("append produced %d calls, want at most %d", len(p.Calls), RecommendedCalls)
	}
}

func TestChooseCallPrefersTemplateCall(t *testing.T) {
	target := InitTargetTest(t, "test", "64")
	p := target.Generate(rand.NewSource(1), 4, target.BuildChoiceTable(nil, nil))
	if len(p.Calls) < 2 {
		t.Fatal("need two calls")
	}
	r := newRand(target, rand.NewSource(1))
	opts := MutateOpts{PrefixLen: len(p.Calls), PreferCall: 0}
	hits := 0
	const n = 200
	for range n {
		if chooseCall(p, r, opts) == 0 {
			hits++
		}
	}
	if hits < n*6/10 {
		t.Fatalf("prefer call chosen %d/%d", hits, n)
	}
	extra := MutateOpts{PrefixLen: 1, PreferCall: -1}
	for range n {
		if got := chooseCall(p, r, extra); got != 0 {
			t.Fatalf("extra template chose call %d, want one of the template calls", got)
		}
	}
}
