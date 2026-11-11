// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func testTarget(t *testing.T) *prog.Target {
	t.Helper()
	target, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestPickAnchor(t *testing.T) {
	f := &fuzzRun{
		cfg: &mgrconfig.Config{Type: "qemu"},
		ts: &targetSet{
			targetPC: map[uint64]struct{}{0x100: {}, 0x101: {}},
			nearbyPC: map[uint64]struct{}{0x200: {}},
		},
	}
	res := &blockResult{perCall: map[int]map[uint64]struct{}{
		0:  {0x300: {}},
		1:  {0x100: {}, 0x101: {}},
		2:  {0x200: {}},
		-1: {0x100: {}, 0x200: {}},
	}}
	if got := f.pickAnchor(res); got != 1 {
		t.Fatalf("anchor = %v, want call 1", got)
	}
	// No target or nearby coverage at all: the anchor is unknown and the caller
	// falls back to the last call.
	res = &blockResult{perCall: map[int]map[uint64]struct{}{0: {0x300: {}}}}
	if got := f.pickAnchor(res); got != -1 {
		t.Fatalf("anchor = %v, want -1", got)
	}
}

func TestMutateChangesProgram(t *testing.T) {
	target := testTarget(t)
	p, err := target.Deserialize([]byte(`socket$nl_xfrm(0x10, 0x0, 0x0)
sendmsg$nl_xfrm(0x0, 0x0, &(0x7f0000000000), 0x0, 0x0, 0x0)
`), prog.NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	f := &fuzzRun{
		rnd:   rand.New(rand.NewSource(1)),
		ct:    target.BuildChoiceTable([]*prog.Prog{p}, nil),
		seeds: []*prog.Prog{p},
	}
	changed := 0
	for range 50 {
		cand := f.mutate(p, 1)
		if cand == nil {
			continue
		}
		changed++
		if bytes.Equal(cand.Serialize(), p.Serialize()) {
			t.Fatalf("candidate is identical to the seed")
		}
		if len(cand.Calls) == 0 {
			t.Fatalf("candidate has no calls")
		}
	}
	if changed == 0 {
		t.Fatal("mutation never produced a candidate")
	}
}
