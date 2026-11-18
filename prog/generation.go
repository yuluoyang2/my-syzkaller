// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math/rand"
)

// Generate generates a random program with ncalls calls.
// ct contains a set of allowed syscalls, if nil all syscalls are used.
func (target *Target) Generate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, ct, nil)
	for len(p.Calls) < ncalls {
		calls := r.generateCall(s, p, len(p.Calls))
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
	}
	// For the last generated call we could get additional calls that create
	// resources and overflow ncalls. Remove some of these calls.
	// The resources in the last call will be replaced with the default values,
	// which is exactly what we want.
	for len(p.Calls) > ncalls {
		p.RemoveCall(ncalls - 1)
	}
	p.sanitizeFix()
	p.debugValidate()
	return p
}

// GenerateCallPair builds one program with a related call first and the target
// call last. Resource arguments of the target call are wired to resources
// produced by the related call while it is generated, so the target consumes
// what the related call created instead of whatever the random fill made.
//
// relatedName may be empty, which means the target call needs no companion.
func (target *Target) GenerateCallPair(rs rand.Source, ct *ChoiceTable,
	targetName, relatedName string) (*Prog, error) {
	if targetName == "" {
		return nil, fmt.Errorf("empty target syscall")
	}
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, ct, nil)
	// keep marks calls that trimming must never drop: the related call and the
	// target call are the point of the program.
	var keep []bool
	appendCalls := func(calls []*Call, protected bool) {
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
			keep = append(keep, protected)
		}
	}
	// dropCalls detaches already generated calls that are not added to the
	// program. Generation links their args into existing resources, so dropping
	// them has to unwind those links, otherwise the result args keep references
	// to args that are not in the tree.
	dropCalls := func(calls []*Call) {
		for _, c := range calls {
			for _, arg := range c.Args {
				removeArg(arg)
			}
			if c.Ret != nil {
				removeArg(c.Ret)
			}
		}
	}
	var bind []*Call
	if relatedName != "" {
		meta, err := target.checkGeneratable(ct, relatedName)
		if err != nil {
			return nil, err
		}
		calls := r.generateParticularCall(s, meta)
		if len(calls) == 0 {
			return nil, fmt.Errorf("failed to generate syscall %q", relatedName)
		}
		appendCalls(calls, true)
		bind = append(bind, calls[len(calls)-1])
	}
	meta, err := target.checkGeneratable(ct, targetName)
	if err != nil {
		return nil, err
	}
	// Interleave random fill between the related call and the target call: real
	// reproducers carry noise between the calls that matter. The budget leaves
	// room for the target, and fill that does not fit is dropped: a single
	// generateCall can recurse into a long resource-constructor chain.
	ncalls := min(RecommendedCalls, MaxCalls)
	if budget := ncalls - len(p.Calls) - 1; budget > 0 {
		fill := r.generateCall(s, p, len(p.Calls))
		if len(fill) <= budget {
			appendCalls(fill, false)
		} else {
			dropCalls(fill)
		}
	}
	// Bind the target call's resource arguments to what the related call
	// produced. The binding is live only for this generation, so the target
	// call cannot pick up an unrelated fd that fill created.
	r.bindCalls = bind
	calls := r.generateParticularCall(s, meta)
	r.bindCalls = nil
	if len(calls) == 0 {
		return nil, fmt.Errorf("failed to generate syscall %q", targetName)
	}
	appendCalls(calls, true)
	if len(p.Calls) > MaxCalls {
		return nil, fmt.Errorf("call pair expanded to %d calls (max %d)", len(p.Calls), MaxCalls)
	}
	// Over budget: drop random fill, never a protected call.
	for len(p.Calls) > ncalls {
		drop := -1
		for i := len(p.Calls) - 1; i >= 0; i-- {
			if !keep[i] {
				drop = i
				break
			}
		}
		if drop < 0 {
			break
		}
		p.RemoveCall(drop)
		keep = append(keep[:drop], keep[drop+1:]...)
	}
	p.sanitizeFix()
	p.debugValidate()
	return p, nil
}

// checkGeneratable returns the syscall meta if it can be generated with ct.
func (target *Target) checkGeneratable(ct *ChoiceTable, name string) (*Syscall, error) {
	meta := target.SyscallMap[name]
	if meta == nil {
		return nil, fmt.Errorf("unknown syscall %q", name)
	}
	if meta.Attrs.Disabled {
		return nil, fmt.Errorf("disabled syscall %q", name)
	}
	if meta.Attrs.NoGenerate {
		return nil, fmt.Errorf("non-generatable syscall %q", name)
	}
	if ct != nil && !ct.Generatable(meta.ID) {
		return nil, fmt.Errorf("syscall %q is not enabled", name)
	}
	return meta, nil
}
