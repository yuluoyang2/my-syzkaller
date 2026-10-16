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

// GenerateSequence builds one program by generating the named syscalls in order.
// Resource-producing calls are inserted when a named syscall needs a resource
// that the sequence has not created yet.
func (target *Target) GenerateSequence(rs rand.Source, ct *ChoiceTable, names []string) (*Prog, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("empty syscall chain")
	}
	p := &Prog{
		Target: target,
	}
	r := newRand(target, rs)
	s := newState(target, ct, nil)
	for _, name := range names {
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
		calls := r.generateParticularCall(s, meta)
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
		if len(p.Calls) > MaxCalls {
			return nil, fmt.Errorf("syscall chain expanded to %d calls (max %d)",
				len(p.Calls), MaxCalls)
		}
	}
	if len(p.Calls) == 0 {
		return nil, fmt.Errorf("generated empty program")
	}
	p.sanitizeFix()
	p.debugValidate()
	return p, nil
}

// AppendGeneratedCalls adds up to n new calls after the existing ones.
// New calls can use resources the program already produces.
func (p *Prog) AppendGeneratedCalls(rs rand.Source, n int, ct *ChoiceTable) {
	if n <= 0 || len(p.Calls) == 0 {
		return
	}
	limit := min(RecommendedCalls, MaxCalls)
	r := newRand(p.Target, rs)
	s := analyze(ct, nil, p, nil)
	for added := 0; added < n && len(p.Calls) < limit; added++ {
		calls := r.generateCall(s, p, len(p.Calls))
		if len(calls) == 0 {
			break
		}
		for _, c := range calls {
			s.analyze(c)
			p.Calls = append(p.Calls, c)
		}
		// Like Generate, keep the selected final call but discard excess resource
		// constructors from the generated batch.
		for len(p.Calls) > limit {
			p.RemoveCall(limit - 1)
		}
	}
	p.sanitizeFix()
	p.debugValidate()
}

// Prefix returns a copy that keeps calls 0..call inclusive.
func (p *Prog) Prefix(call int) *Prog {
	cp := p.Clone()
	if call < 0 {
		call = 0
	}
	for len(cp.Calls) > call+1 {
		cp.RemoveCall(len(cp.Calls) - 1)
	}
	cp.sanitizeFix()
	cp.debugValidate()
	return cp
}
