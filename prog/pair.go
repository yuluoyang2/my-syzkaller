// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import "fmt"

// producedResources returns the resources c produces (DirOut).
func producedResources(c *Call) []*ResultArg {
	if c == nil {
		return nil
	}
	var out []*ResultArg
	ForeachArg(c, func(arg Arg, _ *ArgCtx) {
		a, ok := arg.(*ResultArg)
		if !ok || a.Dir() == DirIn {
			return
		}
		if _, ok := a.Type().(*ResourceType); ok {
			out = append(out, a)
		}
	})
	return out
}

// callResources returns the resource descriptors meta consumes or produces.
func callResources(meta *Syscall, dir Dir) []*ResourceDesc {
	var out []*ResourceDesc
	seen := make(map[*ResourceDesc]bool)
	ForeachCallType(meta, func(t Type, ctx *TypeCtx) {
		res, ok := t.(*ResourceType)
		if !ok || ctx.Optional || ctx.Dir != dir || seen[res.Desc] {
			return
		}
		seen[res.Desc] = true
		out = append(out, res.Desc)
	})
	return out
}

// CheckCallPair reports whether related produces a resource that target
// consumes, that is, whether generating related before target can satisfy one
// of target's resource arguments.
func (target *Target) CheckCallPair(targetName, relatedName string) error {
	tmeta := target.SyscallMap[targetName]
	if tmeta == nil {
		return fmt.Errorf("unknown syscall %q", targetName)
	}
	rmeta := target.SyscallMap[relatedName]
	if rmeta == nil {
		return fmt.Errorf("unknown syscall %q", relatedName)
	}
	produced := callResources(rmeta, DirOut)
	for _, dst := range callResources(tmeta, DirIn) {
		for _, src := range produced {
			// Same precise matching as generation-time binding: a resource the
			// target can only use by broadening (e.g. socket accepting a plain
			// fd) is not a pair, since boundResource will refuse it.
			if isCompatibleResourceImpl(dst.Kind, src.Kind, true) {
				return nil
			}
		}
	}
	return fmt.Errorf("%q produces no resource consumed by %q", relatedName, targetName)
}
