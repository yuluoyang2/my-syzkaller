// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzer

import (
	"math/rand"

	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/prog"
)

// genDirectProgRequest generates a fresh program for one of the configured
// targets. The target call consumes resources produced by a related call, or
// has no companion when none is configured, and its arguments are mutated
// afterwards. Generation happens on every request rather than once at startup,
// so the fuzzer explores different programs instead of copies of a fixed
// sample: the related call, the calls generated for it and the random fill
// between them all differ.
func genDirectProgRequest(fuzzer *Fuzzer, rnd *rand.Rand) *queue.Request {
	targets := fuzzer.Config.DirectTargets
	if !fuzzer.Config.IsDirect || len(targets) == 0 {
		return nil
	}
	target := targets[rnd.Intn(len(targets))]
	related := ""
	if len(target.Related) > 0 {
		related = target.Related[rnd.Intn(len(target.Related))]
	}
	p, err := fuzzer.target.GenerateCallPair(rnd, fuzzer.ChoiceTable(), target.Target, related)
	if err != nil {
		// Config validation rejects bad names, so this means the syscall is not
		// generatable with the current choice table (e.g. it was excluded by
		// enabled_syscalls). Fall back to a random program for this request.
		fuzzer.Logf(0, "direct: %v", err)
		return nil
	}
	// The target call is last, so it is the call that matters.
	p.MutateCallArgOpts(rnd, len(p.Calls)-1, fuzzer.ChoiceTable(), 2,
		prog.MutateOpts{SkipResourceArgs: true, MutateArgCount: 2})
	return &queue.Request{
		Prog:     p,
		ExecOpts: setFlags(fuzzer.execFlags()),
		Stat:     fuzzer.statExecGenerate,
	}
}

// mutateOptsFor biases mutation toward the pair that makes the program
// directed. A program without a target call is mutated with the stock options:
// losing the target is not repaired by inserting a random one, that would
// silently replace the configured goal.
func (fuzzer *Fuzzer) mutateOptsFor(p *prog.Prog) prog.MutateOpts {
	if !fuzzer.Config.IsDirect {
		return prog.DefaultMutateOpts
	}
	target, companion := findPair(p, fuzzer.directNames)
	if target == nil {
		return prog.DefaultMutateOpts
	}
	opts := prog.DefaultMutateOpts
	opts.SpliceWeight = 10
	opts.MutateArgWeight = 200
	// Keep the arguments of the target call, drop the plumbing.
	opts.SkipResourceArgs = true
	opts.MutateArgCount = 2
	opts.TargetCall = target
	opts.CompanionCall = companion
	return opts
}

// findPair locates the target call of p and, if any, the call that produced a
// resource the target consumes.
//
// The target is matched by name, taking the deepest match, so a program is
// recognized no matter where the call sits or how the rest was built. The
// companion is then derived from the data dependency rather than from the
// configured related names: the argument mutation in ResourceType re-binds fd
// arguments, so after a few mutations the real producer may be a fill call
// instead of the syscall the program was generated with. Looking it up through
// ResultArg.Res always yields whatever the target uses right now.
func findPair(p *prog.Prog, names map[string]struct{}) (target, companion *prog.Call) {
	if len(names) == 0 {
		return nil, nil
	}
	for i := len(p.Calls) - 1; i >= 0; i-- {
		if _, ok := names[p.Calls[i].Meta.Name]; ok {
			target = p.Calls[i]
			break
		}
	}
	if target == nil {
		return nil, nil
	}
	producers := make(map[*prog.ResultArg]*prog.Call, len(p.Calls))
	for _, c := range p.Calls {
		if c.Ret != nil {
			producers[c.Ret] = c
		}
	}
	prog.ForeachArg(target, func(arg prog.Arg, _ *prog.ArgCtx) {
		res, ok := arg.(*prog.ResultArg)
		if companion != nil || !ok || res.Res == nil || res.Dir() == prog.DirOut {
			return
		}
		if c := producers[res.Res]; c != nil && c != target {
			companion = c
		}
	})
	return target, companion
}
