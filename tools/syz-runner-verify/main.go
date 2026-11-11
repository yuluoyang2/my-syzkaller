// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-runner-verify is a throw-away verification tool for aflow.RunnerManager.
// It boots a real VM pool from a manager config and submits exactly the given
// programs, printing per-call coverage and any detected crash. No LLM involved.
//
// Coverage is collected as raw KCOV PCs and written out for external consumers
// (syz-cover, symbolizers, custom mapping scripts). This tool deliberately does
// not symbolize anything itself.
//
// With -fuzz the tool keeps the seed programs reachable at the target function
// and mutates around them: every program is executed -execs times, and a
// mutated program is kept only if it covers a target-function PC never seen
// before. Mutation continues from that candidate (with -resetprob of the draws
// going back to an original seed). Any crash ends the run: the program and the
// crash report are saved as the result.
//
// Everything the tool and the manager print is mirrored into <workdir>/run.log,
// so a long run leaves an artifact even if the terminal output is lost. Crash
// reports land there too instead of being saved as separate files.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	golog "log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

var (
	flagConfig   = flag.String("config", "direct.cfg", "manager config file")
	flagProg     = flag.String("prog", "", "syzlang program file to submit")
	flagProg2    = flag.String("prog2", "", "second program file (submitted as one batch with -prog)")
	flagSeedDir  = flag.String("seeddir", "", "directory of .syz seed programs for -fuzz")
	flagWorkdir  = flag.String("workdir", "workdir", "base dir for the temporary manager workdir (relative to the binary)")
	flagNoTime   = flag.Bool("no-timestamp", false, "reuse -workdir as-is instead of appending a timestamp")
	flagRepeat   = flag.Int("repeat", 1, "number of times to submit each program")
	flagBatch    = flag.Int("batch", 1, "submit this many concurrent copies per iteration")
	flagQuiet    = flag.Bool("quiet", false, "print only periodic progress lines")
	flagTimeout  = flag.Duration("timeout", 20*time.Minute, "overall run timeout")
	flagInterval = flag.Duration("interval", 0, "sleep between submissions")
	flagCrash    = flag.Duration("crash-wait", 0, "after submissions, poll for async crashes for this long")
	flagDebug    = flag.Bool("debug", false, "debug output from executor")
	flagCover    = flag.String("coverfile", "rm-verify/coverpcs.txt", "write the union of covered PCs to this file (one 0x-prefixed PC per line); empty disables file output")
	flagPerRun   = flag.String("coverdir", "", "write per-call coverage of every submission into this directory")
	flagRaw      = flag.Bool("raw", false, "write KCOV return addresses as-is instead of the call-site PC (no -5 adjustment)")
	flagLog      = flag.String("log", "run.log", "log file inside the workdir (relative paths are resolved against it); '-' keeps only terminal output")

	flagVMs        = flag.Int("vms", 6, "number of VMs in the pool")
	flagProcs      = flag.Int("procs", 2, "executor processes per VM")
	flagFuzz       = flag.Bool("fuzz", false, "enable directed mutation fuzzing")
	flagTarget     = flag.String("target", "target.json", "target function JSON for -fuzz")
	flagExecs      = flag.Int("execs", 500, "executions per program block in -fuzz mode")
	flagOutDir     = flag.String("outdir", "rm-verify/candidates", "candidate output directory for -fuzz")
	flagRandSeed   = flag.Int64("randseed", 0, "random seed for -fuzz (0 = time-based)")
	flagStructProb = flag.Float64("structprob", 0.1, "probability of a structural mutation instead of an argument mutation")
	flagResetProb  = flag.Float64("resetprob", 0.2, "probability of mutating an original seed instead of the current parent")
)

// wasSet reports whether the named flag was passed on the command line, so a
// mode-specific default can be applied without overriding an explicit value.
func wasSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// out receives everything the tool prints. setupLog points it at both the
// terminal and the run log, so a long run leaves a readable trail behind even
// when only the last few terminal lines survive.
var out io.Writer = os.Stdout

// logMu serializes writes into the log file. Two independent paths write into
// it (the tool through out, syzkaller's pkg/log through the standard logger,
// from rpcserver/execbackend goroutines), and without a shared lock their lines
// would interleave and the file would become unreadable.
var logMu sync.Mutex

type lockedWriter struct {
	w io.Writer
}

func (lw lockedWriter) Write(data []byte) (int, error) {
	logMu.Lock()
	defer logMu.Unlock()
	return lw.w.Write(data)
}

// setupLog opens the run log and mirrors all output into it.
//
// Both output paths have to be redirected: the tool itself prints through out,
// while syzkaller's pkg/log ends up in the standard library logger (it writes
// via log.Print), and that is what carries rpcserver, execbackend and reporter
// messages. The standard logger defaults to stderr, so it is redirected
// separately. Executor serial output is not affected: that is written by
// pkg/instance to its own file.
func setupLog(workdir string) (path string, closeLog func()) {
	path = *flagLog
	if path == "-" {
		return "", func() {}
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(workdir, path)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("failed to create log %v: %v", path, err)
	}
	out = lockedWriter{io.MultiWriter(os.Stdout, f)}
	golog.SetOutput(lockedWriter{io.MultiWriter(os.Stderr, f)})
	return path, func() {
		logMu.Lock()
		defer logMu.Unlock()
		f.Close()
	}
}

func main() {
	flag.Parse()
	if *flagProg == "" && !(*flagFuzz && *flagSeedDir != "") {
		log.Fatalf("usage: syz-runner-verify -config=direct.cfg -prog=prog.syz [-prog2=prog2.syz] [-repeat=N] " +
			"[-fuzz -target=target.json -execs=N [-seeddir=dir]]")
	}
	if *flagFuzz {
		if *flagExecs < 1 || *flagTarget == "" {
			log.Fatalf("-fuzz requires -target and a positive -execs")
		}
		if *flagStructProb < 0 || *flagStructProb > 1 || *flagResetProb < 0 || *flagResetProb > 1 {
			log.Fatalf("-structprob and -resetprob must be in [0, 1]")
		}
		if *flagRaw {
			// PC sets come from the kernel backend, which stores call-site
			// addresses; untranslated KCOV addresses would never match.
			log.Fatalf("-raw is not supported with -fuzz")
		}
		// A fuzz run is expected to last longer than a verification run, so the
		// short verification default does not apply unless it was set explicitly.
		if !wasSet("timeout") {
			*flagTimeout = time.Hour
		}
	}
	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		log.Fatalf("%v: %v", *flagConfig, err)
	}
	if *flagVMs < 1 {
		log.Fatalf("-vms must be positive")
	}
	if *flagProcs < 1 || *flagProcs > prog.MaxPids {
		log.Fatalf("-procs must be in [1, %v]", prog.MaxPids)
	}
	// Override the pool size from the config: verification and fuzz runs choose
	// their own VM count and executor process count.
	vmCfg := map[string]any{}
	if err := json.Unmarshal(cfg.VM, &vmCfg); err != nil {
		log.Fatalf("failed to parse vm config: %v", err)
	}
	vmCfg["count"] = *flagVMs
	if cfg.VM, err = json.Marshal(vmCfg); err != nil {
		log.Fatalf("failed to encode vm config: %v", err)
	}
	cfg.Procs = *flagProcs
	// Do not pollute the real workdir from the config.
	// Relative paths are resolved against the binary's directory, so that
	// the workdir always lands next to the tool regardless of the CWD.
	workdir := *flagWorkdir
	if !filepath.IsAbs(workdir) {
		exe, err := os.Executable()
		if err != nil {
			log.Fatalf("failed to resolve executable path: %v", err)
		}
		workdir = filepath.Join(filepath.Dir(exe), workdir)
	}
	workdir, err = filepath.Abs(workdir)
	if err != nil {
		log.Fatalf("failed to resolve workdir: %v", err)
	}
	if !*flagNoTime {
		workdir = fmt.Sprintf("%v_%v", workdir, time.Now().Format("20060102_150405"))
	}
	cfg.Workdir = workdir
	if err := os.MkdirAll(cfg.Workdir, 0755); err != nil {
		log.Fatalf("failed to create workdir: %v", err)
	}
	// The log lives inside the workdir, so it must be opened after it exists.
	logPath, closeLog := setupLog(cfg.Workdir)
	defer closeLog()
	fmt.Fprintf(out, "workdir: %v\n", cfg.Workdir)
	if logPath != "" {
		fmt.Fprintf(out, "log: %v\n", logPath)
	}

	target, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
	if err != nil {
		log.Fatalf("%v", err)
	}
	var progs []*prog.Prog
	if *flagProg != "" {
		progs = append(progs, loadProg(target, *flagProg))
	}
	if *flagProg2 != "" {
		progs = append(progs, loadProg(target, *flagProg2))
	}
	if *flagSeedDir != "" {
		files, err := filepath.Glob(filepath.Join(*flagSeedDir, "*.syz"))
		if err != nil {
			log.Fatalf("failed to list seed directory: %v", err)
		}
		slices.Sort(files)
		for _, file := range files {
			progs = append(progs, loadProg(target, file))
		}
	}
	if len(progs) == 0 {
		log.Fatalf("no seed programs given")
	}
	for i, p := range progs {
		fmt.Fprintf(out, "program #%v:\n%s\n", i, p.Serialize())
	}

	// Fuzz mode maintains its own union and writes it when it stops; the plain
	// cover store would otherwise overwrite that file with an empty set.
	var cov *coverStore
	if !*flagFuzz {
		cov = newCoverStore(cfg)
		defer cov.close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), *flagTimeout)
	defer cancel()
	start := time.Now()
	err = aflow.RunIsolatedManager(ctx, cfg, *flagDebug, log.Logf,
		func(ctx context.Context, rm *aflow.RunnerManager) error {
			fmt.Fprintf(out, "\n=== VM pool ready after %v\n", time.Since(start).Round(time.Millisecond))
			if *flagFuzz {
				return runFuzz(ctx, cfg, rm, target, progs)
			}
			for i := 0; i < *flagRepeat; i++ {
				batch := progs
				if *flagBatch > 1 {
					batch = nil
					for j := 0; j < *flagBatch; j++ {
						batch = append(batch, progs...)
					}
				}
				submit(ctx, rm, batch, i+1, *flagQuiet, cov)
				if len(rm.RecentCrashes()) > 0 {
					fmt.Fprintf(out, "stopping submissions: crash detected\n")
					break
				}
				if *flagInterval > 0 {
					time.Sleep(*flagInterval)
				}
			}
			if *flagCrash > 0 {
				fmt.Fprintf(out, "\n=== waiting %v for async crashes\n", *flagCrash)
				deadline := time.Now().Add(*flagCrash)
				for time.Now().Before(deadline) && len(rm.RecentCrashes()) == 0 {
					time.Sleep(time.Second)
				}
			}
			printCrashes(rm)
			return nil
		})
	if err != nil {
		log.Fatalf("RunIsolatedManager failed: %v", err)
	}
	fmt.Fprintf(out, "\ntotal wall time: %v\n", time.Since(start).Round(time.Millisecond))
}

func loadProg(target *prog.Target, file string) *prog.Prog {
	data, err := os.ReadFile(file)
	if err != nil {
		log.Fatalf("%v", err)
	}
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		log.Fatalf("failed to deserialize %v: %v", file, err)
	}
	return p
}

func submit(ctx context.Context, rm *aflow.RunnerManager, progs []*prog.Prog, iter int, quiet bool,
	cov *coverStore) {
	begin := time.Now()
	results, err := rm.SubmitBatch(ctx, progs)
	elapsed := time.Since(begin).Round(time.Millisecond)
	if err != nil {
		fmt.Fprintf(out, "=== submit #%v: error after %v: %v\n", iter, elapsed, err)
		return
	}
	cov.addRun(iter, results)
	if quiet {
		crashed := 0
		for _, res := range results {
			if res.Status != queue.Success {
				crashed++
			}
		}
		if crashed == 0 && iter%50 != 0 {
			return
		}
		fmt.Fprintf(out, "=== submit #%v: %v program(s) in %v, %v non-success\n",
			iter, len(results), elapsed, crashed)
		return
	}
	fmt.Fprintf(out, "=== submit #%v: %v program(s) in %v\n", iter, len(results), elapsed)
	for i, res := range results {
		if res.Info == nil {
			fmt.Fprintf(out, "  prog%v status=%v err=%v\n", i, res.Status, res.Err)
			continue
		}
		total := 0
		for j, inf := range res.Info.Calls {
			flags := ""
			if inf.Flags&flatrpc.CallFlagExecuted == 0 {
				flags = " (not executed)"
			}
			fmt.Fprintf(out, "  prog%v call %v: signal=%v cover=%v errno=%v%v\n",
				i, j, len(inf.Signal), len(inf.Cover), inf.Error, flags)
			total += len(inf.Cover)
		}
		extra := 0
		if res.Info.Extra != nil {
			extra = len(res.Info.Extra.Cover)
		}
		fmt.Fprintf(out, "  prog%v status=%v total_cover=%v extra_cover=%v\n", i, res.Status, total, extra)
		if len(res.Output) != 0 {
			fmt.Fprintf(out, "  prog%v output: %s\n", i, strings.TrimSpace(string(res.Output)))
		}
	}
}

// coverStore accumulates raw KCOV PCs across all submissions and writes them
// out for external consumers. It performs no symbolization: mapping PCs back to
// source is left to syz-cover / a separate mapping script.
//
// Output formats are compatible with the rest of the toolchain:
//   - -coverfile  one 0x-prefixed PC per line, as syz-cover's readPCs expects;
//   - -coverdir   one file per (run, prog, call), same line format.
type coverStore struct {
	cfg      *mgrconfig.Config
	sysTgt   *targets.Target
	union    map[uint64]struct{}
	coverDir string
	// raw keeps KCOV return addresses verbatim. By default PCs are adjusted to
	// the call-site instruction (amd64: pc-5), which is what addr2line wants.
	raw bool
}

func newCoverStore(cfg *mgrconfig.Config) *coverStore {
	if *flagCover == "" && *flagPerRun == "" {
		return &coverStore{}
	}
	if *flagPerRun != "" {
		if err := os.MkdirAll(*flagPerRun, 0755); err != nil {
			log.Fatalf("failed to create coverdir: %v", err)
		}
	}
	if *flagCover != "" {
		if err := os.MkdirAll(filepath.Dir(*flagCover), 0755); err != nil {
			log.Fatalf("failed to create coverfile directory: %v", err)
		}
	}
	return &coverStore{
		cfg:      cfg,
		sysTgt:   targets.Get(cfg.TargetOS, cfg.TargetArch),
		union:    make(map[uint64]struct{}),
		coverDir: *flagPerRun,
		raw:      *flagRaw,
	}
}

// addRun records the coverage of one submission, attributing every PC to the
// (program, call) pair that produced it.
func (cs *coverStore) addRun(iter int, results []*queue.Result) {
	if cs.union == nil {
		return
	}
	for i, res := range results {
		if res == nil || res.Info == nil {
			continue
		}
		write := func(callIdx int, suffix string, cover []uint64) {
			if len(cover) == 0 {
				return
			}
			pcs := cs.translate(cover)
			for _, pc := range pcs {
				cs.union[pc] = struct{}{}
			}
			if cs.coverDir != "" {
				name := filepath.Join(cs.coverDir,
					fmt.Sprintf("run%v_prog%v.%v%v", iter, i, callIdx, suffix))
				if err := cs.writePCs(name, pcs); err != nil {
					log.Logf(0, "failed to write %v: %v", name, err)
				}
			}
		}
		for j, inf := range res.Info.Calls {
			write(j, "", inf.Cover)
		}
		if res.Info.Extra != nil {
			write(len(res.Info.Calls), ".extra", res.Info.Extra.Cover)
		}
	}
}

// translate converts KCOV return addresses into the PC that external consumers
// expect. Unless -raw is given, this is the previous instruction: on amd64 KCOV
// records the address right after the call, and addr2line/syz-cover want the
// call site itself.
func (cs *coverStore) translate(cover []uint64) []uint64 {
	if cs.raw {
		return slices.Clone(cover)
	}
	return backend.PreviousInstructionPCs(cs.sysTgt, cs.cfg.Type, cover)
}

func (cs *coverStore) writePCs(name string, pcs []uint64) error {
	var buf strings.Builder
	for _, pc := range pcs {
		fmt.Fprintf(&buf, "0x%x\n", pc)
	}
	return os.WriteFile(name, []byte(buf.String()), 0644)
}

// close flushes the accumulated union of covered PCs to -coverfile.
func (cs *coverStore) close() {
	if cs.union == nil {
		return
	}
	pcs := make([]uint64, 0, len(cs.union))
	for pc := range cs.union {
		pcs = append(pcs, pc)
	}
	slices.Sort(pcs)
	if *flagCover != "" {
		if err := cs.writePCs(*flagCover, pcs); err != nil {
			log.Fatalf("failed to write coverfile %v: %v", *flagCover, err)
		}
		fmt.Fprintf(out, "\n=== wrote %v unique PCs to %v\n", len(pcs), *flagCover)
	} else {
		fmt.Fprintf(out, "\n=== collected %v unique PCs (no -coverfile given, not persisted)\n", len(pcs))
	}
}

// printCrashes writes every detected crash into the run log. Reports are not
// saved to separate files on purpose: this tool is a verification harness, and
// the log is the artifact worth keeping. The report is truncated only to keep
// the log readable, never the title.
func printCrashes(rm *aflow.RunnerManager) {
	crashes := rm.RecentCrashes()
	fmt.Fprintf(out, "\n=== crashes detected: %v\n", len(crashes))
	for _, rep := range crashes {
		fmt.Fprintf(out, "--- title: %v\n", rep.Title)
		lines := strings.Split(string(rep.Report), "\n")
		if len(lines) > 200 {
			lines = lines[:200]
		}
		fmt.Fprintf(out, "%s\n", strings.Join(lines, "\n"))
	}
}
