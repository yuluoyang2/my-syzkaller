// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/vminfo"
)

type report struct {
	InputPCs     int              `json:"input_pcs"`
	MatchedPCs   int              `json:"matched_kernel_pcs"`
	UnmatchedPCs int              `json:"unmatched_pcs"`
	Target       functionReport   `json:"target"`
	CloseFuncs   []functionReport `json:"close_funcs"`
	FileReached  []reachedFunc    `json:"target_file_reached"`
	Warnings     []string         `json:"warnings,omitempty"`
}

type functionReport struct {
	Name        string       `json:"name"`
	File        string       `json:"file,omitempty"`
	Start       string       `json:"start_pc,omitempty"`
	State       string       `json:"state"` // resolved, ambiguous, or no_instrumented_symbol
	HitPCs      int          `json:"hit_pcs"`
	TotalPCs    int          `json:"total_pcs"`
	Lines       []sourceLine `json:"lines"`
	UnmappedPCs []string     `json:"unmapped_pcs,omitempty"`
}

type sourceLine struct {
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Source      string   `json:"source"`
	SourceFuncs []string `json:"source_funcs,omitempty"`
	Inline      bool     `json:"inline,omitempty"`
	Status      string   `json:"status"` // HIT, PARTIAL, MISS
	HitPCs      []string `json:"hit_pcs,omitempty"`
	MissPCs     []string `json:"miss_pcs,omitempty"`
}

type reachedFunc struct {
	Name   string `json:"name"`
	Start  string `json:"start_pc"`
	HitPCs int    `json:"hit_pcs"`
}

type lineKey struct {
	file string
	line int
}

type linePoints struct {
	pc     map[uint64]bool
	funcs  map[string]bool
	inline bool
	path   string
}

func hexPC(pc uint64) string {
	return fmt.Sprintf("0x%x", pc)
}

func analyze(spec targetSpec, observed map[uint64]bool, rg *cover.ReportGenerator, srcDir string) (*report, error) {
	if len(observed) == 0 {
		return nil, errors.New("coverage file has no PCs")
	}
	r := &report{
		InputPCs:    len(observed),
		CloseFuncs:  []functionReport{},
		FileReached: []reachedFunc{},
	}
	for pc := range observed {
		if _, found := slices.BinarySearch(rg.CallbackPoints, pc); found {
			r.MatchedPCs++
		}
	}
	r.UnmatchedPCs = r.InputPCs - r.MatchedPCs
	// Mismatched builds, KASLR addresses, or -raw input must not appear as
	// legitimate zero coverage. Module-only PCs cannot be resolved without VM
	// module addresses and also trigger this error if they dominate the input.
	if r.MatchedPCs*2 < r.InputPCs {
		return nil, fmt.Errorf("only %d/%d coverage PCs match vmlinux callbacks; check kernel build, KASLR, "+
			"-raw input and module-only coverage (modules are unsupported)", r.MatchedPCs, r.InputPCs)
	}
	if r.UnmatchedPCs != 0 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("%d input PCs do not match vmlinux callbacks (may include module PCs)",
			r.UnmatchedPCs))
	}

	var target []*backend.Symbol
	closeByName := make(map[string][]*backend.Symbol)
	closeNames := make(map[string]bool)
	for _, item := range spec.CloseFuncs {
		closeNames[item.Func] = true
	}
	for _, s := range rg.Symbols {
		if s.Module == nil || s.Module.Name != "" || s.Unit == nil {
			continue // only vmlinux; module addresses are unknown
		}
		if s.Name == spec.TargetFunc && s.Unit.Name == spec.Path {
			target = append(target, s)
		}
		if closeNames[s.Name] {
			closeByName[s.Name] = append(closeByName[s.Name], s)
		}
		if s.Unit.Name == spec.Path {
			hits := countHits(s.PCs, observed)
			if hits > 0 {
				r.FileReached = append(r.FileReached, reachedFunc{s.Name, hexPC(s.Start), hits})
			}
		}
	}
	if len(target) != 1 {
		return nil, fmt.Errorf("target %q in %q has %d KCOV-instrumented vmlinux symbols; "+
			"expected exactly one (this does not prove the function is absent from the source)",
			spec.TargetFunc, spec.Path, len(target))
	}
	slices.SortFunc(r.FileReached, func(a, b reachedFunc) int {
		if a.Name != b.Name {
			return strings.Compare(a.Name, b.Name)
		}
		return strings.Compare(a.Start, b.Start)
	})

	// Symbolize the full PC set of selected functions, not just the observed
	// subset. Clone the slice: the backend may rewrite the supplied PCs.
	selected := make(map[*backend.Symbol]bool)
	selected[target[0]] = true
	for _, syms := range closeByName {
		for _, s := range syms {
			selected[s] = true
		}
	}
	pcSet := make(map[*vminfo.KernelModule]map[uint64]bool)
	for s := range selected {
		if pcSet[s.Module] == nil {
			pcSet[s.Module] = make(map[uint64]bool)
		}
		for _, pc := range s.PCs {
			pcSet[s.Module][pc] = true
		}
	}
	toSymbolize := make(map[*vminfo.KernelModule][]uint64)
	for mod, pcs := range pcSet {
		for pc := range pcs {
			toSymbolize[mod] = append(toSymbolize[mod], pc)
		}
		slices.Sort(toSymbolize[mod])
	}
	frames, err := rg.Symbolize(toSymbolize)
	if err != nil {
		return nil, fmt.Errorf("symbolize selected callbacks: %w", err)
	}
	byPC := make(map[uint64][]*backend.Frame)
	for _, frame := range frames {
		if frame.StartLine > 0 && frame.Name != "" {
			byPC[frame.PC] = append(byPC[frame.PC], frame)
		}
	}
	sourceCache := make(map[string][]string)
	sourceWarnings := make(map[string]bool)
	build := func(s *backend.Symbol, state string) functionReport {
		f := functionReport{
			Name: s.Name, File: s.Unit.Name, Start: hexPC(s.Start), State: state,
			Lines: []sourceLine{},
		}
		points := make(map[lineKey]*linePoints)
		seen := make(map[uint64]bool)
		for _, pc := range s.PCs {
			if seen[pc] {
				continue
			}
			seen[pc] = true
			f.TotalPCs++
			if observed[pc] {
				f.HitPCs++
			}
			if len(byPC[pc]) == 0 {
				f.UnmappedPCs = append(f.UnmappedPCs, hexPC(pc))
			}
			for _, frame := range byPC[pc] {
				key := lineKey{frame.Name, frame.StartLine}
				p := points[key]
				if p == nil {
					p = &linePoints{pc: make(map[uint64]bool), funcs: make(map[string]bool), path: frame.Path}
					points[key] = p
				}
				p.pc[pc] = true
				if frame.FuncName != "" {
					p.funcs[frame.FuncName] = true
				}
				p.inline = p.inline || frame.Inline
			}
		}
		slices.Sort(f.UnmappedPCs)
		for key, p := range points {
			line := sourceLine{File: key.file, Line: key.line, Inline: p.inline,
				SourceFuncs: []string{}}
			for name := range p.funcs {
				line.SourceFuncs = append(line.SourceFuncs, name)
			}
			slices.Sort(line.SourceFuncs)
			for pc := range p.pc {
				if observed[pc] {
					line.HitPCs = append(line.HitPCs, hexPC(pc))
				} else {
					line.MissPCs = append(line.MissPCs, hexPC(pc))
				}
			}
			slices.Sort(line.HitPCs)
			slices.Sort(line.MissPCs)
			switch {
			case len(line.MissPCs) == 0:
				line.Status = "HIT"
			case len(line.HitPCs) == 0:
				line.Status = "MISS"
			default:
				line.Status = "PARTIAL"
			}
			source, ok := sourceCache[p.path]
			if !ok {
				data, err := os.ReadFile(p.path)
				if err != nil && filepath.IsLocal(key.file) {
					data, err = os.ReadFile(filepath.Join(srcDir, key.file))
				}
				if err != nil {
					if !sourceWarnings[p.path] {
						r.Warnings = append(r.Warnings, fmt.Sprintf("cannot read source %q: %v", p.path, err))
						sourceWarnings[p.path] = true
					}
				} else {
					source = strings.Split(string(data), "\n")
				}
				sourceCache[p.path] = source
			}
			if line.Line <= len(source) {
				line.Source = strings.TrimSuffix(source[line.Line-1], "\r")
			} else if len(source) > 0 && !sourceWarnings[p.path] {
				r.Warnings = append(r.Warnings, fmt.Sprintf("source %q has fewer than %d lines; check source build", p.path, line.Line))
				sourceWarnings[p.path] = true
			}
			f.Lines = append(f.Lines, line)
		}
		slices.SortFunc(f.Lines, func(a, b sourceLine) int {
			// Show the function's compilation unit before inline frames in headers.
			if (a.File == f.File) != (b.File == f.File) {
				if a.File == f.File {
					return -1
				}
				return 1
			}
			if a.File != b.File {
				return strings.Compare(a.File, b.File)
			}
			return a.Line - b.Line
		})
		return f
	}
	r.Target = build(target[0], "resolved")
	for _, item := range spec.CloseFuncs {
		candidates := closeByName[item.Func]
		slices.SortFunc(candidates, func(a, b *backend.Symbol) int {
			if a.Start != b.Start {
				if a.Start < b.Start {
					return -1
				}
				return 1
			}
			return strings.Compare(a.Unit.Name, b.Unit.Name)
		})
		if len(candidates) == 0 {
			r.CloseFuncs = append(r.CloseFuncs, functionReport{
				Name: item.Func, State: "no_instrumented_symbol", Lines: []sourceLine{},
			})
			continue
		}
		state := "resolved"
		if len(candidates) > 1 {
			state = "ambiguous"
		}
		for _, s := range candidates {
			r.CloseFuncs = append(r.CloseFuncs, build(s, state))
		}
	}
	if len(r.Target.UnmappedPCs) != 0 {
		r.Warnings = append(r.Warnings, fmt.Sprintf("%d target callbacks have no source location", len(r.Target.UnmappedPCs)))
	}
	slices.Sort(r.Warnings)
	return r, nil
}

func countHits(pcs []uint64, observed map[uint64]bool) int {
	hits := 0
	seen := make(map[uint64]bool)
	for _, pc := range pcs {
		if observed[pc] && !seen[pc] {
			hits++
			seen[pc] = true
		}
	}
	return hits
}

func writeText(w io.Writer, r *report) error {
	var b strings.Builder
	fmt.Fprintf(&b, "KCOV function coverage (observed union)\nPCs: %d input, %d matched vmlinux, %d unmatched\n",
		r.InputPCs, r.MatchedPCs, r.UnmatchedPCs)
	writeFunc := func(label string, f functionReport) {
		fmt.Fprintf(&b, "\n%s %s", label, f.Name)
		if f.File != "" {
			fmt.Fprintf(&b, " (%s, %s)", f.File, f.Start)
		}
		fmt.Fprintf(&b, " [%s] %d/%d PCs hit\n", f.State, f.HitPCs, f.TotalPCs)
		for _, line := range f.Lines {
			inline := ""
			if line.Inline {
				inline = " [inline: " + strings.Join(line.SourceFuncs, ", ") + "]"
			}
			fmt.Fprintf(&b, "  %-7s %s:%d  %s  (hit: %d, miss: %d)%s\n", line.Status,
				line.File, line.Line, strings.TrimSpace(line.Source), len(line.HitPCs), len(line.MissPCs), inline)
		}
		if len(f.UnmappedPCs) != 0 {
			fmt.Fprintf(&b, "  PCs without source line: %s\n", strings.Join(f.UnmappedPCs, ", "))
		}
	}
	writeFunc("TARGET", r.Target)
	for _, f := range r.CloseFuncs {
		writeFunc("CLOSE", f)
	}
	fmt.Fprintf(&b, "\nREACHED FUNCTIONS IN %s\n", r.Target.File)
	if len(r.FileReached) == 0 {
		b.WriteString("  none\n")
	}
	for _, f := range r.FileReached {
		fmt.Fprintf(&b, "  %s (%s): %d PCs hit\n", f.Name, f.Start, f.HitPCs)
	}
	if len(r.Warnings) != 0 {
		b.WriteString("\nWARNINGS\n")
		for _, warning := range r.Warnings {
			fmt.Fprintf(&b, "  %s\n", warning)
		}
	}
	b.WriteString("\nOnly lines with KCOV callbacks are listed; absent lines are not counted as uncovered. " +
		"A union shows whether a callback was ever hit, not its hit frequency.\n")
	_, err := io.WriteString(w, b.String())
	return err
}
