// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/vminfo"
)

func TestAnalyze(t *testing.T) {
	src := t.TempDir()
	path := "net/xfrm/xfrm_state.c"
	file := filepath.Join(src, path)
	if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("first\npartial\ncovered\nmissed\nreached\n"), 0644); err != nil {
		t.Fatal(err)
	}
	header := filepath.Join(src, "include/linux/xfrm.h")
	if err := os.MkdirAll(filepath.Dir(header), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(header, []byte("inline code\n"), 0644); err != nil {
		t.Fatal(err)
	}
	mod := &vminfo.KernelModule{Path: "vmlinux"}
	unit := &backend.CompileUnit{ObjectUnit: backend.ObjectUnit{Name: path}, Module: mod}
	sym := func(name string, start uint64, pcs []uint64, u *backend.CompileUnit) *backend.Symbol {
		return &backend.Symbol{
			ObjectUnit: backend.ObjectUnit{Name: name, PCs: pcs}, Start: start,
			Module: mod, Unit: u,
		}
	}
	target := sym("target", 0x100, []uint64{0x100, 0x105, 0x10a, 0x10f}, unit)
	close1 := sym("near", 0x200, []uint64{0x200}, unit)
	close2 := sym("near", 0x300, []uint64{0x300}, &backend.CompileUnit{ObjectUnit: backend.ObjectUnit{
		Name: "other.c"}, Module: mod})
	outside := sym("outside", 0x400, []uint64{0x400}, unit)
	selectedPCs := []uint64{0x100, 0x105, 0x10a, 0x10f, 0x200, 0x300}
	rg := &cover.ReportGenerator{Impl: &backend.Impl{
		Symbols:        []*backend.Symbol{target, close1, close2, outside},
		CallbackPoints: []uint64{0x100, 0x105, 0x10a, 0x10f, 0x200, 0x300, 0x400},
		Symbolize: func(input map[*vminfo.KernelModule][]uint64) ([]*backend.Frame, error) {
			if !reflect.DeepEqual(input[mod], selectedPCs) || len(input) != 1 {
				t.Errorf("symbolized unexpected PCs: %v", input)
			}
			// The backend is allowed to modify the input; the symbol callback sets
			// must remain unchanged in the report.
			input[mod][0] = 0xdeadbeef
			return []*backend.Frame{
				{PC: 0x100, Name: path, Path: file, FuncName: "target", Range: backend.Range{StartLine: 2}},
				{PC: 0x105, Name: path, Path: file, FuncName: "target", Range: backend.Range{StartLine: 2}},
				{PC: 0x10a, Name: path, Path: file, FuncName: "target", Range: backend.Range{StartLine: 3}},
				{PC: 0x10a, Name: "include/linux/xfrm.h", Path: header, FuncName: "inline_fn",
					Inline: true, Range: backend.Range{StartLine: 1}},
				{PC: 0x10f, Name: path, Path: file, FuncName: "target", Range: backend.Range{StartLine: 4}},
				{PC: 0x200, Name: path, Path: file, FuncName: "near", Range: backend.Range{StartLine: 5}},
				{PC: 0x300, Name: "other.c", Path: filepath.Join(src, "other.c"),
					FuncName: "near", Range: backend.Range{StartLine: 1}},
			}, nil
		},
	}}
	spec := targetSpec{TargetFunc: "target", Path: path}
	spec.CloseFuncs = []closeFuncSpec{{Func: "near"}, {Func: "absent"}}
	r, err := analyze(spec, map[uint64]bool{0x100: true, 0x10a: true, 0x400: true}, rg, src)
	if err != nil {
		t.Fatal(err)
	}
	if r.InputPCs != 3 || r.MatchedPCs != 3 || r.UnmatchedPCs != 0 ||
		r.Target.TotalPCs != 4 || r.Target.HitPCs != 2 || !slices.Equal(target.PCs,
		[]uint64{0x100, 0x105, 0x10a, 0x10f}) {
		t.Fatalf("bad target PC accounting: %+v (original PCs: %v)", r, target.PCs)
	}
	want := map[string]string{path + ":2": "PARTIAL", path + ":3": "HIT", path + ":4": "MISS",
		"include/linux/xfrm.h:1": "HIT"}
	if len(r.Target.Lines) != len(want) {
		t.Fatalf("wrong number of lines: %+v", r.Target.Lines)
	}
	for _, line := range r.Target.Lines {
		key := line.File + ":" + strconv.Itoa(line.Line)
		if want[key] != line.Status {
			t.Errorf("line %s: got %s, want %s", key, line.Status, want[key])
		}
		if key == path+":2" && (line.Source != "partial" || len(line.HitPCs) != 1 || len(line.MissPCs) != 1) {
			t.Errorf("bad partial line: %+v", line)
		}
		if key == "include/linux/xfrm.h:1" && (!line.Inline || !slices.Contains(line.SourceFuncs, "inline_fn")) {
			t.Errorf("inline frame missing: %+v", line)
		}
	}
	if len(r.CloseFuncs) != 3 || r.CloseFuncs[0].State != "ambiguous" ||
		r.CloseFuncs[1].State != "ambiguous" || r.CloseFuncs[2].State != "no_instrumented_symbol" ||
		r.CloseFuncs[2].TotalPCs != 0 {
		t.Fatalf("close candidates not reported separately: %+v", r.CloseFuncs)
	}
	if len(r.FileReached) != 2 || r.FileReached[0].Name != "outside" ||
		r.FileReached[1].Name != "target" {
		t.Fatalf("file reached should include only observed symbols: %+v", r.FileReached)
	}
	var out bytes.Buffer
	if err := writeText(&out, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "PARTIAL") || !strings.Contains(out.String(), "MISS") ||
		!strings.Contains(out.String(), "REACHED FUNCTIONS") || !strings.Contains(out.String(), "[ambiguous]") ||
		!strings.Contains(out.String(), "[inline: inline_fn]") {
		t.Errorf("missing text report fields:\n%s", out.String())
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"start_pc":"0x100"`)) ||
		!bytes.Contains(data, []byte(`"hit_pcs":["0x100"]`)) {
		t.Errorf("JSON lost PC precision or lines: %s", data)
	}
}

func TestAnalyzeMismatchedBuild(t *testing.T) {
	rg := &cover.ReportGenerator{Impl: &backend.Impl{CallbackPoints: []uint64{0x100}}}
	spec := targetSpec{TargetFunc: "target", Path: "net/xfrm/xfrm_state.c"}
	observed := map[uint64]bool{0x100: true}
	for pc := uint64(0x200); pc < 0x220; pc++ {
		observed[pc] = true
	}
	_, err := analyze(spec, observed, rg, "")
	if err == nil || !strings.Contains(err.Error(), "match vmlinux callbacks") {
		t.Fatalf("expected build mismatch, got %v", err)
	}
}

func TestAnalyzeNoInstrumentedTarget(t *testing.T) {
	mod := &vminfo.KernelModule{Path: "vmlinux"}
	rg := &cover.ReportGenerator{Impl: &backend.Impl{
		CallbackPoints: []uint64{0x100},
		Symbols: []*backend.Symbol{{
			ObjectUnit: backend.ObjectUnit{Name: "target", PCs: []uint64{0x100}},
			Unit:       &backend.CompileUnit{ObjectUnit: backend.ObjectUnit{Name: "other.c"}}, Module: mod,
		}},
	}}
	_, err := analyze(targetSpec{TargetFunc: "target", Path: "net/xfrm/xfrm_state.c"},
		map[uint64]bool{0x100: true}, rg, "")
	if err == nil || !strings.Contains(err.Error(), "0 KCOV-instrumented vmlinux symbols") {
		t.Fatalf("expected unresolved target error, got %v", err)
	}
}

func TestReadInputs(t *testing.T) {
	src := t.TempDir()
	path := filepath.Join(src, "target.json")
	if err := os.WriteFile(path, []byte(`{"target_func":" t ","path":"net/xfrm/../xfrm/xfrm_state.c",`+
		`"close_funcs":[{"func":" n "}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	spec, err := readTarget(path)
	if err != nil || spec.TargetFunc != "t" || spec.Path != "net/xfrm/xfrm_state.c" ||
		spec.CloseFuncs[0].Func != "n" {
		t.Fatalf("target parsing: %+v, %v", spec, err)
	}
	pcs, err := readPCs(strings.NewReader("0x100\n0x100\n0x105\n"))
	if err != nil || len(pcs) != 2 || !pcs[0x105] {
		t.Fatalf("PC parsing: %v, %v", pcs, err)
	}
	if _, err := readPCs(strings.NewReader("not-a-pc")); err == nil {
		t.Fatal("expected invalid PC error")
	}
	if _, err := readPCs(strings.NewReader("\n")); err == nil {
		t.Fatal("expected empty PC error")
	}
}
