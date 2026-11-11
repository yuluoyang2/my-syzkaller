// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-direct-cover maps coverage from syz-runner-verify to a small set of kernel functions.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/vminfo"
)

type targetSpec struct {
	TargetFunc string          `json:"target_func"`
	Path       string          `json:"path"`
	CloseFuncs []closeFuncSpec `json:"close_funcs"`
}

type closeFuncSpec struct {
	Func string `json:"func"`
}

func main() {
	configFile := flag.String("config", "direct.cfg", "manager config (only kernel build and source are used)")
	targetFile := flag.String("target", "target.json", "target function and close functions JSON")
	coverFile := flag.String("coverfile", "rm-verify/coverpcs.txt", "call-site PCs from syz-runner-verify -coverfile")
	format := flag.String("format", "txt", "report format: txt or json")
	output := flag.String("output", "", "report destination (default stdout)")
	flag.Parse()
	if *coverFile == "" || (*format != "txt" && *format != "json") {
		fmt.Fprintln(os.Stderr, "usage: syz-direct-cover [-config=direct.cfg] [-target=target.json] [-coverfile=rm-verify/coverpcs.txt] [-format=txt|json] [-output=file]")
		os.Exit(2)
	}
	if err := run(*configFile, *targetFile, *coverFile, *format, *output); err != nil {
		fmt.Fprintln(os.Stderr, "syz-direct-cover:", err)
		os.Exit(1)
	}
}

func run(configFile, targetFile, coverFile, format, output string) error {
	spec, err := readTarget(targetFile)
	if err != nil {
		return err
	}
	input, err := os.Open(coverFile)
	if err != nil {
		return fmt.Errorf("open coverage file: %w", err)
	}
	pcs, err := readPCs(input)
	input.Close()
	if err != nil {
		return fmt.Errorf("read coverage file: %w", err)
	}
	cfg, err := mgrconfig.LoadFile(configFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if cfg.TargetOS != "linux" || cfg.TargetArch != "amd64" {
		return fmt.Errorf("only linux/amd64 is supported, got %s/%s", cfg.TargetOS, cfg.TargetArch)
	}
	// VM module load addresses are not recorded by syz-runner-verify. Do not
	// scan or symbolize .ko files against guessed addresses: vmlinux only.
	modules := []*vminfo.KernelModule{{Path: filepath.Join(cfg.KernelObj, cfg.SysTarget.KernelObject)}}
	rg, err := cover.MakeReportGenerator(cfg, modules)
	if err != nil {
		return fmt.Errorf("load vmlinux coverage: %w", err)
	}
	report, err := analyze(spec, pcs, rg, cfg.KernelSrc)
	if err != nil {
		return err
	}
	var w io.Writer = os.Stdout
	var file *os.File
	if output != "" {
		// Never truncate an existing report or an accidentally supplied input file.
		file, err = os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			return fmt.Errorf("create report (output must not exist): %w", err)
		}
		w = file
	}
	var writeErr error
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		writeErr = enc.Encode(report)
	} else {
		writeErr = writeText(w, report)
	}
	if file != nil {
		closeErr := file.Close()
		if writeErr == nil {
			writeErr = closeErr
		}
	}
	return writeErr
}

func readTarget(file string) (targetSpec, error) {
	var spec targetSpec
	data, err := os.ReadFile(file)
	if err != nil {
		return spec, fmt.Errorf("read target JSON: %w", err)
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		return spec, fmt.Errorf("parse target JSON: %w", err)
	}
	spec.TargetFunc = strings.TrimSpace(spec.TargetFunc)
	spec.Path = filepath.ToSlash(filepath.Clean(spec.Path))
	if spec.TargetFunc == "" || spec.Path == "." || filepath.IsAbs(spec.Path) ||
		spec.Path == ".." || strings.HasPrefix(spec.Path, "../") {
		return spec, errors.New("target_func and a relative kernel source path are required")
	}
	for i := range spec.CloseFuncs {
		spec.CloseFuncs[i].Func = strings.TrimSpace(spec.CloseFuncs[i].Func)
		if spec.CloseFuncs[i].Func == "" {
			return spec, fmt.Errorf("close_funcs[%d].func is empty", i)
		}
	}
	return spec, nil
}

func readPCs(r io.Reader) (map[uint64]bool, error) {
	pcs := make(map[uint64]bool)
	s := bufio.NewScanner(r)
	for line := 1; s.Scan(); line++ {
		str := strings.TrimSpace(s.Text())
		if str == "" {
			continue
		}
		pc, err := strconv.ParseUint(str, 0, 64)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		pcs[pc] = true
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(pcs) == 0 {
		return nil, errors.New("coverage file has no PCs")
	}
	return pcs, nil
}
