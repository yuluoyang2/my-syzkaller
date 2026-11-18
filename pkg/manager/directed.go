// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
)

// PrepareDirectedCoverage reuses coverage symbolization, but deliberately does
// not use CoverageFilter: that helper also includes comparison callbacks and
// may install a signal filter. K denominators contain trace-PC points only.
func PrepareDirectedCoverage(source *ReportGeneratorWrapper, cfg *mgrconfig.Config) (
	*corpus.DirectedCoverage, string, error) {
	if cfg.Directed == nil {
		return nil, "", nil
	}
	rg, err := source.Get()
	if err != nil {
		return nil, "", err
	}
	goal := cfg.Directed.Target
	functions := func(name string) ([]uint64, error) {
		var pcs []uint64
		for _, sym := range rg.Symbols {
			if sym.Name == name {
				pcs = append(pcs, sym.PCs...)
			}
		}
		if len(pcs) == 0 {
			return nil, fmt.Errorf("directed function %q has no observable KCOV PCs", name)
		}
		return pcs, nil
	}
	target, err := functions(goal.Func)
	if err != nil {
		return nil, "", err
	}
	var closePCs, filePCs, subsystemPCs []uint64
	for _, name := range goal.CloseFuncs {
		pcs, err := functions(name)
		if err != nil {
			return nil, "", err
		}
		closePCs = append(closePCs, pcs...)
	}
	clean := func(path string) string {
		return strings.TrimPrefix(filepath.ToSlash(filepath.Clean(path)), "./")
	}
	for _, unit := range rg.Units {
		name := clean(unit.Name)
		if goal.Path != "" && name == clean(goal.Path) {
			filePCs = append(filePCs, unit.PCs...)
		}
		if goal.Subsystem != "" && strings.HasPrefix(name, strings.TrimSuffix(clean(goal.Subsystem), "/")+"/") {
			subsystemPCs = append(subsystemPCs, unit.PCs...)
		}
	}
	if goal.Path != "" && len(filePCs) == 0 {
		return nil, "", fmt.Errorf("directed file %q has no observable KCOV PCs", goal.Path)
	}
	if goal.Subsystem != "" && len(subsystemPCs) == 0 {
		return nil, "", fmt.Errorf("directed subsystem %q has no observable KCOV PCs", goal.Subsystem)
	}
	regions := [][]uint64{target, closePCs, filePCs, subsystemPCs}
	for i, pcs := range regions {
		for j, pc := range pcs {
			pcs[j] = backend.NextInstructionPC(cfg.SysTarget, cfg.Type, pc)
		}
		slices.Sort(pcs)
		regions[i] = slices.Compact(pcs)
	}
	// Build/config/address identity prevents using a previous kernel or a
	// different module layout as the gain baseline after restart.
	h := sha256.New()
	config, err := json.Marshal(cfg.Directed)
	if err != nil {
		return nil, "", err
	}
	fmt.Fprintf(h, "%s\n%s\n%v\n", cfg.RawTarget, config, regions)
	object, err := os.Open(filepath.Join(cfg.KernelObj, cfg.SysTarget.KernelObject))
	if err != nil {
		return nil, "", err
	}
	_, copyErr := io.Copy(h, object)
	closeErr := object.Close()
	if copyErr != nil {
		return nil, "", copyErr
	}
	if closeErr != nil {
		return nil, "", closeErr
	}
	return corpus.NewDirectedCoverage(regions[0], regions[1], regions[2], regions[3]),
		hex.EncodeToString(h.Sum(nil)), nil
}

type directedGainState struct {
	Version int      `json:"version"`
	Build   string   `json:"build"`
	PCs     []uint64 `json:"gain_seen_pcs"`
}

func LoadDirectedGainState(filename, build string) ([]uint64, error) {
	state, err := osutil.ReadJSON[directedGainState](filename)
	if err != nil {
		return nil, err
	}
	if state.Version != 1 || state.Build != build {
		return nil, fmt.Errorf("directed gain history belongs to a different build or format")
	}
	return state.PCs, nil
}

func SaveDirectedGainState(filename, build string, pcs []uint64) error {
	slices.Sort(pcs)
	data, err := json.Marshal(directedGainState{Version: 1, Build: build, PCs: slices.Compact(pcs)})
	if err != nil {
		return err
	}
	return osutil.WriteFileAtomically(filename, data)
}
