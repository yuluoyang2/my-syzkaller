// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
)

func TestDefaultCoverfile(t *testing.T) {
	const wantPath = "rm-verify/coverpcs.txt"
	if *flagCover != wantPath {
		t.Fatalf("default coverfile = %q, want %q", *flagCover, wantPath)
	}
	t.Chdir(t.TempDir())
	cfg := &mgrconfig.Config{}
	cfg.TargetOS, cfg.TargetArch, cfg.Type = "linux", "amd64", "qemu"
	store := newCoverStore(cfg)
	store.union[0x200] = struct{}{}
	store.union[0x100] = struct{}{}
	store.close()
	data, err := os.ReadFile(filepath.Join("rm-verify", "coverpcs.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != "0x100\n0x200\n" {
		t.Fatalf("wrong coverage file: %q", got)
	}
}
