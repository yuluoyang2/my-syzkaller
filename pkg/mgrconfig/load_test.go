// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkdirTimestamp(t *testing.T) {
	data, err := os.ReadFile("testdata/qemu.cfg")
	require.NoError(t, err)
	data = []byte(strings.Replace(string(data), "/syzkaller/workdir",
		"/syzkaller/workdir_{{TIMESTAMP}}", 1))

	cfg, err := LoadData(data)
	require.NoError(t, err)
	require.Regexp(t, `^/syzkaller/workdir_\d{8}_\d{6}\.\d{9}$`, cfg.Workdir)
}

func TestParseEnabledSyscalls(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)

	tests := []struct {
		name   string
		mode   DescriptionsMode
		enable []string
		// TODO: add disable tests as well.
		expectEnabled  []string
		expectDisabled []string
	}{
		{
			name:           "wildcard, no snapshot",
			mode:           ManualDescriptions,
			enable:         []string{"test"},
			expectDisabled: []string{"test$snapshot_only"},
		},
		{
			name:          "wildcard, snapshot",
			mode:          ManualDescriptions | SnapshotDescriptions,
			enable:        []string{"test"},
			expectEnabled: []string{"test$snapshot_only"},
		},
		{
			name:          "no wildcard, no snapshot",
			mode:          ManualDescriptions,
			enable:        []string{"test$snapshot_only"},
			expectEnabled: []string{"test$snapshot_only"},
		},
		{
			name:          "no wildcard, snapshot",
			mode:          ManualDescriptions | SnapshotDescriptions,
			enable:        []string{"test$snapshot_only"},
			expectEnabled: []string{"test$snapshot_only"},
		},
		{
			name:   "automatic allowed",
			mode:   ManualDescriptions | AutoDescriptions,
			enable: []string{"test"},
			expectEnabled: []string{
				"test$automatic",
				"test$automatic_helper",
				"test$manual",
			},
		},
		{
			name:   "manual only",
			mode:   ManualDescriptions,
			enable: []string{"test"},
			expectEnabled: []string{
				"test$automatic_helper",
				"test$manual",
			},
			expectDisabled: []string{
				"test$automatic",
			},
		},
		{
			name:   "auto only",
			mode:   AutoDescriptions,
			enable: []string{"test"},
			expectEnabled: []string{
				"test$automatic",
				"test$automatic_helper",
			},
			expectDisabled: []string{
				"test$manual",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ids, err := ParseEnabledSyscalls(target, test.enable,
				nil, test.mode)
			require.NoError(t, err)
			for _, enabled := range test.expectEnabled {
				assert.Contains(t, ids, target.SyscallMap[enabled].ID)
			}
			for _, disabled := range test.expectDisabled {
				assert.NotContains(t, ids, target.SyscallMap[disabled].ID)
			}
		})
	}
}

func TestCompleteDescriptionsMode(t *testing.T) {
	data := []byte(`{
		"target": "linux/amd64",
		"type": "none",
		"workdir": "/tmp",
		"syzkaller": "testdata/syzkaller",
		"experimental": {
			"descriptions_mode": "invalid"
		}
	}`)
	_, err := LoadData(data)
	require.Error(t, err)
	require.Contains(t, err.Error(), `invalid descriptions_mode "invalid", must be one of: any, auto, manual`)
}

func TestCompleteDirectTargets(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)
	var enabledIDs []int
	for _, meta := range target.SyscallMap {
		enabledIDs = append(enabledIDs, meta.ID)
	}
	const (
		targetCall  = "ioctl$sock_netrom_SIOCADDRT"
		relatedCall = "syz_init_net_socket$netrom"
	)
	tests := []struct {
		name     string
		isDirect bool
		targets  []DirectTarget
		err      string
	}{
		{name: "none"},
		{
			name: "valid", isDirect: true,
			targets: []DirectTarget{{Target: targetCall, Related: []string{relatedCall}}},
		},
		{
			// A target with no resource dependency, e.g. a pseudo-syscall that
			// needs no fd, is valid with an empty related list.
			name: "no related", isDirect: true,
			targets: []DirectTarget{{Target: "syz_emit_vhci"}},
		},
		{
			name: "direct without targets", isDirect: true,
			err: "isDirect is set, but directTargets is empty",
		},
		{
			name:    "targets without direct",
			targets: []DirectTarget{{Target: targetCall}},
			err:     "directTargets is set, but isDirect is not",
		},
		{
			name: "empty target", isDirect: true,
			targets: []DirectTarget{{}},
			err:     "directTargets[0]: empty target",
		},
		{
			name: "unknown target", isDirect: true,
			targets: []DirectTarget{{Target: "not_a_syscall"}},
			err:     `directTargets[0]: unknown syscall "not_a_syscall"`,
		},
		{
			name: "duplicate target", isDirect: true,
			targets: []DirectTarget{{Target: targetCall}, {Target: targetCall}},
			err:     fmt.Sprintf("duplicate direct target %q", targetCall),
		},
		{
			name: "unknown related", isDirect: true,
			targets: []DirectTarget{{Target: targetCall, Related: []string{"not_a_syscall"}}},
			err:     `directTargets[0]: unknown related syscall "not_a_syscall"`,
		},
		{
			name: "empty related", isDirect: true,
			targets: []DirectTarget{{Target: targetCall, Related: []string{""}}},
			err:     "directTargets[0]: empty related syscall",
		},
		{
			name: "reversed pair", isDirect: true,
			targets: []DirectTarget{{Target: relatedCall, Related: []string{targetCall}}},
			err:     fmt.Sprintf("%q produces no resource consumed by %q", targetCall, relatedCall),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := &Config{
				Derived: Derived{
					Target:   target,
					Syscalls: enabledIDs,
				},
				IsDirect:      test.isDirect,
				DirectTargets: test.targets,
			}
			err := cfg.completeDirectTargets()
			if test.err == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), test.err)
		})
	}
}

func TestCompleteDirectTargetsNotEnabled(t *testing.T) {
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)
	const (
		targetCall  = "ioctl$sock_netrom_SIOCADDRT"
		relatedCall = "syz_init_net_socket$netrom"
	)
	// Only the target is enabled, so the related call cannot be generated.
	cfg := &Config{
		Derived: Derived{
			Target:   target,
			Syscalls: []int{target.SyscallMap[targetCall].ID},
		},
		IsDirect: true,
		DirectTargets: []DirectTarget{{
			Target:  targetCall,
			Related: []string{relatedCall},
		}},
	}
	err = cfg.completeDirectTargets()
	require.Error(t, err)
	require.Contains(t, err.Error(), `related syscall "syz_init_net_socket$netrom" is not enabled`)
}

func TestFormatTarget(t *testing.T) {
	tests := []struct {
		os     string
		vmArch string
		arch   string
		want   string
	}{
		{targets.Linux, "amd64", "amd64", "linux/amd64"},
		{targets.Linux, "", "amd64", "linux/amd64"},
		{targets.Linux, "amd64", "386", "linux/amd64/386"},
		{targets.Linux, "arm64", "arm", "linux/arm64/arm"},
	}
	for _, tc := range tests {
		got := FormatTarget(tc.os, tc.vmArch, tc.arch)
		require.Equal(t, tc.want, got)
	}
}
