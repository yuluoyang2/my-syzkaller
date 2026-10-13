// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vmimpl

import "testing"

func TestOpenSSHMajor(t *testing.T) {
	tests := []struct {
		version string
		major   int
	}{
		{"OpenSSH_8.2p1 Ubuntu-4ubuntu0.13, OpenSSL 1.1.1f  31 Mar 2020", 8},
		{"OpenSSH_9.6p1 Ubuntu-3ubuntu13.11, OpenSSL 3.0.13 30 Jan 2024", 9},
		{"Dropbear", 0},
	}
	for _, tc := range tests {
		if got := openSSHMajor(tc.version); got != tc.major {
			t.Errorf("openSSHMajor(%q) = %d, want %d", tc.version, got, tc.major)
		}
	}
}
