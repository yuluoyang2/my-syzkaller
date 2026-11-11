#!/usr/bin/env bash
# Build syz-runner-verify with the git revision stamped in.
#
# The executor inside the VM reports its own prog.GitRevision, and pkg/rpcserver
# aborts the pool when it differs from the manager's (rpcserver.go checkRevisions).
# A plain `go build` / `go run` leaves prog.GitRevision as "unknown", so the
# VMs are rejected. The value has to be computed exactly like tools/version.mk:
# HEAD, plus "+" when the tree is dirty.
set -euo pipefail

cd "$(dirname "$0")/../.."

rev=$(git rev-parse HEAD)
if [[ -n "$(git diff --shortstat)" ]]; then
	rev="${rev}+"
fi
date=$(git log -n 1 --format=%cd --date=format:%Y%m%d-%H%M%S)
echo "building rev ${rev}"

mkdir -p rm-verify
go build \
	-ldflags="-s -w -X github.com/google/syzkaller/prog.GitRevision=${rev} -X github.com/google/syzkaller/prog.gitRevisionDate=${date}" \
	-o rm-verify/syz-runner-verify \
	./tools/syz-runner-verify

echo "built rm-verify/syz-runner-verify"
