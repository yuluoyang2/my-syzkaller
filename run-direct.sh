#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$repo_dir"
config_file="$repo_dir/direct.cfg"
timestamp=$(date +%Y%m%d_%H%M%S.%N)

# Resolve the same workdir template used by syz-manager before starting tee.
workdir=$(jq -er --arg timestamp "$timestamp" '
  .workdir | select(contains("{{TIMESTAMP}}")) |
  split("{{TIMESTAMP}}") | join($timestamp)
' "$config_file")
case "$workdir" in
  /*) ;;
  *) workdir="$repo_dir/$workdir" ;;
esac
mkdir -- "$workdir"

# Keep the exact configuration and complete console output with this run.
jq --arg workdir "$workdir" '.workdir = $workdir' "$config_file" > "$workdir/config.cfg"
printf 'workdir: %s\n' "$workdir"
sudo "$repo_dir/bin/syz-manager" -config "$workdir/config.cfg" 2>&1 | tee "$workdir/syz.log"
