#!/usr/bin/env bash
# Proves that the scanners catch the known problems in the original task
# inputs and accept the hardened files. Exits non-zero on the first surprise.
#
# cfn-lint is a template validator, not a security scanner. It accepts the
# original template, so it is only asserted to pass on the hardened one.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

cfn_orig=cloudformation/original.yaml
cfn_hard=cloudformation/hardened.yaml
dock_orig=docker/Dockerfile.original
dock_hard=docker/Dockerfile.hardened

failures=0

# run <label> <expected: pass|fail> <command...>
run() {
  local label="$1" expect="$2"
  shift 2
  "$@" >/dev/null 2>&1
  local rc=$?
  if [[ "$expect" == "pass" && $rc -eq 0 ]] || [[ "$expect" == "fail" && $rc -ne 0 ]]; then
    printf 'ok    %-44s expected %-4s got exit %d\n' "$label" "$expect" "$rc"
  else
    printf 'FAIL  %-44s expected %-4s got exit %d\n' "$label" "$expect" "$rc"
    failures=$((failures + 1))
  fi
}

for tool in cfn-lint checkov hadolint trivy; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 2; }
done

# Originals must be rejected.
run "checkov     $cfn_orig"  fail checkov -f "$cfn_orig" --framework cloudformation --quiet
run "checkov     $dock_orig" fail checkov -f "$dock_orig" --framework dockerfile --quiet
run "hadolint    $dock_orig" fail hadolint --failure-threshold info "$dock_orig"
run "trivy config $cfn_orig" fail trivy config --exit-code 1 "$cfn_orig"
run "trivy config $dock_orig" fail trivy config --exit-code 1 "$dock_orig"

# Hardened files must be accepted.
run "cfn-lint    $cfn_hard"  pass cfn-lint "$cfn_hard"
run "checkov     $cfn_hard"  pass checkov -f "$cfn_hard" --framework cloudformation --quiet
run "checkov     $dock_hard" pass checkov -f "$dock_hard" --framework dockerfile --quiet
run "hadolint    $dock_hard" pass hadolint --failure-threshold info "$dock_hard"
run "trivy config $cfn_hard" pass trivy config --exit-code 1 "$cfn_hard"
run "trivy config $dock_hard" pass trivy config --exit-code 1 "$dock_hard"

if [[ $failures -ne 0 ]]; then
  echo "$failures assertion(s) failed" >&2
  exit 1
fi
echo "all assertions held"
