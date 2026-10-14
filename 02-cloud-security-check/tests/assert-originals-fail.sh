#!/usr/bin/env bash
# Checks that the scanners reject the original files for the right reason and
# accept the hardened files. Exits 1 if any check does not behave as expected.
#
# cfn-lint only checks that a template is valid, and the original is valid. So
# it is run on the hardened template only.
#
# There is no "set -e": the script counts the failures and reports them at the end.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

cfn_orig=cloudformation/original.yaml
cfn_hard=cloudformation/hardened.yaml
dock_orig=docker/Dockerfile.original
dock_hard=docker/Dockerfile.hardened

failures=0

# run <label> <expected: pass|fail> <rule id to find in the output, or -> <command...>
# A "fail" check must exit non-zero and print the rule id. A crash does not count.
run() {
  local label="$1" expect="$2" rule="$3" out rc note=""
  shift 3
  out="$("$@" 2>&1)"
  rc=$?
  if [[ "$expect" == "pass" && $rc -eq 0 ]] || [[ "$expect" == "fail" && $rc -ne 0 && "$out" == *"$rule"* ]]; then
    [[ $rule != - ]] && note="($rule found)"
    printf 'ok    %-26s expected %-4s got exit %d %s\n' "$label" "$expect" "$rc" "$note"
  else
    printf 'FAIL  %-26s expected %-4s got exit %d\n' "$label" "$expect" "$rc"
    failures=$((failures + 1))
  fi
}

for tool in cfn-lint checkov hadolint trivy; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 2; }
done

# The original files must be rejected, and the output must name a known problem.
run "checkov original.yaml"       fail CKV_AWS_63    checkov -f "$cfn_orig" --framework cloudformation --quiet
run "checkov Dockerfile.original" fail CKV_DOCKER_8  checkov -f "$dock_orig" --framework dockerfile --quiet
run "hadolint Dockerfile.original" fail DL3002       hadolint --failure-threshold info "$dock_orig"
run "trivy original.yaml"         fail AWS-0086      trivy config --exit-code 1 "$cfn_orig"
run "trivy Dockerfile.original"   fail DS-0031       trivy config --exit-code 1 "$dock_orig"

# The hardened files must be accepted.
run "cfn-lint hardened.yaml"       pass -            cfn-lint "$cfn_hard"
run "checkov hardened.yaml"        pass -            checkov -f "$cfn_hard" --framework cloudformation --quiet
run "checkov Dockerfile.hardened"  pass -            checkov -f "$dock_hard" --framework dockerfile --quiet
run "hadolint Dockerfile.hardened" pass -            hadolint --failure-threshold info "$dock_hard"
run "trivy hardened.yaml"          pass -            trivy config --exit-code 1 "$cfn_hard"
run "trivy Dockerfile.hardened"    pass -            trivy config --exit-code 1 "$dock_hard"

if [[ $failures -ne 0 ]]; then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "all checks held"
