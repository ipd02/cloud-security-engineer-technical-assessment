#!/usr/bin/env bash
# Installs the pinned scanners that Part 2 needs on a Linux x86_64 CI runner.
# Usage: ci-install-tools.sh python|hadolint|trivy ...
# Tools land in $BIN_DIR (default $HOME/.local/bin). Every download is checked
# against a SHA-256 before it is used.
set -euo pipefail

HADOLINT_VERSION=2.15.1
# The hadolint release publishes no checksum file. This value was computed
# from the v2.15.1 release asset when it was pinned here.
HADOLINT_SHA256=c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507
TRIVY_VERSION=0.75.0

BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$BIN_DIR"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

install_python_tools() {
  local venv="$HOME/.cloud-check-venv"
  python3 -m venv "$venv"
  # ci/scanners.txt pins cfn-lint, checkov and every dependency by hash.
  "$venv/bin/pip" install --quiet --disable-pip-version-check --require-hashes \
    -r "$(dirname "${BASH_SOURCE[0]}")/../../ci/scanners.txt"
  ln -sf "$venv/bin/cfn-lint" "$BIN_DIR/cfn-lint"
  ln -sf "$venv/bin/checkov" "$BIN_DIR/checkov"
}

install_hadolint() {
  local url="https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-linux-x86_64"
  curl -sSfL "$url" -o "$work/hadolint"
  echo "${HADOLINT_SHA256}  $work/hadolint" | sha256sum -c -
  install -m 0755 "$work/hadolint" "$BIN_DIR/hadolint"
}

install_trivy() {
  local base="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"
  local file="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
  curl -sSfL "${base}/${file}" -o "$work/${file}"
  curl -sSfL "${base}/trivy_${TRIVY_VERSION}_checksums.txt" -o "$work/checksums.txt"
  (cd "$work" && grep " ${file}\$" checksums.txt | sha256sum -c -)
  tar -xzf "$work/${file}" -C "$work" trivy
  install -m 0755 "$work/trivy" "$BIN_DIR/trivy"
}

for tool in "$@"; do
  case "$tool" in
    python) install_python_tools ;;
    hadolint) install_hadolint ;;
    trivy) install_trivy ;;
    *) echo "unknown tool: $tool" >&2; exit 2 ;;
  esac
done
