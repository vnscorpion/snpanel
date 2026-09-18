#!/usr/bin/env bash
set -euo pipefail

SNPANEL_GITHUB="${SNPANEL_GITHUB:-https://github.com/vnscorpion/snpanel}"
SNPANEL_REPO_SLUG="${SNPANEL_GITHUB#*github.com/}"
INSTALLER_REL_PATH="${INSTALLER_REL_PATH:-installer/install.sh}"

latest_tag="$(
  if [[ -n "${SNPANEL_VERSION:-}" ]]; then
    printf '%s\n' "${SNPANEL_VERSION}"
  else
    curl -fsSL "https://api.github.com/repos/${SNPANEL_REPO_SLUG}/tags?per_page=100" \
      | sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\(v[^"]*\)".*/\1/p' \
      | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' \
      | sort -V \
      | tail -n 1
  fi
)"

if [[ -z "$latest_tag" ]]; then
  echo "ERROR: Could not detect latest SNPanel release tag." >&2
  exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'cd /; rm -rf "$tmp_dir"' EXIT

echo "==> Installing ${latest_tag}"
curl -fsSL "${SNPANEL_GITHUB}/archive/refs/tags/${latest_tag}.tar.gz" -o "$tmp_dir/source.tar.gz"
tar -xzf "$tmp_dir/source.tar.gz" -C "$tmp_dir"
source_dir="$(find "$tmp_dir" -mindepth 1 -maxdepth 1 -type d -name 'snpanel-*' | head -n 1)"
[[ -n "$source_dir" && -d "$source_dir" ]] || {
  echo "ERROR: Could not extract SNPanel source archive." >&2
  exit 1
}
cd "$source_dir"
chmod +x "$INSTALLER_REL_PATH" installer/update.sh installer/rescue-firewall.sh
bash "$INSTALLER_REL_PATH"
