#!/usr/bin/env bash
set -euo pipefail

pattern="AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|(?i)(api[_-]?key|secret|password)[[:space:]]*[:=][[:space:]]*['\"][A-Za-z0-9+/=_-]{24,}"
findings="$(rg --hidden --glob '!.git/**' --glob '!target/**' --glob '!fuzz/target/**' --pcre2 "$pattern" . || true)"
findings="$(printf '%s\n' "$findings" | rg -v 'replace-with|example|changeme|<[^>]+>' || true)"
if [[ -n "$findings" ]]; then
  printf '%s\n' "$findings"
  echo "potential committed secret detected" >&2
  exit 1
fi
