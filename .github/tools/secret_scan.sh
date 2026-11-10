#!/usr/bin/env bash
set -euo pipefail

pattern="AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|(?i)(api[_-]?key|secret|password)[[:space:]]*[:=][[:space:]]*['\"][A-Za-z0-9+/=_-]{24,}"
if findings="$(rg --hidden --glob '!.git/**' --glob '!target/**' --glob '!fuzz/target/**' --pcre2 "$pattern" . 2>/dev/null)"; then
  :
else
  status=$?
  if [[ "$status" -ne 1 ]]; then
    echo "secret scan failed while searching (matching content redacted)" >&2
    exit 2
  fi
fi
if [[ -n "$findings" ]]; then
  if findings="$(printf '%s\n' "$findings" | rg -v 'replace-with|example|changeme|<[^>]+>' 2>/dev/null)"; then
    :
  else
    status=$?
    if [[ "$status" -ne 1 ]]; then
      echo "secret scan failed while filtering (matching content redacted)" >&2
      exit 2
    fi
  fi
fi
if [[ -n "$findings" ]]; then
  echo "potential committed secret detected (matching content redacted)" >&2
  exit 1
fi
