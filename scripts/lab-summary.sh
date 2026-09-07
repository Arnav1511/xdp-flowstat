#!/usr/bin/env bash
# One-screen summary of the verifier lab: each safety check deleted, and
# exactly what the kernel said about it.
#
#   sudo ./scripts/lab-summary.sh
set -uo pipefail
cd "$(dirname "$0")/.."

printf '\n  %-31s %s\n' "CHECK DELETED" "WHAT THE VERIFIER SAID"
printf '  %s\n' "$(printf '─%.0s' {1..92})"

./scripts/verifier-lab.sh 2>&1 | awk '
/^══════/ {
  name = $0
  sub(/^══════ /, "", name); sub(/ \(deleting.*/, "", name); sub(/ ══════$/, "", name)
  next
}
/invalid access|invalid mem access/ {
  err = $0; sub(/^ *[0-9]+:/, "", err)
  if (name != "" && !(name in seen)) { printf "  %-31s %s\n", name, err; seen[name] = 1 }
}
/^ *[0-9]*:?processed/ {
  if (name ~ /baseline/) { p = $0; sub(/^ *[0-9]+:/, "", p); base = p }
}
END { if (base != "") printf "\n  baseline (all checks present): %s\n", base }'
echo
