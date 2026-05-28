#!/usr/bin/env bash
set -euo pipefail

profile="${1:-coverage.out}"
test_log="${2:-}"

if [[ ! -f "${profile}" ]]; then
	echo "coverage profile not found: ${profile}" >&2
	exit 1
fi

echo "Coverage summary"
echo "================"

if [[ -n "${test_log}" && -f "${test_log}" ]]; then
	grep -E 'coverage:' "${test_log}" | awk '{
		pkg=""
		pct=""
		for (i = 1; i <= NF; i++) {
			if ($i ~ /github\.com\/fidlabs\/paid-retrievals\//) {
				pkg = $i
				sub(/^.*paid-retrievals\//, "", pkg)
			}
			if ($i == "coverage:") {
				pct = $(i + 1)
			}
		}
		if (pkg != "" && pct != "") {
			printf "  %-45s %s\n", pkg, pct
		}
	}' || true
	echo ""
fi

total="$(go tool cover -func="${profile}" | awk '/^total:/ {print $3; exit}')"
echo "  Total: ${total} of statements"
echo "  Detail: coverage.html (per-function breakdown)"
