#!/usr/bin/env bash
set -euo pipefail

# Local CodeQL analysis helper for Python.
#
# Prereqs:
# - CodeQL CLI installed and on PATH (e.g., `brew install codeql` on macOS)
# - Java available (CodeQL bundles a JRE on most platforms)
#
# Usage:
#   scripts/run_codeql_local.sh [OUT_DIR]
#
# Output:
# - Creates a CodeQL database under .codeql-db
# - Writes SARIF results to OUT_DIR (default: .codeql-results)
#

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
DB_DIR="${ROOT_DIR}/.codeql-db"
OUT_DIR="${1:-${ROOT_DIR}/.codeql-results}"
SARIF_FILE="${OUT_DIR}/codeql-python.sarif"

echo "[CodeQL] Root: ${ROOT_DIR}"
echo "[CodeQL] DB:   ${DB_DIR}"
echo "[CodeQL] Out:  ${OUT_DIR}"

mkdir -p "${OUT_DIR}"

# Clean any previous DB (safe)
rm -rf "${DB_DIR}"

# Create the database for Python (idempotent)
codeql database create "${DB_DIR}" \
  --language=python \
  --source-root "${ROOT_DIR}" \
  --command "python -m py_compile $(git ls-files '*.py' | tr '\n' ' ')" || true

# Finalize database before analysis (required by some CLI versions)
echo "[CodeQL] Finalizing database at ${DB_DIR}"
codeql database finalize "${DB_DIR}" || true

# Try analysis directly using the python-queries suite. If it fails due to
# missing packs, print guidance.
SUITE="codeql/python-queries:codeql-suites/python-security-and-quality.qls"
echo "[CodeQL] Analyzing with suite: ${SUITE}"
if ! codeql database analyze "${DB_DIR}" \
  "${SUITE}" \
  --format=sarifv2.1.0 \
  -o "${SARIF_FILE}" \
  --threads=0; then
  cat >&2 <<'EOF'
[CodeQL] Analysis failed.
[CodeQL] If the failure message indicates the database is not finalized, try:
[CodeQL]   codeql database finalize .codeql-db
[CodeQL] If the failure is due to missing query packs, you have two options:
[CodeQL] You have two options:
[CodeQL]  1) Authenticate and download the pack (recommended):
[CodeQL]       echo "$CODEQL_AUTH_TOKEN" | codeql pack download codeql/python-queries --github-auth-stdin
[CodeQL]     Then re-run this script.
[CodeQL]  2) Or analyze with auto-download (requires token):
[CodeQL]       CODEQL_AUTH_TOKEN=<ghpat> codeql database analyze .codeql-db \
[CodeQL]         codeql/python-queries:codeql-suites/python-security-and-quality.qls \
[CodeQL]         --download --format=sarifv2.1.0 -o .codeql-results/codeql-python.sarif \
[CodeQL]         --threads=0
EOF
  exit 2
fi

echo "[CodeQL] Results written to: ${SARIF_FILE}"
echo "[CodeQL] Tip: Open SARIF in VS Code with the 'SARIF Viewer' extension for a nice UI."
