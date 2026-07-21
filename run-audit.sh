#!/bin/bash
# run-audit.sh — Launch audit-restore.sh on a remote VPS and download results
# Usage: ./run-audit.sh root@your-vps-ip
#        ./run-audit.sh root@your-vps-ip -p 2222        (custom SSH port)
#        ./run-audit.sh root@your-vps-ip -i ~/.ssh/key   (custom key)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUDIT_SCRIPT="${SCRIPT_DIR}/audit-restore.sh"
LOCAL_OUT="${SCRIPT_DIR}/audits"

if [ -z "${1:-}" ]; then
  echo "Usage: $0 <ssh-target> [ssh-options]"
  echo "  e.g. $0 root@192.168.1.100"
  echo "  e.g. $0 root@192.168.1.100 -p 2222"
  exit 1
fi

SSH_TARGET="$1"
shift
SSH_OPTS=("$@")

echo "=== Remote Audit: ${SSH_TARGET} ==="
echo ""

# ── Run audit script on VPS via stdin ───────────────────────────
echo "[1/2] Running audit on ${SSH_TARGET}..."
REMOTE_OUTPUT=$(ssh ${SSH_OPTS[@]+"${SSH_OPTS[@]}"} "$SSH_TARGET" 'bash -s' < "$AUDIT_SCRIPT" 2>&1)

echo "$REMOTE_OUTPUT"
echo ""

# ── Extract tarball path from output ────────────────────────────
REMOTE_TAR=$(echo "$REMOTE_OUTPUT" | grep '^TARBALL_PATH=' | tail -1 | cut -d= -f2)

if [ -z "$REMOTE_TAR" ]; then
  echo "[ERROR] Could not find TARBALL_PATH in remote output."
  echo "        The audit script may have failed. Check output above."
  exit 1
fi

# ── Download ────────────────────────────────────────────────────
mkdir -p "$LOCAL_OUT"
LOCAL_TAR="${LOCAL_OUT}/$(basename "$REMOTE_TAR")"

echo "[2/2] Downloading ${REMOTE_TAR}..."
scp ${SSH_OPTS[@]+"${SSH_OPTS[@]}"} "${SSH_TARGET}:${REMOTE_TAR}" "$LOCAL_TAR"

# ── Extract locally for quick inspection ────────────────────────
EXTRACT_DIR="${LOCAL_OUT}/$(basename "$REMOTE_TAR" .tar.gz)"
mkdir -p "$EXTRACT_DIR"
tar -xzf "$LOCAL_TAR" -C "$EXTRACT_DIR" --strip-components=1

echo ""
echo "=== Done ==="
echo "Archive:  ${LOCAL_TAR}"
echo "Extracted:"
echo "  ${EXTRACT_DIR}/test_results.csv"
echo "  ${EXTRACT_DIR}/site_summary.csv"
echo ""

# ── Quick preview ───────────────────────────────────────────────
echo "--- site_summary.csv preview ---"
column -t -s',' "$EXTRACT_DIR/site_summary.csv" | head -20

FAIL_COUNT=$(grep -c '"FAIL"' "$EXTRACT_DIR/test_results.csv" 2>/dev/null || echo "0")
TOTAL_COUNT=$(tail -n +2 "$EXTRACT_DIR/test_results.csv" | wc -l | tr -d ' ')
echo ""
echo "Tests: ${TOTAL_COUNT} total, ${FAIL_COUNT} failing"
