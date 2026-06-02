#!/usr/bin/env bash
# Thin wrapper around aci-builder.py for convenient APIC pushes.
#
# Usage:
#   apic-push.sh --file <build-file> --host <apic-ip-or-host>
#                [--user admin] [--password <pass>] [--validate] [--verbose]
#
# Credential resolution order:
#   user:     --user flag > APIC_USER env var > admin
#   password: --password flag > APIC_PASSWORD env var > interactive prompt
#
# Examples:
#   APIC_PASSWORD=secret ./apic-push.sh --file rch-profile.txt --host 172.16.99.170
#   ./apic-push.sh --file site.txt --host apic.lab --user admin --password hunter2

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILDER="${SCRIPT_DIR}/aci-builder.py"

FILE=""
HOST=""
USER="${APIC_USER:-admin}"
PASSWORD="${APIC_PASSWORD:-}"
EXTRA_FLAGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --file)     FILE="$2";     shift 2 ;;
        --host)     HOST="$2";     shift 2 ;;
        --user)     USER="$2";     shift 2 ;;
        --password) PASSWORD="$2"; shift 2 ;;
        --validate|--verbose|--dry-run) EXTRA_FLAGS+=("$1"); shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$FILE" ]]; then
    echo "ERROR: --file is required" >&2; exit 1
fi

# --validate doesn't need a host; --dry-run does (it connects to verify credentials)
if [[ -z "$HOST" ]] && ! printf '%s\n' "${EXTRA_FLAGS[@]}" | grep -qx -- '--validate'; then
    echo "ERROR: --host is required (omit only with --validate)" >&2; exit 1
fi

CMD=(python3 "$BUILDER" --in_file "$FILE" --user "$USER" "${EXTRA_FLAGS[@]}")

if [[ -n "$HOST" ]]; then
    CMD+=(--url "$HOST")
fi

if [[ -n "$PASSWORD" ]]; then
    CMD+=(--password "$PASSWORD")
fi

exec "${CMD[@]}"
