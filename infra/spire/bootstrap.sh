#!/bin/sh
set -eu

SPIRE_SERVER_BIN="${SPIRE_SERVER_BIN:-/opt/spire/bin/spire-server}"
SPIRE_SERVER_SOCKET="${SPIRE_SERVER_SOCKET:-/run/spire/server/private/api.sock}"
SPIRE_BOOTSTRAP_DIR="${SPIRE_BOOTSTRAP_DIR:-/run/spire/bootstrap}"
SPIRE_REGISTRATION_FILE="${SPIRE_REGISTRATION_FILE:-/etc/spire/registration-entries.json}"
SPIRE_AGENT_ID="${SPIRE_AGENT_ID:-spiffe://aegis-ot.m4g.local/agent/compose}"

TOKEN_FILE="${SPIRE_BOOTSTRAP_DIR}/join-token"
BUNDLE_FILE="${SPIRE_BOOTSTRAP_DIR}/bundle.pem"
ENTRIES_MARKER="${SPIRE_BOOTSTRAP_DIR}/registration.complete"

umask 077
mkdir -p "${SPIRE_BOOTSTRAP_DIR}"

bundle_tmp="${BUNDLE_FILE}.tmp"
"${SPIRE_SERVER_BIN}" bundle show \
    -format pem \
    -socketPath "${SPIRE_SERVER_SOCKET}" > "${bundle_tmp}"
mv "${bundle_tmp}" "${BUNDLE_FILE}"

if [ ! -s "${TOKEN_FILE}" ]; then
    token_json=$("${SPIRE_SERVER_BIN}" token generate \
        -output json \
        -spiffeID "${SPIRE_AGENT_ID}" \
        -ttl 600 \
        -socketPath "${SPIRE_SERVER_SOCKET}")
    token=$(printf '%s\n' "${token_json}" \
        | sed -n 's/.*"value"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    if [ -z "${token}" ]; then
        echo "SPIRE token response did not contain a value" >&2
        exit 1
    fi
    token_tmp="${TOKEN_FILE}.tmp"
    printf '%s\n' "${token}" > "${token_tmp}"
    mv "${token_tmp}" "${TOKEN_FILE}"
fi

if [ ! -f "${ENTRIES_MARKER}" ]; then
    "${SPIRE_SERVER_BIN}" entry create \
        -data "${SPIRE_REGISTRATION_FILE}" \
        -socketPath "${SPIRE_SERVER_SOCKET}"
    marker_tmp="${ENTRIES_MARKER}.tmp"
    printf '%s\n' "registered" > "${marker_tmp}"
    mv "${marker_tmp}" "${ENTRIES_MARKER}"
fi
