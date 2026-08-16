#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${AGENT_COMPOSE_INSTALL_DIR:-/opt/agent-compose}"
ENV_FILE="${INSTALL_DIR}/.env"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "missing platform env file: ${ENV_FILE}" >&2
  exit 1
fi

OCTOBUS_TOKEN="$(sed -n 's/^OCTOBUS_TOKEN=//p' "${ENV_FILE}" | tail -1)"
if [[ -z "${OCTOBUS_TOKEN}" ]]; then
  echo "OCTOBUS_TOKEN is not configured in ${ENV_FILE}" >&2
  exit 1
fi

payload="$(printf '{"addr":"http://octobus:9000","token":"%s"}' "${OCTOBUS_TOKEN}")"
printf '%s' "${payload}" | curl --fail-with-body --silent --show-error \
  -X POST \
  -H 'Content-Type: application/json' \
  -H 'Connect-Protocol-Version: 1' \
  --data-binary @- \
  http://127.0.0.1:7410/agentcompose.v2.SettingsService/UpdateCapabilityGatewayConfig \
  >/dev/null

unset payload OCTOBUS_TOKEN
echo "Agent Compose capability gateway configured (token value not displayed)."
