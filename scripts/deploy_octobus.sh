#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${AGENT_COMPOSE_INSTALL_DIR:-/opt/agent-compose}"
PROJECT_DIR="${VULN_REACH_PROJECT_DIR:-${INSTALL_DIR}/data/projects/vuln-reach}"
ENV_FILE="${INSTALL_DIR}/.env"

cd "${PROJECT_DIR}"

OCTOBUS_TOKEN="$(sed -n 's/^OCTOBUS_TOKEN=//p' "${ENV_FILE}" | tail -1)"
if [[ -z "${OCTOBUS_TOKEN}" ]]; then
  echo "OCTOBUS_TOKEN is not configured in ${ENV_FILE}" >&2
  exit 1
fi

octo() {
  docker exec octobus octobus --addr 127.0.0.1:9000 "$@"
}

octo capset delete vulnreach 2>/dev/null || true
octo instance delete reach-01 2>/dev/null || true
octo service delete vuln-reach 2>/dev/null || true

docker exec -u 0 octobus sh -c \
  'rm -rf /var/lib/octobus/imports/vuln-reach && mkdir -p /var/lib/octobus/imports/vuln-reach/workspace/rules'
docker cp octobus/. octobus:/var/lib/octobus/imports/vuln-reach/
docker cp workspace/rules/. octobus:/var/lib/octobus/imports/vuln-reach/workspace/rules/
docker cp sources.yaml octobus:/var/lib/octobus/imports/vuln-reach/sources.yaml
docker cp inputs octobus:/var/lib/octobus/imports/vuln-reach/inputs
docker exec -u 0 octobus chmod 755 /var/lib/octobus/imports/vuln-reach/bin/vuln-reach.js

octo service import vuln-reach /var/lib/octobus/imports/vuln-reach --build auto --reinstall
octo instance create reach-01 \
  --service vuln-reach \
  --config-json '{"workspacePath":"/data/projects/vuln-reach/workspace"}'
octo capset create vulnreach --name VulnerabilityReach \
  --description 'Vulnerability reachability capability set'
octo capset add-instance vulnreach reach-01 --no-all-methods
octo capset select-method \
  vulnreach reach-01 vulnreach.v1.VulnReachService/BuildRepositoryEvidence \
  --mcp-tool vuln-reach__reach-01__build_repository_evidence
octo capset select-method \
  vulnreach reach-01 vulnreach.v1.VulnReachService/CheckReachability \
  --mcp-tool vuln-reach__reach-01__check_reachability

printf '%s' "${OCTOBUS_TOKEN}" | docker exec -i octobus \
  octobus --addr 127.0.0.1:9000 capset add-token \
  vulnreach vulnreach-token-01 --token-stdin

unset OCTOBUS_TOKEN
octo capset list-methods vulnreach
