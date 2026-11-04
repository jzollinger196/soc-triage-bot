#!/usr/bin/env bash
# Import the SOC Triage dashboard into the Wazuh dashboard (OpenSearch Dashboards).
# Usage: bash dashboard/import_dashboard.sh [https://<dashboard-host>] [admin-user]
# You'll be prompted for the password. -k accepts the lab's self-signed certificate.
set -euo pipefail
DASHBOARD_URL="${1:-https://127.0.0.1}"
USER_NAME="${2:-admin}"
FILE="$(cd "$(dirname "$0")" && pwd)/soc-triage-dashboard.ndjson"

read -r -s -p "Password for ${USER_NAME}: " PASSWORD; echo
curl -sS -k -u "${USER_NAME}:${PASSWORD}" \
  -X POST "${DASHBOARD_URL}/api/saved_objects/_import?overwrite=true" \
  -H "osd-xsrf: true" \
  --form "file=@${FILE}"
echo
echo "Open ${DASHBOARD_URL}, search the menu for 'Dashboards', and open 'SOC Triage Bot'."
