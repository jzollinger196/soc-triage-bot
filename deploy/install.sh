#!/usr/bin/env bash
# Installs the SOC triage bot on the Wazuh MANAGER host.
# Usage (from the project folder):  sudo bash deploy/install.sh
set -euo pipefail

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_DIR=/opt/soc-triage
DATA_DIR=/var/lib/soc-triage
CONF_DIR=/etc/soc-triage
WAZUH_DIR=/var/ossec

[[ $EUID -eq 0 ]] || { echo "Run with sudo."; exit 1; }
[[ -d $WAZUH_DIR/integrations ]] || { echo "No Wazuh manager found at $WAZUH_DIR. Run this on the manager."; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
  || { echo "Python 3.9 or newer is required (sudo apt install python3)."; exit 1; }

# Wazuh 4.x runs as user "wazuh"; very old releases used "ossec".
WAZUH_USER=wazuh
id "$WAZUH_USER" >/dev/null 2>&1 || WAZUH_USER=ossec
WAZUH_GROUP="$(id -gn "$WAZUH_USER")"

echo "[1/6] Service account"
getent group soctriage >/dev/null || groupadd --system soctriage
id soctriage >/dev/null 2>&1 || useradd --system --gid soctriage --home-dir "$DATA_DIR" \
  --shell /usr/sbin/nologin soctriage
# Wazuh daemons drop supplementary groups when they start, so the spool must belong to
# Wazuh's primary group. The bot's account joins that group to read what Wazuh drops there.
usermod -aG "$WAZUH_GROUP" soctriage

echo "[2/6] Data directories"
# 0751: other users (Wazuh) may pass through to the spool but cannot list or read the folder.
install -d -o soctriage -g soctriage -m 0751 "$DATA_DIR"
install -d -o soctriage -g soctriage -m 0750 "$DATA_DIR/reports"
install -d -o soctriage -g "$WAZUH_GROUP" -m 2770 "$DATA_DIR/spool"
chgrp "$WAZUH_GROUP" "$DATA_DIR/spool"   # also fixes installs made by older versions of this script
chmod 2770 "$DATA_DIR/spool"

echo "[3/6] Application code -> $APP_DIR"
install -d -o root -g root -m 0755 "$APP_DIR"
rm -rf "$APP_DIR/soc_triage"
cp -r "$SRC_DIR/soc_triage" "$APP_DIR/"
chown -R root:root "$APP_DIR"
chmod -R u=rwX,go=rX "$APP_DIR"

echo "[4/6] Config -> $CONF_DIR/config.json"
install -d -o root -g soctriage -m 0750 "$CONF_DIR"
if [[ -f $CONF_DIR/config.json ]]; then
  echo "      existing config kept"
else
  install -o root -g soctriage -m 0640 "$SRC_DIR/config.example.json" "$CONF_DIR/config.json"
fi
if [[ ! -f $CONF_DIR/secrets.env ]]; then
  install -o root -g soctriage -m 0640 "$SRC_DIR/deploy/secrets.env.example" "$CONF_DIR/secrets.env"
fi
# Let the bot verify the Wazuh indexer's TLS certificate (used by the dashboard feature).
if [[ -f /etc/wazuh-indexer/certs/root-ca.pem ]]; then
  install -o root -g soctriage -m 0644 /etc/wazuh-indexer/certs/root-ca.pem "$CONF_DIR/indexer-root-ca.pem"
fi

echo "[5/6] Wazuh integration hook"
install -o root -g "$WAZUH_GROUP" -m 0750 "$SRC_DIR/wazuh/custom-soc-triage" "$WAZUH_DIR/integrations/custom-soc-triage"
install -o root -g "$WAZUH_GROUP" -m 0750 "$SRC_DIR/wazuh/custom-soc-triage.py" "$WAZUH_DIR/integrations/custom-soc-triage.py"

echo "[6/6] systemd service and soc-triage command"
install -o root -g root -m 0755 "$SRC_DIR/deploy/soc-triage" /usr/local/bin/soc-triage
install -o root -g root -m 0644 "$SRC_DIR/deploy/soc-triage.service" /etc/systemd/system/soc-triage.service
systemctl daemon-reload
systemctl enable --now soc-triage

cat <<EOF

Installed. Remaining manual steps:
  1. Edit $CONF_DIR/config.json (agent names, Ollama URL/model, ticketing)
     and put passwords/tokens in $CONF_DIR/secrets.env.
  2. Paste wazuh/ossec-integration.xml into $WAZUH_DIR/etc/ossec.conf
     and wazuh/local_rules.xml into $WAZUH_DIR/etc/rules/local_rules.xml.
  3. sudo systemctl restart wazuh-manager soc-triage
  4. Check everything: soc-triage check
  5. Watch: sudo journalctl -u soc-triage -f
Reports land in $DATA_DIR/reports/
EOF
