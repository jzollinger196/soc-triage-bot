#!/usr/bin/env python3
"""Wazuh integratord hook: hand each matching alert to the triage worker.

Wazuh runs this once per alert as:
    custom-soc-triage.py <alert_file> [api_key] [hook_url]

It must finish quickly (Wazuh waits for it), so it only copies the alert into the
spool directory. The soc-triage service does the slow LLM work. Standard library
only, because it runs under Wazuh's bundled Python.
"""
import json
import os
import sys
import time
import uuid

SPOOL_DIR = os.environ.get("SOC_TRIAGE_SPOOL_DIR", "/var/lib/soc-triage/spool")
LOG_FILE = os.environ.get("SOC_TRIAGE_HOOK_LOG", "/var/ossec/logs/integrations.log")
MAX_BYTES = 1_000_000


def log(message):
    line = time.strftime("%Y/%m/%d %H:%M:%S") + " custom-soc-triage: " + message + "\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        sys.stderr.write(line)


def main(argv):
    if len(argv) < 2:
        log("called without an alert file argument")
        return 1
    alert_path = argv[1]
    try:
        if os.path.getsize(alert_path) > MAX_BYTES:
            log("alert larger than %d bytes, skipped: %s" % (MAX_BYTES, alert_path))
            return 1
        with open(alert_path, encoding="utf-8", errors="replace") as fh:
            alert = json.load(fh)
    except (OSError, ValueError) as exc:
        log("cannot read alert %s: %s" % (alert_path, exc))
        return 1
    if not isinstance(alert, dict) or "rule" not in alert:
        log("file is not a Wazuh alert (check <alert_format>json</alert_format>): " + alert_path)
        return 1

    name = "%d-%s.json" % (time.time_ns(), uuid.uuid4().hex[:8])
    tmp_path = os.path.join(SPOOL_DIR, "." + name + ".tmp")
    final_path = os.path.join(SPOOL_DIR, name)
    try:
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o660)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(alert, fh)
        os.chmod(tmp_path, 0o660)        # group-readable by the soctriage worker despite umask
        os.rename(tmp_path, final_path)  # atomic: the worker never sees a half-written file
    except OSError as exc:
        log("cannot write to spool %s: %s" % (SPOOL_DIR, exc))
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
