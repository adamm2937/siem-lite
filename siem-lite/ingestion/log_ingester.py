"""
SIEM-Lite — Log Ingestion Engine
Watches multiple log sources, parses and normalises events,
then forwards them to the detection pipeline.
"""

import os
import re
import json
import time
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Generator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [INGESTER] %(message)s")
log = logging.getLogger(__name__)


# ─── Normalised event schema ──────────────────────────────────────────────────

def make_event(
    source: str,
    event_type: str,
    severity: str,
    raw: str,
    **extra,
) -> dict:
    """Return a normalised event dict."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "event_type": event_type,
        "severity": severity,          # info | low | medium | high | critical
        "raw": raw,
        **extra,
    }


# ─── Parsers ──────────────────────────────────────────────────────────────────

class AuthLogParser:
    """Parses /var/log/auth.log (Linux SSH / sudo events)."""

    SSH_FAIL   = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)")
    SSH_OK     = re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)")
    SUDO_FAIL  = re.compile(r"sudo:.+user NOT in sudoers")
    SUDO_OK    = re.compile(r"sudo:.+COMMAND=(.+)")

    def parse(self, line: str) -> dict | None:
        if m := self.SSH_FAIL.search(line):
            return make_event(
                source="auth.log", event_type="ssh_login_failure",
                severity="medium", raw=line.strip(),
                user=m.group(1), src_ip=m.group(2),
            )
        if m := self.SSH_OK.search(line):
            return make_event(
                source="auth.log", event_type="ssh_login_success",
                severity="info", raw=line.strip(),
                user=m.group(1), src_ip=m.group(2),
            )
        if self.SUDO_FAIL.search(line):
            return make_event(
                source="auth.log", event_type="sudo_failure",
                severity="high", raw=line.strip(),
            )
        if m := self.SUDO_OK.search(line):
            return make_event(
                source="auth.log", event_type="sudo_command",
                severity="low", raw=line.strip(),
                command=m.group(1).strip(),
            )
        return None


class NginxLogParser:
    """Parses Nginx / Apache combined access log format."""

    PATTERN = re.compile(
        r'(?P<ip>[\d.]+) .+ \[.+\] "(?P<method>\S+) (?P<path>\S+)[^"]*" '
        r'(?P<status>\d{3}) (?P<bytes>\d+)'
    )
    SUSPICIOUS_PATHS = re.compile(
        r"(\.\./|/etc/passwd|/wp-admin|/phpmyadmin|\.php\?|union.select|"
        r"<script|eval\(|base64_decode)", re.I
    )

    def parse(self, line: str) -> dict | None:
        m = self.PATTERN.match(line)
        if not m:
            return None
        status = int(m.group("status"))
        path   = m.group("path")
        sev    = "info"
        etype  = "http_request"

        if status >= 500:
            sev, etype = "medium", "http_server_error"
        elif status == 403:
            sev, etype = "low", "http_forbidden"
        elif status == 404 and self.SUSPICIOUS_PATHS.search(path):
            sev, etype = "high", "http_path_traversal_attempt"
        elif self.SUSPICIOUS_PATHS.search(path):
            sev, etype = "high", "http_injection_attempt"

        return make_event(
            source="nginx_access", event_type=etype, severity=sev,
            raw=line.strip(), src_ip=m.group("ip"),
            method=m.group("method"), path=path, status=status,
        )


class SyslogParser:
    """Generic syslog / kern.log parser — catches OOM, segfaults, firewall drops."""

    OOM     = re.compile(r"Out of memory|oom_kill_process")
    SEGFAULT= re.compile(r"segfault at")
    IPTABLES= re.compile(r"IN=\S+ OUT=\S*.*SRC=([\d.]+).*DST=([\d.]+)")

    def parse(self, line: str) -> dict | None:
        if self.OOM.search(line):
            return make_event(source="syslog", event_type="oom_kill",
                              severity="high", raw=line.strip())
        if self.SEGFAULT.search(line):
            return make_event(source="syslog", event_type="segfault",
                              severity="medium", raw=line.strip())
        if m := self.IPTABLES.search(line):
            return make_event(source="syslog", event_type="firewall_drop",
                              severity="low", raw=line.strip(),
                              src_ip=m.group(1), dst_ip=m.group(2))
        return None


class JSONLogParser:
    """
    Parses newline-delimited JSON logs (e.g. from your brute-force detector
    or any structured logger).
    """
    def parse(self, line: str) -> dict | None:
        try:
            data = json.loads(line)
            return make_event(
                source=data.get("source", "json_log"),
                event_type=data.get("event_type", "generic"),
                severity=data.get("severity", "info"),
                raw=line.strip(),
                **{k: v for k, v in data.items()
                   if k not in ("source", "event_type", "severity")},
            )
        except json.JSONDecodeError:
            return None


# ─── File tailer ──────────────────────────────────────────────────────────────

def tail_file(path: str) -> Generator[str, None, None]:
    """Yield new lines appended to *path*, blocking between batches."""
    p = Path(path)
    p.touch(exist_ok=True)
    with p.open() as fh:
        fh.seek(0, 2)           # jump to end
        while True:
            line = fh.readline()
            if line:
                yield line
            else:
                time.sleep(0.2)


# ─── Ingester orchestrator ────────────────────────────────────────────────────

SOURCES = [
    ("logs/auth.log",        AuthLogParser()),
    ("logs/nginx_access.log", NginxLogParser()),
    ("logs/syslog",           SyslogParser()),
    ("logs/app.json",         JSONLogParser()),
]


class LogIngester:
    def __init__(self, callback: Callable[[dict], None]):
        self.callback  = callback
        self._threads: list[threading.Thread] = []

    def _watch(self, path: str, parser) -> None:
        log.info("Watching %s", path)
        for line in tail_file(path):
            event = parser.parse(line)
            if event:
                self.callback(event)

    def start(self) -> None:
        for path, parser in SOURCES:
            t = threading.Thread(target=self._watch, args=(path, parser),
                                 daemon=True, name=f"tail-{path}")
            t.start()
            self._threads.append(t)
        log.info("Ingester running — watching %d sources", len(SOURCES))

    def join(self) -> None:
        for t in self._threads:
            t.join()
