"""
SIEM-Lite — Detection Engine
Rule-based threat detection with sliding-window correlation.
Each rule receives a normalised event and the recent event history,
and returns a ThreatAlert (or None).
"""

import time
import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

log = logging.getLogger(__name__)


# ─── Alert model ──────────────────────────────────────────────────────────────

@dataclass
class ThreatAlert:
    rule_id:     str
    title:       str
    description: str
    severity:    str          # low | medium | high | critical
    mitre_tactic: str
    mitre_technique: str
    event:       dict
    context:     dict = field(default_factory=dict)
    timestamp:   str  = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return self.__dict__.copy()


# ─── Sliding-window state ────────────────────────────────────────────────────

class SlidingWindow:
    """
    Keeps the last *max_age* seconds of events, per arbitrary key.
    Used for correlation (brute-force, port scan, etc.)
    """
    def __init__(self, max_age: int = 60):
        self.max_age = max_age
        self._store: dict[str, deque] = defaultdict(deque)

    def add(self, key: str, value) -> None:
        now = time.monotonic()
        self._store[key].append((now, value))

    def get(self, key: str) -> list:
        now = time.monotonic()
        dq  = self._store[key]
        while dq and now - dq[0][0] > self.max_age:
            dq.popleft()
        return [v for _, v in dq]

    def count(self, key: str) -> int:
        return len(self.get(key))


# ─── Individual detection rules ──────────────────────────────────────────────

class BruteForceSSHRule:
    """
    MITRE T1110 — Brute Force
    Alert when ≥5 SSH failures from the same IP within 60 seconds.
    """
    THRESHOLD = 5
    WINDOW    = 60   # seconds

    def __init__(self):
        self._win = SlidingWindow(max_age=self.WINDOW)

    def evaluate(self, event: dict) -> ThreatAlert | None:
        if event.get("event_type") != "ssh_login_failure":
            return None
        ip = event.get("src_ip", "unknown")
        self._win.add(ip, event)
        count = self._win.count(ip)
        if count >= self.THRESHOLD:
            return ThreatAlert(
                rule_id="DET-001",
                title="SSH Brute Force Detected",
                description=(
                    f"{count} failed SSH attempts from {ip} "
                    f"in the last {self.WINDOW}s."
                ),
                severity="high",
                mitre_tactic="Credential Access",
                mitre_technique="T1110.001 — Password Guessing",
                event=event,
                context={"src_ip": ip, "attempt_count": count},
            )
        return None


class SuccessAfterFailureRule:
    """
    MITRE T1078 — Valid Accounts
    Alert when a successful SSH login follows multiple failures
    from the same IP (possible credential stuffing success).
    """
    FAIL_THRESHOLD = 3

    def __init__(self):
        self._failures = SlidingWindow(max_age=300)

    def evaluate(self, event: dict) -> ThreatAlert | None:
        etype = event.get("event_type")
        ip    = event.get("src_ip", "unknown")

        if etype == "ssh_login_failure":
            self._failures.add(ip, event)

        elif etype == "ssh_login_success":
            failures = self._failures.count(ip)
            if failures >= self.FAIL_THRESHOLD:
                return ThreatAlert(
                    rule_id="DET-002",
                    title="Successful Login After Multiple Failures",
                    description=(
                        f"Login succeeded from {ip} after {failures} failures — "
                        "possible credential stuffing."
                    ),
                    severity="critical",
                    mitre_tactic="Initial Access",
                    mitre_technique="T1078 — Valid Accounts",
                    event=event,
                    context={"src_ip": ip, "prior_failures": failures,
                             "user": event.get("user")},
                )
        return None


class WebPathTraversalRule:
    """
    MITRE T1083 — File and Directory Discovery
    Alert on HTTP path traversal / injection attempts.
    """
    BAD_TYPES = {"http_path_traversal_attempt", "http_injection_attempt"}

    def evaluate(self, event: dict) -> ThreatAlert | None:
        if event.get("event_type") not in self.BAD_TYPES:
            return None
        return ThreatAlert(
            rule_id="DET-003",
            title="Web Attack Attempt",
            description=(
                f"Suspicious HTTP request from {event.get('src_ip')} "
                f"targeting {event.get('path')}"
            ),
            severity="high",
            mitre_tactic="Discovery / Initial Access",
            mitre_technique="T1083 — File & Directory Discovery",
            event=event,
            context={"path": event.get("path"), "src_ip": event.get("src_ip"),
                     "status": event.get("status")},
        )


class WebScannerRule:
    """
    MITRE T1595 — Active Scanning
    Alert when ≥20 HTTP 404s from the same IP within 30 seconds
    (directory / endpoint enumeration).
    """
    THRESHOLD = 20
    WINDOW    = 30

    def __init__(self):
        self._win = SlidingWindow(max_age=self.WINDOW)

    def evaluate(self, event: dict) -> ThreatAlert | None:
        if event.get("event_type") != "http_request" or event.get("status") != 404:
            return None
        ip = event.get("src_ip", "unknown")
        self._win.add(ip, event)
        count = self._win.count(ip)
        if count == self.THRESHOLD:   # fire once at threshold
            return ThreatAlert(
                rule_id="DET-004",
                title="Web Directory Scan Detected",
                description=(
                    f"{count} HTTP 404s from {ip} in {self.WINDOW}s — "
                    "directory enumeration."
                ),
                severity="medium",
                mitre_tactic="Reconnaissance",
                mitre_technique="T1595.003 — Wordlist Scanning",
                event=event,
                context={"src_ip": ip, "request_count": count},
            )
        return None


class PrivilegeEscalationRule:
    """
    MITRE T1548 — Abuse Elevation Control Mechanism
    Alert on sudo failures (user not in sudoers).
    """
    def evaluate(self, event: dict) -> ThreatAlert | None:
        if event.get("event_type") != "sudo_failure":
            return None
        return ThreatAlert(
            rule_id="DET-005",
            title="Privilege Escalation Attempt",
            description="A user attempted sudo but is not in the sudoers file.",
            severity="high",
            mitre_tactic="Privilege Escalation",
            mitre_technique="T1548.003 — Sudo and Sudo Caching",
            event=event,
            context={},
        )


class FirewallSweepRule:
    """
    MITRE T1046 — Network Service Discovery
    Alert when ≥15 firewall drops from the same source IP in 60 seconds.
    """
    THRESHOLD = 15
    WINDOW    = 60

    def __init__(self):
        self._win = SlidingWindow(max_age=self.WINDOW)

    def evaluate(self, event: dict) -> ThreatAlert | None:
        if event.get("event_type") != "firewall_drop":
            return None
        ip = event.get("src_ip", "unknown")
        self._win.add(ip, event)
        count = self._win.count(ip)
        if count == self.THRESHOLD:
            return ThreatAlert(
                rule_id="DET-006",
                title="Port Sweep Detected",
                description=(
                    f"{count} firewall drops from {ip} in {self.WINDOW}s — "
                    "possible port scan."
                ),
                severity="medium",
                mitre_tactic="Discovery",
                mitre_technique="T1046 — Network Service Discovery",
                event=event,
                context={"src_ip": ip, "drop_count": count},
            )
        return None


# ─── Detection engine ─────────────────────────────────────────────────────────

ALL_RULES = [
    BruteForceSSHRule(),
    SuccessAfterFailureRule(),
    WebPathTraversalRule(),
    WebScannerRule(),
    PrivilegeEscalationRule(),
    FirewallSweepRule(),
]


class DetectionEngine:
    def __init__(self, alert_callback: Callable[[ThreatAlert], None]):
        self.rules    = ALL_RULES
        self.callback = alert_callback
        self._total_events = 0
        self._total_alerts = 0

    def process(self, event: dict) -> None:
        self._total_events += 1
        for rule in self.rules:
            try:
                alert = rule.evaluate(event)
                if alert:
                    self._total_alerts += 1
                    log.warning("ALERT [%s] %s", alert.severity.upper(), alert.title)
                    self.callback(alert)
            except Exception as exc:
                log.error("Rule %s failed: %s", rule.__class__.__name__, exc)

    @property
    def stats(self) -> dict:
        return {
            "events_processed": self._total_events,
            "alerts_fired":     self._total_alerts,
        }
