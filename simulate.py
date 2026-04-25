"""
SIEM-Lite — Demo Log Generator
Writes realistic fake log entries to simulate live attack scenarios.
Usage: python simulate.py
"""

import random
import time
from datetime import datetime
from pathlib import Path

# ── helpers ───────────────────────────────────────────────────────────────────

ATTACKER_IPS  = ["185.220.101.42", "45.33.32.156", "103.21.244.0", "198.51.100.7"]
LEGIT_IPS     = ["10.0.0.2", "10.0.0.5", "192.168.1.10"]
USERS         = ["admin", "root", "ubuntu", "deploy", "git", "oracle"]
PATHS_SAFE    = ["/", "/index.html", "/api/users", "/favicon.ico"]
PATHS_EVIL    = ["/../../../etc/passwd", "/wp-admin", "/phpmyadmin",
                 "/?q=<script>alert(1)</script>", "/?id=1 union select 1,2,3"]

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

auth_log   = open(LOG_DIR / "auth.log", "a")
nginx_log  = open(LOG_DIR / "nginx_access.log", "a")
syslog     = open(LOG_DIR / "syslog", "a")


def ts():
    return datetime.now().strftime("%b %d %H:%M:%S")


def write(f, line):
    f.write(line + "\n")
    f.flush()


# ── scenario generators ───────────────────────────────────────────────────────

def ssh_brute_force(ip=None):
    ip = ip or random.choice(ATTACKER_IPS)
    user = random.choice(USERS)
    for _ in range(random.randint(6, 12)):
        write(auth_log,
              f"{ts()} server sshd[1234]: Failed password for {user} from {ip} port 22 ssh2")
        time.sleep(0.1)
    print(f"[SIM] SSH brute-force from {ip}")


def ssh_success_after_fail(ip=None):
    ip = ip or random.choice(ATTACKER_IPS)
    user = random.choice(USERS)
    for _ in range(4):
        write(auth_log,
              f"{ts()} server sshd[1234]: Failed password for {user} from {ip} port 22 ssh2")
        time.sleep(0.05)
    write(auth_log,
          f"{ts()} server sshd[1234]: Accepted password for {user} from {ip} port 22 ssh2")
    print(f"[SIM] Login success after failures from {ip} (user={user})")


def web_scan(ip=None):
    ip = ip or random.choice(ATTACKER_IPS)
    for _ in range(25):
        path = f"/wp-content/{random.randint(1000,9999)}"
        write(nginx_log,
              f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
              f'"GET {path} HTTP/1.1" 404 162 "-" "sqlmap/1.7"')
        time.sleep(0.02)
    print(f"[SIM] Web directory scan from {ip}")


def web_attack(ip=None):
    ip = ip or random.choice(ATTACKER_IPS)
    path = random.choice(PATHS_EVIL)
    write(nginx_log,
          f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
          f'"GET {path} HTTP/1.1" 200 512 "-" "curl/7.88"')
    print(f"[SIM] Web attack from {ip}: {path}")


def privilege_escalation():
    write(auth_log,
          f"{ts()} server sudo: hacker : user NOT in sudoers ; "
          f"TTY=pts/0 ; PWD=/home/hacker ; USER=root ; COMMAND=/bin/bash")
    print("[SIM] Privilege escalation attempt")


def firewall_sweep(ip=None):
    ip = ip or random.choice(ATTACKER_IPS)
    for port in random.sample(range(1, 65535), 20):
        write(syslog,
              f"{ts()} server kernel: [UFW BLOCK] IN=eth0 OUT= "
              f"SRC={ip} DST=10.0.0.1 LEN=44 PROTO=TCP DPT={port}")
        time.sleep(0.05)
    print(f"[SIM] Port sweep from {ip}")


def normal_traffic():
    """INFO — regular legitimate HTTP requests."""
    ip   = random.choice(LEGIT_IPS)
    path = random.choice(PATHS_SAFE)
    write(nginx_log,
          f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
          f'"GET {path} HTTP/1.1" 200 1024 "-" "Mozilla/5.0"')


def ssh_success_normal():
    """INFO — legitimate SSH login from internal IP."""
    ip   = random.choice(LEGIT_IPS)
    user = random.choice(["adam", "deploy", "ubuntu"])
    write(auth_log,
          f"{ts()} server sshd[1234]: Accepted publickey for {user} from {ip} port 22 ssh2")
    print(f"[SIM] Normal SSH login from {ip} (user={user})")


def sudo_normal():
    """LOW — authorised sudo command from a known user."""
    user = random.choice(["adam", "ubuntu", "deploy"])
    cmd  = random.choice(["/usr/bin/apt update", "/bin/systemctl restart nginx",
                          "/usr/bin/tail -f /var/log/syslog"])
    write(auth_log,
          f"{ts()} server sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; "
          f"USER=root ; COMMAND={cmd}")
    print(f"[SIM] Authorised sudo by {user}: {cmd}")


def http_forbidden():
    """LOW — 403 on a restricted path (misconfigured client, not an attack)."""
    ip   = random.choice(LEGIT_IPS)
    path = random.choice(["/admin", "/server-status", "/.env"])
    write(nginx_log,
          f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
          f'"GET {path} HTTP/1.1" 403 512 "-" "Mozilla/5.0"')
    print(f"[SIM] HTTP 403 from {ip} → {path}")


def http_server_error():
    """MEDIUM — 500 server error (app bug, not an attack)."""
    ip   = random.choice(LEGIT_IPS + ATTACKER_IPS[:1])
    path = random.choice(["/api/users", "/api/data", "/checkout"])
    write(nginx_log,
          f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
          f'"POST {path} HTTP/1.1" 500 256 "-" "python-requests/2.28"')
    print(f"[SIM] HTTP 500 from {ip} → {path}")


# ── main loop ─────────────────────────────────────────────────────────────────
#
# Severity distribution target:
#   critical ~5%  |  high ~25%  |  medium ~25%  |  low ~20%  |  info ~25%
#
SCENARIOS = [
    # --- CRITICAL / HIGH ---
    (ssh_success_after_fail,  0.05),   # critical
    (ssh_brute_force,         0.12),   # high
    (web_attack,              0.08),   # high
    (privilege_escalation,    0.05),   # high
    # --- MEDIUM ---
    (web_scan,                0.12),   # medium
    (firewall_sweep,          0.08),   # medium
    (http_server_error,       0.05),   # medium
    # --- LOW ---
    (http_forbidden,          0.10),   # low
    (sudo_normal,             0.10),   # low
    # --- INFO ---
    (normal_traffic,          0.15),   # info
    (ssh_success_normal,      0.10),   # info
]

if __name__ == "__main__":
    print("SIEM-Lite simulator running — Ctrl+C to stop\n")
    weights = [w for _, w in SCENARIOS]
    funcs   = [f for f, _ in SCENARIOS]
    try:
        while True:
            fn = random.choices(funcs, weights=weights, k=1)[0]
            fn()
            time.sleep(random.uniform(0.5, 3.0))
    except KeyboardInterrupt:
        print("\nSimulator stopped.")