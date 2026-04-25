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
    ip   = random.choice(LEGIT_IPS)
    path = random.choice(PATHS_SAFE)
    write(nginx_log,
          f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
          f'"GET {path} HTTP/1.1" 200 1024 "-" "Mozilla/5.0"')


# ── main loop ─────────────────────────────────────────────────────────────────

SCENARIOS = [
    (ssh_brute_force,         0.15),
    (ssh_success_after_fail,  0.10),
    (web_scan,                0.10),
    (web_attack,              0.20),
    (privilege_escalation,    0.08),
    (firewall_sweep,          0.10),
    (normal_traffic,          0.27),
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
