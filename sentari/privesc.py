"""Privilege-escalation enumeration over SSH (read-only).

Given credentials to an authorized Linux host, this runs a curated set of
read-only enumeration commands and flags known local escalation vectors
(NOPASSWD sudo, dangerous SUID binaries, writable sensitive files, cron and
capability issues). Every command's real output is the evidence; a vector is
reported only when the output actually shows it.

It runs no exploit and changes nothing on the host: it enumerates. It needs
paramiko (pip install "sentari[privesc]") and is gated behind post-exploitation.
"""
from __future__ import annotations

import importlib
from typing import Optional

# SUID binaries that are a known path to root (a small GTFOBins subset).
_SUID_GTFO = {
    "nmap", "vim", "find", "bash", "more", "less", "nano", "cp", "mv", "awk",
    "python", "python2", "python3", "perl", "ruby", "php", "env", "tar", "zip",
    "gdb", "docker", "dmesg", "systemctl", "man", "socat", "ionice", "flock",
}

# (name, command, is-a-vector predicate over the raw output) -> a finding.
_CHECKS = [
    ("whoami/id", "id", None),
    ("kernel version", "uname -a", None),
    ("sudo NOPASSWD", "sudo -n -l 2>/dev/null", "nopasswd"),
    ("SUID binaries", "find / -perm -4000 -type f 2>/dev/null", "suid"),
    ("world-writable /etc/passwd", "ls -la /etc/passwd", "passwd_writable"),
    ("readable /etc/shadow", "test -r /etc/shadow && echo READABLE || echo no",
     "shadow_readable"),
    ("file capabilities", "getcap -r / 2>/dev/null | head -50", "caps"),
    ("writable cron scripts",
     "ls -la /etc/cron* 2>/dev/null; find /etc/cron* -writable -type f 2>/dev/null",
     "cron_writable"),
]


def _paramiko():
    try:
        return importlib.import_module("paramiko")
    except Exception:
        return None


def enumerate_linux(host: str, user: str, password: Optional[str] = None,
                    key_path: Optional[str] = None, port: int = 22,
                    timeout: int = 20) -> tuple[list[dict], Optional[str]]:
    """Return (checks, error). Each check: {name, command, output, vector, severity}."""
    paramiko = _paramiko()
    if paramiko is None:
        return [], "paramiko not installed (pip install \"sentari[privesc]\")"
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=user, password=password,
                       key_filename=key_path, timeout=timeout,
                       allow_agent=False, look_for_keys=bool(key_path))
    except Exception as e:
        return [], f"SSH connect failed: {type(e).__name__}: {e}"
    out = []
    try:
        for name, cmd, vector_key in _CHECKS:
            try:
                _in, _o, _e = client.exec_command(cmd, timeout=timeout)
                body = (_o.read() + _e.read()).decode("utf-8", "replace")
            except Exception as e:
                body = f"<command failed: {e}>"
            vector, sev = _assess(vector_key, body)
            out.append({"name": name, "command": cmd, "output": body[:4000],
                        "vector": vector, "severity": sev})
    finally:
        client.close()
    return out, None


def _assess(vector_key: Optional[str], body: str) -> tuple[Optional[str], str]:
    """Decide whether a check's output shows an escalation vector."""
    low = body.lower()
    if vector_key == "nopasswd" and "nopasswd" in low:
        return "sudo NOPASSWD entry (potential root via allowed command)", "high"
    if vector_key == "suid":
        hits = sorted({b for line in body.splitlines()
                       for b in [line.rsplit("/", 1)[-1].strip()] if b in _SUID_GTFO})
        if hits:
            return f"dangerous SUID binaries present: {', '.join(hits)}", "high"
    if vector_key == "passwd_writable":
        parts = body.split()
        # -rw-rw-rw- or group/other write bit on /etc/passwd
        if parts and len(parts[0]) >= 10 and (parts[0][8] == "w" or parts[0][5] == "w"):
            return "/etc/passwd is writable (add a root user)", "critical"
    if vector_key == "shadow_readable" and "readable" in low:
        return "/etc/shadow is readable (offline hash cracking)", "critical"
    if vector_key == "caps" and ("cap_setuid" in low or "cap_dac_override" in low):
        return "binary with a dangerous capability (cap_setuid/cap_dac_override)", "high"
    if vector_key == "cron_writable":
        # a writable file listed by the find portion
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("/etc/cron") and " " not in line:
                return "writable cron script (code runs as its owner)", "high"
    return None, "info"
