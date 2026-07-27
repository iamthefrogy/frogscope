"""Locating and describing the external scanners.

Frogscope does not reimplement subfinder or httpx. It runs them, which means the
interesting failure is "the binary is not there" — and that has to be reported
clearly rather than as a stack trace, because it is the normal state outside the
Docker image.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass

# Where the Docker image puts Go binaries, plus the usual local install path. A
# plain PATH lookup misses both when the server is started by something with a
# minimal environment.
EXTRA_PATHS = ("/usr/local/bin", "/root/go/bin",
               os.path.expanduser("~/go/bin"))


@dataclass
class Tool:
    name: str
    purpose: str
    available: bool
    path: str = ""
    version: str = ""
    install_hint: str = ""

    def as_dict(self) -> dict:
        return {"name": self.name, "purpose": self.purpose,
                "available": self.available, "path": self.path,
                "version": self.version, "install_hint": self.install_hint}


# Required for every scan. `EXTRA` powers IP/CIDR target resolution, port
# scanning, DNS analysis, and TLS certificate reading — all unconditional
# now, but their absence must never break a plain domain scan (each degrades
# gracefully, see `missing(required=...)` below).
CORE = ("subfinder", "httpx")
EXTRA = ("dnsx", "mapcidr", "tlsx", "naabu")
ALL = CORE + EXTRA

HINTS = {
    "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/"
                 "cmd/subfinder@latest",
    "httpx": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "dnsx": "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "mapcidr": "go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest",
    "tlsx": "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
    "naabu": "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
}

PURPOSE = {
    "subfinder": "finds subdomains of a domain from passive sources",
    "httpx": "probes each host and reports what answers",
    "dnsx": "resolves names to addresses, and addresses back to names",
    "mapcidr": "expands an address range into individual addresses",
    "tlsx": "reads TLS certificates, including the other names they cover",
    "naabu": "scans for open ports so httpx/tlsx skip closed ones",
}


def find(name: str) -> str:
    """Absolute path to a tool, or empty string."""
    found = shutil.which(name)
    if found:
        return found
    for directory in EXTRA_PATHS:
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""


def _version(path: str) -> str:
    """Read a version banner. Best-effort: absence is not an error."""
    try:
        result = subprocess.run([path, "-version"], capture_output=True,
                                text=True, encoding="utf-8", errors="replace",
                                timeout=15)
    except (OSError, subprocess.SubprocessError):
        return ""
    # These tools print the banner on stderr, and colour it.
    blob = f"{result.stdout}\n{result.stderr}"
    blob = re.sub(r"\x1b\[[0-9;]*m", "", blob)
    match = re.search(r"v?(\d+\.\d+\.\d+)", blob)
    return match.group(1) if match else ""


def describe(name: str) -> Tool:
    path = find(name)
    return Tool(
        name=name,
        purpose=PURPOSE.get(name, ""),
        available=bool(path),
        path=path,
        version=_version(path) if path else "",
        install_hint=HINTS.get(name, ""),
    )


def inventory(names: tuple[str, ...] = ALL) -> dict[str, Tool]:
    return {name: describe(name) for name in names}


def missing(required: tuple[str, ...] = CORE) -> list[str]:
    """Which of `required` are absent. Defaults to the tools a plain domain
    scan cannot run without — checking the full `ALL` inventory here would
    fail every existing scan the moment EXTRA grows on a machine that never
    installed dnsx/mapcidr/tlsx."""
    return [name for name in required if not describe(name).available]
