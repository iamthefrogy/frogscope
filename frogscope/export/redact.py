"""Hostname redaction for reports that leave the organisation.

Replaces each hostname with a stable pseudonym while preserving the structure a
reader needs — zone depth, environment, and which assets share a parent — so the
shape of the findings survives but the inventory does not.

Deterministic within one export and salted per export, so the same host maps to
the same pseudonym throughout a document while two documents cannot be
cross-referenced to rebuild the real names.
"""

from __future__ import annotations

import hashlib
import os
import re
from typing import Any

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")


class Redactor:
    """Stable pseudonyms for hosts, IPs, and anything containing them."""

    def __init__(self, salt: str | None = None, keep_tld: bool = True):
        # A random salt unless one is supplied, so two exports of the same estate
        # cannot be joined to recover the real names.
        self.salt = salt or os.urandom(16).hex()
        self.keep_tld = keep_tld
        self._hosts: dict[str, str] = {}
        self._ips: dict[str, str] = {}
        self._domains: dict[str, str] = {}

    def _token(self, value: str, length: int = 8) -> str:
        return hashlib.sha256(
            f"{self.salt}\0{value.lower()}".encode()).hexdigest()[:length]

    def domain(self, name: str) -> str:
        key = name.lower()
        if key not in self._domains:
            self._domains[key] = f"org-{self._token(key, 6)}.example"
        return self._domains[key]

    def host(self, name: str) -> str:
        """Redact a hostname, keeping label count and the registrable domain shape.

        `adm.iem.acme.com` becomes `h-1a2b.z-3c4d.org-5e6f.example` — so a reader
        can still see that two hosts share a zone, and how deep each sits, without
        learning either real name.
        """
        raw = str(name or "").strip()
        if not raw:
            return ""
        key = raw.lower()
        if key in self._hosts:
            return self._hosts[key]

        labels = key.rstrip(".").split(".")
        if len(labels) <= 1:
            out = f"h-{self._token(key)}"
        else:
            # Last two labels are the registrable domain; everything left of it
            # keeps its depth so zone structure is preserved.
            root = ".".join(labels[-2:])
            prefix = labels[:-2]
            parts = [f"h-{self._token('.'.join(labels))}"]
            parts.extend(f"z-{self._token(root + '.' + label, 4)}"
                         for label in prefix[1:])
            out = ".".join(parts + [self.domain(root)])
        self._hosts[key] = out
        return out

    def ip(self, address: str) -> str:
        raw = str(address or "").strip()
        if not raw:
            return ""
        if raw not in self._ips:
            token = self._token(raw, 4)
            if ":" in raw:
                self._ips[raw] = f"2001:db8::{token}"
            else:
                # 198.51.100.0/24 is reserved for documentation.
                self._ips[raw] = (
                    f"198.51.100.{int(token, 16) % 254 + 1}")
        return self._ips[raw]

    def text(self, value: Any) -> Any:
        """Redact any hostnames or addresses embedded in free text or a URL."""
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, (list, tuple)):
            return [self.text(v) for v in value]
        if isinstance(value, dict):
            # Keys as well as values. Several payload sections are keyed BY
            # endpoint — `{"adm.iem.acme.com:443": {...}}` — so redacting only
            # values leaves every hostname sitting in plain sight in the keys.
            return {self.text(k): self.text(v) for k, v in value.items()}

        text = str(value)
        # Longest first, so a host is replaced before its own parent domain
        # turns the host into a half-redacted string.
        for original in sorted(self._hosts, key=len, reverse=True):
            if original in text.lower():
                text = re.sub(re.escape(original), self._hosts[original], text,
                              flags=re.I)
        for original in sorted(self._domains, key=len, reverse=True):
            if original in text.lower():
                text = re.sub(re.escape(original), self._domains[original], text,
                              flags=re.I)
        text = _IPV4.sub(lambda m: self.ip(m.group(0)), text)
        text = _IPV6.sub(lambda m: self.ip(m.group(0)), text)
        return text

    HOST_FIELDS = ("host", "host_display", "final_host", "cname_final",
                   "asset_key", "worst_endpoint")
    IP_FIELDS = ("host_ip", "ip")
    # `zone` and `registrable_domain` are hostname fragments, so they get the
    # domain treatment rather than being renamed as whole hosts.
    DOMAIN_FIELDS = ("registrable_domain",)

    def row(self, row: dict) -> dict:
        """Redact one record.

        Every string value is passed through `text()` rather than a hand-listed
        set of fields. An allow-list is the wrong shape here: `zone`,
        `registrable_domain`, and `tech_flat` all carry the domain, and any field
        missed off the list leaks silently — which is the worst possible failure
        mode for this feature.
        """
        out = dict(row)

        # Register identities first so `text()` can find them inside composite
        # values such as `endpoint_key` and `final_url`.
        for field in self.HOST_FIELDS:
            if out.get(field):
                self.host(str(out[field]))
        for field in self.DOMAIN_FIELDS:
            if out.get(field):
                self.domain(str(out[field]))
        for field in self.IP_FIELDS:
            if out.get(field):
                self.ip(str(out[field]))

        for field in self.HOST_FIELDS:
            if out.get(field):
                out[field] = self.host(str(out[field]))
        for field in self.DOMAIN_FIELDS:
            if out.get(field):
                out[field] = self.domain(str(out[field]))
        for field in self.IP_FIELDS:
            if out.get(field):
                out[field] = self.ip(str(out[field]))

        for key, value in out.items():
            if key in self.HOST_FIELDS or key in self.IP_FIELDS \
                    or key in self.DOMAIN_FIELDS:
                continue
            out[key] = self.text(value)
        return out

    def note(self) -> str:
        return (
            "Hostnames and addresses in this document are pseudonyms. Label "
            "depth and shared parent zones are preserved so the structure of the "
            "findings still reads correctly, but the real names are not "
            "recoverable and two redacted exports cannot be cross-referenced."
        )
