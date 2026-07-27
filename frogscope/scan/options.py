"""Scan options, and turning them into an argument list.

SECURITY: this module exists so that nothing a user types in a browser is ever
concatenated into a command line. Options arrive as a small, typed, validated set
and are turned into an `argv` LIST — never a shell string, and the subprocess is
always started without a shell.

The alternative — "let the user type httpx flags" — would be command injection
with extra steps: `-o /etc/passwd`, `-H $(...)`, or simply `; rm -rf ~`. So the UI
exposes choices, and the choices map to flags here.

Adding a flag is a deliberate act: put it in `FLAGS` (or `PORT_PROFILES`) and it
becomes selectable. Anything not listed cannot be reached.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

# A domain, as strictly as is reasonable. Deliberately narrow: no schemes, no
# paths, no spaces, no shell metacharacters can survive this.
DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

# A coarse pre-check, not a validator: only decides whether an `ipaddress`
# parse attempt is worth making at all. `ipaddress.ip_network` is the actual
# validator; this just stops "example.com/a/b" (also containing a "/") from
# being sent through that path and misread as a malformed CIDR.
_CIDR_SHAPE = re.compile(r"^[0-9a-f:.]+/\d{1,3}$")

# A real domain portfolio is large. A company of any size holds live brands,
# country domains, defensive registrations, acquisitions, and parked names — the
# list runs to hundreds, and asking somebody to split it across projects would
# fragment the very history this tool exists to build.
#
# So this is a sanity ceiling against a pasted-in file, not a policy. The limit
# that matters is on HOSTS, below: domain count costs enumeration time, but host
# count is what decides how much traffic is sent, and that is the one worth
# gating.
MAX_DOMAINS = 2_000

# The hard ceiling on what one scan will probe. Passive enumeration of a single
# well-known domain returned 23,350 hosts in testing — probing all of them is a
# lot of traffic aimed at strangers, and almost never what somebody meant to do.
# Raised alongside MAX_DOMAINS: a few hundred domains legitimately resolve to far
# more hosts than a single one does.
MAX_HOSTS = 200_000

# Above this, the scan STOPS and asks. Enumeration is passive and harmless;
# probing is not, and consent should be proportional to scale. A number typed
# before you know the size of the estate is not informed consent.
#
# This, not the domain count, is the real safety valve — and it matters more as
# the domain list grows.
CONFIRM_ABOVE = 500

# Domains enumerated at once. subfinder takes roughly half a minute per domain
# against passive sources, so a few hundred done one after another is hours of
# apparent hang. These are read-only queries to third-party APIs, so a modest pool
# is polite and turns that into minutes.
ENUMERATION_WORKERS = 8

# v2: a scan may target a domain, a bare IP address, or a CIDR range, instead
# of only a domain. No `asn` kind — asnmap/dnsx-asn/mapcidr's ASN input all
# require a ProjectDiscovery API key, which this release does not depend on.
TARGET_KINDS = ("domain", "ip", "cidr", "mixed")

# Same reasoning as MAX_DOMAINS: a ceiling against a pasted-in file, not a
# policy against a real list of addresses somebody means to scan.
MAX_IPS = 5_000

# A single CIDR entry is refused outright above this many addresses, with a
# real explanation, rather than silently taking a long time or being caught
# only after mapcidr has already expanded it. 65,536 is a /16 (or a v6 block
# of the same size) — noticeably more than that is very rarely what someone
# pasting in a range meant to do.
MAX_CIDR_ADDRESSES = 65_536


# Port sets, named rather than free-typed. A free-form port string is both a
# validation problem and a way to accidentally launch a 65535-port scan.
PORT_PROFILES: dict[str, dict] = {
    "web": {
        "label": "Standard web (80, 443)",
        "ports": [80, 443],
        "note": "Fastest. Misses anything on an alternate port.",
    },
    "common": {
        "label": "Common web and proxy ports",
        "ports": [80, 443, 8080, 8443, 8000, 8888, 81, 591, 2082, 2087, 3000],
        "note": "A reasonable default for a recurring scan.",
    },
    "wide": {
        "label": "Wide — includes app servers and management ports",
        "ports": [80, 443, 81, 82, 83, 84, 85, 88, 90, 443, 2052, 2053, 2082,
                  2083, 2086, 2087, 2095, 2096, 3000, 3128, 4443, 4433, 5000,
                  7001, 7002, 8000, 8001, 8008, 8080, 8081, 8443, 8834, 8880,
                  8888, 9000, 9090, 9200, 9443, 10000],
        "note": "Finds app servers and consoles. Slower, and more likely to be "
                "noticed.",
    },
}

DEFAULT_PROFILE = "common"


# Selectable httpx behaviour. `flag` is what actually reaches argv.
#
# `-screenshot` is deliberately absent. It needs a headless browser that the image
# does not ship, and httpx exits 1 when it cannot find one — losing the whole scan,
# enumeration included, for a flag whose output the analysis does not yet consume.
# An option that reliably breaks the run is worse than no option.
#
# Ordered most useful first. The form renders them in this order, and an
# alphabetical list put the two least useful flags at the top.
FLAGS: dict[str, dict] = {
    "tech_detect": {
        "flag": ["-tech-detect"], "default": True,
        "label": "Identify technologies",
        "note": "Needed for end-of-life and outdated-component findings.",
    },
    "tls_grab": {
        "flag": ["-tls-grab"], "default": True,
        "label": "Read TLS certificates",
        "note": "Unlocks the certificate-expiry and legacy-TLS rules, which are "
                "otherwise inert.",
    },
    "favicon": {
        "flag": ["-favicon"], "default": True,
        "label": "Hash favicons",
        "note": "Often the only way to identify a product behind a login page.",
    },
    "body_preview": {
        "flag": ["-body-preview"], "default": True,
        "label": "Capture a little response body",
        "note": "Unlocks takeover fingerprints and credential-in-response checks.",
    },
    "follow_redirects": {
        "flag": ["-follow-redirects"], "default": True,
        "label": "Follow redirects",
        "note": "Reveals where a host actually sends you — needed to spot "
                "federated logins and off-site redirects.",
    },
    "jarm": {
        "flag": ["-jarm"], "default": False,
        "label": "JARM TLS fingerprint",
        "note": "Slower: it makes several extra TLS handshakes per host.",
    },
    "asn": {
        "flag": ["-asn"], "default": False,
        "label": "Look up ASN",
        "note": "Adds the owning network. Needs an offline database on first use.",
    },
}


# DNS/network analysis (dnsx resolve+reverse, mapcidr aggregate) and TLS
# certificate reading (tlsx) are both core now — every scan gets all of it,
# regardless of target kind, with no opt-in toggle. No `asn_lookup` — asnmap/
# dnsx-asn/mapcidr's ASN input all require a ProjectDiscovery API key, which
# this release does not depend on (see config/cloud_ranges.yaml for the
# credential-free replacement).

# Discovered cert-SAN names are recorded, never auto-probed (probing a name
# nobody entered would defeat the authorisation checkbox this whole module is
# built around) — but recording is still bounded, so a CT-log-scale
# certificate cannot make one run's sidecar unbounded.
MAX_SAN_DISCOVERED = 2_000


class OptionError(ValueError):
    """A scan request that will not be run."""


def classify_target(entry: str) -> tuple[str, str]:
    """Classify one pasted line as ("domain"|"ip"|"cidr", canonical value).

    The canonical value is always produced BY `ipaddress`/the domain regex,
    never passed through from the raw string — the same "nothing typed in a
    browser reaches argv unvalidated" posture `httpx_argv`/`subfinder_argv`
    already rely on. Raises OptionError with a real explanation for anything
    that is none of the three.
    """
    name = str(entry).strip().lower().rstrip(".")
    # Strip a URL scheme, but NOT a path yet — a CIDR's "/28" reads exactly
    # like a URL path segment, so path-stripping has to happen AFTER the CIDR
    # check below, not before it (an earlier version stripped it first and
    # silently turned every CIDR into its own bare network address).
    scheme_stripped = re.sub(r"^[a-z]+://", "", name)

    # Only worth an ip_network() attempt if this is shaped like one — hex
    # digits/dots/colons then a prefix length. Without this guard,
    # "example.com/a/b" also contains a "/" and would otherwise be sent
    # through the CIDR path instead of being read as a URL with a path.
    if _CIDR_SHAPE.match(scheme_stripped):
        try:
            network = ipaddress.ip_network(scheme_stripped, strict=False)
        except ValueError:
            raise OptionError(
                f"{entry!r} looks like an address range but is not a valid "
                f"CIDR block (e.g. 203.0.113.0/24).") from None
        if network.num_addresses > MAX_CIDR_ADDRESSES:
            raise OptionError(
                f"{entry!r} is {network.num_addresses:,} addresses, more than "
                f"the {MAX_CIDR_ADDRESSES:,} ceiling for one range. Probing a "
                f"block that size is a lot of traffic aimed at addresses that "
                f"may not even be yours — split it into smaller ranges if you "
                f"mean all of it.")
        return "cidr", network.compressed

    # Try the whole string as an IP first — splitting on ":" before this would
    # mangle an IPv6 address, which uses ":" as its own separator.
    try:
        address = ipaddress.ip_address(scheme_stripped)
    except ValueError:
        # Might be "203.0.113.5:8080" from a pasted URL. Only worth retrying
        # for the IPv4-with-port shape; a truncated IPv6 address fails
        # ip_address just as validly, so no special-casing is needed there.
        try:
            address = ipaddress.ip_address(
                scheme_stripped.split("/")[0].split(":")[0])
        except ValueError:
            address = None
    if address is not None:
        return "ip", address.compressed

    # Domain: accept a pasted URL by taking its host, but nothing else.
    stripped = scheme_stripped.split("/")[0].split(":")[0]
    if not DOMAIN.match(stripped):
        raise OptionError(
            f"{entry!r} is not a domain, an IP address, or a CIDR range. "
            f"Enter something like example.com, 203.0.113.5, or "
            f"203.0.113.0/24 — not a URL or a wildcard.")
    return "domain", stripped


@dataclass
class ScanOptions:
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    # Derived from what's present: domain | ip | cidr | mixed. Kept as an
    # explicit field (not recomputed ad hoc) because it's recorded on the run
    # (runs.target_kind) so "why does this run look like this" always has an
    # answer.
    target_kind: str = "domain"
    profile: str = DEFAULT_PROFILE
    flags: dict[str, bool] = field(default_factory=dict)
    rate_limit: int = 150
    threads: int = 50
    timeout: int = 10
    retries: int = 1
    subfinder: bool = True
    # Set once the user has seen the host count and accepted it. Absent, a scan
    # that expands past CONFIRM_ABOVE pauses instead of probing.
    approved_hosts: int = 0
    # A recorded acknowledgement, not a checkbox for show: scanning is an action
    # against someone's infrastructure.
    authorised: bool = False

    def as_dict(self) -> dict:
        return {
            "domains": self.domains, "ips": self.ips, "cidrs": self.cidrs,
            "target_kind": self.target_kind, "profile": self.profile,
            "flags": self.flags, "rate_limit": self.rate_limit,
            "threads": self.threads, "timeout": self.timeout,
            "retries": self.retries, "subfinder": self.subfinder,
            "authorised": self.authorised,
            "approved_hosts": self.approved_hosts,
        }


def parse(payload: dict) -> ScanOptions:
    """Validate a request from the browser. Raises `OptionError` on anything odd.

    Every numeric bound below is a real limit, not decoration: an unbounded rate
    limit against someone else's estate is a denial-of-service, and an unbounded
    domain list is a way to start a scan nobody can stop.
    """
    raw_targets = payload.get("targets", payload.get("domains")) or []
    if isinstance(raw_targets, str):
        raw_targets = re.split(r"[\s,]+", raw_targets)

    domains: list[str] = []
    ips: list[str] = []
    cidrs: list[str] = []
    for entry in raw_targets:
        raw = str(entry).strip()
        if not raw:
            continue
        kind, value = classify_target(raw)
        if kind == "domain" and value not in domains:
            domains.append(value)
        elif kind == "ip" and value not in ips:
            ips.append(value)
        elif kind == "cidr" and value not in cidrs:
            cidrs.append(value)

    if not (domains or ips or cidrs):
        raise OptionError(
            "Enter at least one domain, IP address, or address range to scan.")
    if len(domains) > MAX_DOMAINS:
        raise OptionError(
            f"{len(domains)} domains exceeds the {MAX_DOMAINS} ceiling. That "
            f"ceiling exists to catch a pasted-in file rather than to limit a real "
            f"portfolio — raise MAX_DOMAINS in frogscope/scan/options.py if you "
            f"genuinely have more.")
    if len(ips) > MAX_IPS:
        raise OptionError(
            f"{len(ips)} addresses exceeds the {MAX_IPS} ceiling for a pasted "
            f"list — use a CIDR range instead if you mean a whole block.")

    kinds_present = [k for k, present in
                     (("domain", domains), ("ip", ips), ("cidr", cidrs)) if present]
    target_kind = kinds_present[0] if len(kinds_present) == 1 else "mixed"

    profile = str(payload.get("profile") or DEFAULT_PROFILE)
    if profile not in PORT_PROFILES:
        raise OptionError(f"unknown port profile {profile!r}")

    requested = payload.get("flags") or {}
    if not isinstance(requested, dict):
        raise OptionError("flags must be an object")
    flags = {name: bool(requested.get(name, spec["default"]))
             for name, spec in FLAGS.items()}
    unknown = set(requested) - set(FLAGS)
    if unknown:
        # Refused rather than ignored: silently dropping a flag somebody thought
        # they had enabled would make the coverage report wrong.
        raise OptionError(f"unknown option(s): {', '.join(sorted(unknown))}")

    def bounded(key: str, default: int, low: int, high: int) -> int:
        try:
            value = int(payload.get(key, default))
        except (TypeError, ValueError):
            raise OptionError(f"{key} must be a whole number") from None
        if not low <= value <= high:
            raise OptionError(f"{key} must be between {low} and {high}")
        return value

    options = ScanOptions(
        domains=domains,
        ips=ips,
        cidrs=cidrs,
        target_kind=target_kind,
        profile=profile,
        flags=flags,
        rate_limit=bounded("rate_limit", 150, 1, 1000),
        threads=bounded("threads", 50, 1, 300),
        timeout=bounded("timeout", 10, 1, 60),
        retries=bounded("retries", 1, 0, 3),
        subfinder=bool(payload.get("subfinder", True)),
        authorised=bool(payload.get("authorised")),
        # Defaults to the ceiling, not 0: scans proceed without an interactive
        # "confirm before probing" pause. `len(hosts)` can never exceed
        # MAX_HOSTS (runner.py's hard ceiling raises ScanError first), so this
        # makes NeedsApproval's `approved_hosts < len(hosts)` permanently
        # false for any caller that doesn't explicitly pass a smaller value —
        # nothing in the UI does. The scheduler is unaffected: it already
        # sets `approved_hosts` explicitly before calling parse().
        approved_hosts=bounded("approved_hosts", MAX_HOSTS, 0, MAX_HOSTS),
    )

    if not options.authorised:
        raise OptionError(
            "Confirm you are authorised to scan these targets. This sends real "
            "traffic to real infrastructure.")
    return options


def subfinder_argv(binary: str, domain: str) -> list[str]:
    """Passive enumeration only.

    `-silent` keeps stdout to one hostname per line, which is what the caller
    parses. No brute force: that is a lot of traffic aimed at someone's DNS for a
    marginal gain.
    """
    return [binary, "-silent", "-all", "-d", domain]


def httpx_argv(binary: str, options: ScanOptions, *, input_path: str,
               output_path: str, ports_prescoped: bool = False) -> list[str]:
    """Build the httpx command as a list. Never a string, never via a shell.

    `ports_prescoped=True` means `input_path` already has one `host:port` per
    line (naabu found that port open) — omit `-ports` entirely. Confirmed
    against the real httpx binary: `-ports` does not merge with an embedded
    port, it OVERRIDES it — passing both silently throws away naabu's work
    and probes the whole profile again on top.
    """
    argv = [
        binary,
        "-list", input_path,
        "-csv",
        "-output", output_path,
    ]
    if not ports_prescoped:
        ports = PORT_PROFILES[options.profile]["ports"]
        argv += ["-ports", ",".join(str(p) for p in sorted(set(ports)))]
    argv += [
        "-status-code", "-content-length", "-title", "-web-server",
        "-cdn", "-cname", "-ip", "-location",
        "-rate-limit", str(options.rate_limit),
        "-threads", str(options.threads),
        "-timeout", str(options.timeout),
        "-retries", str(options.retries),
        "-no-color",
        "-silent",
    ]
    for name, enabled in options.flags.items():
        if enabled:
            argv.extend(FLAGS[name]["flag"])
    return argv


def naabu_argv(binary: str, options: ScanOptions, *, input_path: str) -> list[str]:
    """Scan `input_path` (one host/IP per line) for open ports, scoped to the
    same port list `httpx_argv` would otherwise probe blindly. Output is
    JSON lines, one per OPEN port only (confirmed against the real naabu
    binary: `{"host","ip","port","protocol","tls",...}`) — its own `tls`
    field is unreliable (seen `false` on a port confirmed serving HTTPS), so
    callers must not use it; TLS-capability is decided from httpx's own
    results instead (see `runner.py::_run_tlsx`).

    `-s c` (TCP connect, not raw SYN) is not a preference — this container
    runs with `cap_drop: ["ALL"]` (docker-compose.yml), and SYN scanning
    needs a capability that setup deliberately doesn't grant.
    """
    ports = PORT_PROFILES[options.profile]["ports"]
    return [
        binary, "-list", input_path,
        "-port", ",".join(str(p) for p in sorted(set(ports))),
        "-scan-type", "c",
        "-c", str(options.threads),
        "-json", "-silent", "-duc",
    ]


def dnsx_ptr_argv(binary: str, *, input_path: str) -> list[str]:
    """Reverse DNS on a list of IPs, one per line in `input_path`.

    A named endpoint is what the rest of the pipeline keys on
    (`loader._host_from` prefers a name over a bare address), so an IP or CIDR
    scan target resolves through this before anything is handed to httpx.

    `-resp-only` and `-j` combine fine (confirmed against real dnsx v1.2.2
    output — `-resp-only` only affects the plain-text path); kept together
    so the JSONL result always carries the full record.
    """
    return [binary, "-l", input_path, "-ptr", "-resp-only", "-j",
            "-silent", "-nc", "-duc"]


def mapcidr_expand_argv(binary: str, *, input_path: str) -> list[str]:
    """Expand one or more CIDR ranges (one per line in `input_path`) into
    individual addresses.

    mapcidr has NO `-json` output mode at all (confirmed against the real
    v1.1.97 binary) — this is plain one-address-per-line stdout, parsed with
    `.splitlines()`, never a JSON decoder. `-skip-base -skip-broadcast` drops
    the network/broadcast addresses, which nothing ever answers on — though
    confirmed against the real binary, `-skip-broadcast` is a literal
    "ends in .255" check, not a true broadcast-address calculation, so on a
    subnet narrower than a /24 (e.g. this function's own /30 test case) the
    real broadcast address can still come through. Harmless: httpx simply
    gets no response from it, same as any other dead address.
    """
    return [binary, "-cl", input_path, "-silent", "-duc",
            "-skip-base", "-skip-broadcast"]


def dnsx_resolve_argv(binary: str, *, input_path: str) -> list[str]:
    """Resolve a list of domains (one per line in `input_path`) to their A/AAAA
    records and CNAME chain — the domain->IP half of the core DNS/network
    analysis pass every scan runs.

    No `-asn`/`-cdn` here: `-asn` hits dnsx's own ASN lookup, which shares the
    same ProjectDiscovery-key dependency as asnmap and mapcidr's ASN input,
    and this release does not depend on that (see config/cloud_ranges.yaml).
    """
    return [binary, "-l", input_path, "-a", "-aaaa", "-cname", "-j",
            "-silent", "-nc", "-duc"]


def mapcidr_aggregate_argv(binary: str, *, input_path: str) -> list[str]:
    """Collapse a list of IPs/CIDRs (one per line in `input_path`) into the
    smallest set of CIDR blocks that covers them — reported in the Network
    view rather than probed, so it costs nothing to compute for every
    correlated scan."""
    return [binary, "-cl", input_path, "-aggregate", "-silent", "-duc"]


def tlsx_argv(binary: str, options: ScanOptions, *, input_path: str) -> list[str]:
    """Pull TLS certificate data for a list of hosts/IPs (one per line in
    `input_path`) — runs on every scan, same as the DNS/network analysis pass.

    Deliberately does NOT pass `-san`/`-cn`/`-so`/`-tv`/`-cipher`: confirmed
    against the real tlsx v1.2.2 binary, `-san`/`-cn` cannot be combined with
    ANY other probe flag ("san or cn flag cannot be used with other probes"),
    and — the reason this costs nothing — `-json` mode already returns every
    one of those fields regardless of which probe flags are passed, including
    zero of them. `-hash` needs `=` syntax (`-hash sha256`, space-separated,
    fails outright) — confirmed the hard way, see
    tests/fixtures/correlation/README.md. `-rps` derives SNI from reverse PTR,
    which is what makes probing a bare IP for a cert worth doing at all.
    """
    return [
        binary, "-l", input_path,
        "-ex", "-ss", "-mm", "-un", "-hash=sha256", "-jarm", "-rps",
        "-j", "-silent", "-nc", "-duc",
        "-timeout", str(options.timeout), "-retry", str(options.retries),
    ]


def manual_commands(profile: str = DEFAULT_PROFILE) -> list[dict]:
    """The commands to run this by hand, generated from the same tables the
    built-in scanner uses.

    Derived rather than written out, so the guide cannot drift from what the tool
    actually runs — a copied command that produces a CSV missing `-body-preview`
    silently disables a set of checks.
    """
    defaults = ScanOptions(
        domains=["example.com"], profile=profile,
        flags={name: spec["default"] for name, spec in FLAGS.items()})
    httpx = httpx_argv("httpx", defaults, input_path="hosts.txt",
                       output_path="scan.csv")
    return [
        {
            "step": "Find the subdomains",
            "command": " ".join(subfinder_argv("subfinder", "example.com"))
                       + " -o hosts.txt",
            "note": "Passive sources only. Repeat for each domain you own, "
                    "appending with -o.",
        },
        {
            "step": "Probe what answers",
            "command": " ".join(httpx),
            "note": "The flags matter: -tls-grab, -favicon and -body-preview each "
                    "unlock checks that are otherwise skipped.",
        },
        {
            "step": "Upload scan.csv",
            "command": "",
            "note": "Drop it below. Or from a terminal: "
                    "frogscope ingest scan.csv --project <name>",
        },
    ]


def catalogue() -> dict:
    """What the UI offers. Derived from the same tables that build argv, so the
    form cannot drift from what is actually runnable."""
    return {
        "profiles": {
            key: {"label": spec["label"], "note": spec["note"],
                  "port_count": len(set(spec["ports"]))}
            for key, spec in PORT_PROFILES.items()
        },
        "default_profile": DEFAULT_PROFILE,
        "target_kinds": list(TARGET_KINDS),
        # Definition order, which is deliberate: most useful first.
        "flag_order": list(FLAGS),
        # The equivalent commands, for anyone who would rather run it themselves.
        "manual": manual_commands(),
        "flags": {
            key: {"label": spec["label"], "note": spec["note"],
                  "default": spec["default"]}
            for key, spec in FLAGS.items()
        },
        "limits": {
            "max_domains": MAX_DOMAINS,
            "max_ips": MAX_IPS,
            "max_cidr_addresses": MAX_CIDR_ADDRESSES,
            "max_hosts": MAX_HOSTS,
            "max_san_discovered": MAX_SAN_DISCOVERED,
            "confirm_above": CONFIRM_ABOVE,
            # Roughly how long enumeration takes, so a large list can warn rather
            # than appear to hang.
            "seconds_per_domain": 30,
            "enumeration_workers": ENUMERATION_WORKERS,
            "rate_limit": [1, 1000],
            "threads": [1, 300],
            "timeout": [1, 60],
            "retries": [0, 3],
        },
    }
