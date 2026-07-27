"""Run subfinder, then httpx, then hand the CSV to the normal ingest path.

**This is the only part of Frogscope that generates traffic to someone else's
infrastructure.** Analysis stays offline: the output of this module is a CSV, and
from there everything follows exactly the same path as a file you uploaded. That
matters for trust — a scan and an upload produce identical runs, so nothing about
the analysis depends on how the data arrived.

Design notes:

* Subprocesses are started with an argv list and never a shell. See `options.py`.
* Progress is reported by counting lines, because neither tool emits structured
  progress. Approximate but honest: the phase and the counts are real.
* Cancellation terminates the process group, since httpx spawns workers.
* A scan that finds nothing is a result, not an error, and says so.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import os
import signal
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from . import options as opts
from . import tools

# Long enough for a wide scan of a large estate, short enough that a wedged
# process does not hold a slot forever.
DEFAULT_TIMEOUT = 6 * 60 * 60


class ScanError(RuntimeError):
    pass


class EmptyResult(RuntimeError):
    """The scan ran to completion and genuinely found nothing to probe or
    nothing that answered — a domain with no live subdomains, an address
    range that resolved to nothing, a host list that probed clean. Distinct
    from `ScanError`: nothing here needs fixing on this machine, so the UI
    should say so calmly rather than showing the same red "scan failed" it
    shows for a missing tool or a crashed subprocess."""


class Cancelled(RuntimeError):
    pass


class NeedsApproval(RuntimeError):
    """Enumeration found more hosts than the caller has agreed to probe.

    Raised between the passive and active phases. Enumeration has already happened
    and cost nobody anything; probing is the part that sends traffic, so the
    decision belongs here — once the size is known — rather than in a number typed
    before anyone knew how big the estate was.
    """

    def __init__(self, hosts: list[str]):
        super().__init__(f"{len(hosts)} hosts found — confirm before probing")
        self.hosts = hosts


@dataclass
class Progress:
    phase: str = "starting"
    message: str = ""
    hosts_found: int = 0
    hosts_total: int = 0
    endpoints_found: int = 0
    domains_done: int = 0
    domains_total: int = 0
    started_at: float = field(default_factory=time.time)
    log: list[str] = field(default_factory=list)

    def note(self, line: str, *, keep: int = 200) -> None:
        self.log.append(line)
        # A bounded log: a wide scan emits tens of thousands of lines and the UI
        # only ever shows the tail.
        if len(self.log) > keep:
            del self.log[: len(self.log) - keep]

    def as_dict(self) -> dict:
        return {
            "phase": self.phase,
            "message": self.message,
            "hosts_found": self.hosts_found,
            "hosts_total": self.hosts_total,
            "endpoints_found": self.endpoints_found,
            "domains_done": self.domains_done,
            "domains_total": self.domains_total,
            "elapsed": int(time.time() - self.started_at),
            "log": self.log[-40:],
        }


class ScanRun:
    """One scan. Owns its subprocesses so it can be cancelled."""

    def __init__(self, options: opts.ScanOptions, *, workdir: Path | None = None,
                 on_progress: Callable[[Progress], None] | None = None):
        self.options = options
        self.progress = Progress(domains_total=len(options.domains))
        self.on_progress = on_progress
        # Sidecar files produced alongside the httpx CSV — currently just the
        # opt-in correlation JSON, if that step ran. A scan and an upload
        # still produce identical runs: an upload simply has no sidecar, and
        # every v2 field degrades to empty rather than breaking.
        self.artifacts: dict[str, Path] = {}
        # ip -> ptr hostname, populated by `_resolve_ip_cidr_targets` for
        # every IP/CIDR target that has a reverse record. DNS/network
        # correlation reuses this instead of asking dnsx the same question
        # twice.
        self._ptr_cache: dict[str, str] = {}
        self._cancelled = threading.Event()
        # A SET, not a single slot: enumeration runs several subfinder processes at
        # once, and a single-process field would leave every worker but the last
        # one running after a cancel.
        self._processes: set[subprocess.Popen] = set()
        self._lock = threading.Lock()
        self._workdir = workdir
        self._owns_workdir = workdir is None
        self._probe_done = threading.Event()

    # ── lifecycle ───────────────────────────────────────────────────────────

    def cancel(self) -> None:
        self._cancelled.set()
        with self._lock:
            running = list(self._processes)
        for process in running:
            if process.poll() is not None:
                continue
            # The whole group: these tools run worker processes, and killing only
            # the parent leaves them querying or probing.
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                process.terminate()

    def _check_cancelled(self) -> None:
        if self._cancelled.is_set():
            raise Cancelled("scan cancelled")

    def _emit(self, phase: str, message: str) -> None:
        self.progress.phase = phase
        self.progress.message = message
        self.progress.note(message)
        if self.on_progress:
            self.on_progress(self.progress)

    # ── the pipeline ────────────────────────────────────────────────────────

    def run(self) -> Path:
        """Execute the scan and return the path to the httpx CSV."""
        missing = tools.missing()
        needed = missing if self.options.subfinder else [
            m for m in missing if m != "subfinder"]
        if needed:
            raise ScanError(
                f"{' and '.join(needed)} not found on this machine. "
                f"Use the Docker image, which bundles both, or install them with: "
                + "; ".join(tools.HINTS[m] for m in needed))

        directory = Path(self._workdir or tempfile.mkdtemp(prefix="frogscope-scan-"))
        directory.mkdir(parents=True, exist_ok=True)
        hosts_file = directory / "hosts.txt"
        csv_file = directory / "scan.csv"

        hosts = self._resolve_targets(directory)
        if not hosts:
            if self.options.domains:
                raise EmptyResult(
                    "Subdomain enumeration found nothing for "
                    f"{', '.join(self.options.domains)}. Either the domain "
                    f"isn't live, has no discoverable subdomains, or "
                    f"enumeration's passive sources came up empty — try "
                    f"unticking enumeration to probe the domain itself "
                    f"instead.")
            raise EmptyResult(
                "The address(es) or range(s) given resolved to nothing — "
                "there's nothing there to probe.")

        if (len(hosts) > opts.CONFIRM_ABOVE
                and self.options.approved_hosts < len(hosts)):
            self._emit("awaiting_approval",
                       f"Found {len(hosts)} hosts. Probing them means sending "
                       f"traffic to every one — confirm to continue.")
            raise NeedsApproval(hosts)

        port_pairs = self._port_scan(directory, hosts)
        ports_prescoped = port_pairs is not None
        hosts_file.write_text(
            "\n".join(port_pairs if ports_prescoped else hosts) + "\n", encoding="utf-8")
        self._probe(hosts_file, csv_file, ports_prescoped=ports_prescoped)

        if not csv_file.exists() or not csv_file.stat().st_size:
            raise EmptyResult(
                f"httpx probed {len(hosts)} host(s) and none answered. Most "
                f"often this just means nothing is live on the ports this "
                f"profile checks — if you expected a response, check network "
                f"egress from here and that the target is actually reachable.")

        # DNS/network analysis and TLS certificate reading are both core, not
        # opt-in — see `_correlate()`. Every scan gets all of it.
        correlation_path = directory / "correlation.json"
        tls_targets = _https_targets_from_csv(csv_file)
        self._correlate(directory, hosts, tls_targets, correlation_path)
        self.artifacts["correlation"] = correlation_path

        return csv_file

    def _enumerate(self) -> list[str]:
        """Passive subdomain enumeration across every domain.

        Concurrent, because subfinder takes roughly half a minute per domain and a
        real portfolio runs to hundreds — sequentially that is hours during which
        the UI looks hung. These are read-only queries to third-party passive
        sources, so a bounded pool is polite.
        """
        binary = tools.find("subfinder")
        domains = list(self.options.domains)
        found: set[str] = set()
        done = 0
        lock = threading.Lock()

        def enumerate_one(domain: str) -> set[str]:
            nonlocal done
            if self._cancelled.is_set():
                return set()
            names: set[str] = set()
            for line in self._stream(opts.subfinder_argv(binary, domain)):
                host = line.strip().lower()
                if host and "." in host and " " not in host:
                    names.add(host)
            # The domain itself is worth probing even if enumeration missed it.
            names.add(domain)

            with lock:
                nonlocal found
                found |= names
                done += 1
                self.progress.domains_done = done
                self.progress.hosts_found = len(found)
                total = len(found)
            self._emit("enumerating",
                       f"{done} of {len(domains)} domains · {total} hosts so far")
            return names

        workers = max(1, min(opts.ENUMERATION_WORKERS, len(domains)))
        self._emit("enumerating",
                   f"Finding subdomains of {len(domains)} "
                   f"domain{'' if len(domains) == 1 else 's'}"
                   + (f", {workers} at a time" if workers > 1 else ""))

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(enumerate_one, d) for d in domains]
            for future in as_completed(futures):
                if self._cancelled.is_set():
                    for f in futures:
                        f.cancel()
                    break
                try:
                    future.result()
                except ScanError as exc:
                    # One domain failing is not the scan failing. A portfolio of
                    # hundreds will contain a few that error, and discarding every
                    # other result for one of them would be absurd.
                    self.progress.note(f"! {exc}")

        self._check_cancelled()
        if len(found) > opts.MAX_HOSTS:
            raise ScanError(
                f"enumeration returned {len(found)} hosts, more than the "
                f"{opts.MAX_HOSTS} this will probe in one scan")
        return sorted(found)

    def _resolve_targets(self, directory: Path) -> list[str]:
        """Turn whatever the scan was pointed at — domains, bare IPs, CIDR
        ranges, or a mix — into the flat host list httpx probes.

        Domains go through the existing enumeration path unchanged. IPs and
        CIDR ranges are new (v2): a CIDR expands to individual addresses via
        mapcidr, then every address resolves through dnsx PTR so a named
        endpoint reaches httpx wherever one exists — a named endpoint is what
        the rest of the pipeline keys on (`loader._host_from` prefers a name
        over a bare address). An address with no reverse record is still
        probed, just by the address itself.
        """
        domain_hosts: list[str] = []
        if self.options.domains:
            domain_hosts = (self._enumerate() if self.options.subfinder
                            else list(self.options.domains))

        ip_cidr_hosts: list[str] = []
        if self.options.ips or self.options.cidrs:
            ip_cidr_hosts = self._resolve_ip_cidr_targets(directory)

        return sorted(set(domain_hosts) | set(ip_cidr_hosts))

    def _resolve_ip_cidr_targets(self, directory: Path) -> list[str]:
        addresses: list[str] = list(self.options.ips)

        if self.options.cidrs:
            binary = tools.find("mapcidr")
            if not binary:
                raise ScanError(
                    "mapcidr not found on this machine, and this scan targets "
                    f"one or more address ranges. Use the Docker image, which "
                    f"bundles it, or install it with: {tools.HINTS['mapcidr']}")
            cidr_file = directory / "targets_cidr.txt"
            cidr_file.write_text("\n".join(self.options.cidrs) + "\n",
                                 encoding="utf-8")
            self._emit("resolving_targets",
                       f"Expanding {len(self.options.cidrs)} address range(s)")
            expanded = {
                line.strip() for line in
                self._stream(opts.mapcidr_expand_argv(binary, input_path=str(cidr_file)))
                if line.strip()
            }
            addresses.extend(sorted(expanded))
            if len(addresses) > opts.MAX_HOSTS:
                raise ScanError(
                    f"the expanded address ranges total {len(addresses)} "
                    f"addresses, more than the {opts.MAX_HOSTS} this will "
                    f"probe in one scan")

        addresses = sorted(set(addresses))
        if not addresses:
            return []

        binary = tools.find("dnsx")
        if not binary:
            # Not fatal: an address with no reverse-DNS lookup is still a
            # perfectly probeable target, just by the address itself.
            self.progress.note(
                "dnsx not found — probing addresses directly, without "
                "reverse-DNS names")
            return addresses

        ip_file = directory / "targets_ip.txt"
        ip_file.write_text("\n".join(addresses) + "\n", encoding="utf-8")
        self._emit("resolving_targets",
                   f"Looking up reverse DNS for {len(addresses)} address(es)")

        ptr_by_ip: dict[str, str] = {}
        for line in self._stream(opts.dnsx_ptr_argv(binary, input_path=str(ip_file))):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            ip = record.get("host")
            ptr = record.get("ptr") or []
            if ip and ptr:
                ptr_by_ip[ip] = str(ptr[0]).rstrip(".").lower()

        # Stashed rather than discarded: the correlate step's dns_reverse
        # collector reuses this instead of looking the same IPs up again.
        self._ptr_cache.update(ptr_by_ip)
        return sorted({ptr_by_ip.get(ip, ip) for ip in addresses})

    def _port_scan(self, directory: Path, hosts: list[str]) -> list[str] | None:
        """Scan `hosts` for open ports (naabu) so httpx only probes
        confirmed-open `host:port` pairs instead of every host across the
        whole port profile. Returns `None` (not an empty list) when naabu
        can't run at all — the caller's signal to fall back to today's
        behaviour: probe `hosts` directly, letting httpx's own `-ports`
        flag try the whole profile. An empty list is a real result (naabu
        ran, found nothing open) and stays distinct from that fallback.
        """
        binary = tools.find("naabu")
        if not binary:
            self.progress.note(
                "naabu not found — probing every host across the whole "
                "port profile, without a fast open-port pre-filter")
            return None

        path = directory / "targets_ports.txt"
        path.write_text("\n".join(hosts) + "\n", encoding="utf-8")
        self._emit("port_scanning", f"Scanning {len(hosts)} host(s) for open ports")

        pairs: set[str] = set()
        try:
            for line in self._stream(opts.naabu_argv(binary, self.options, input_path=str(path))):
                rec = _parse_json_line(line)
                if rec is None:
                    continue
                host = rec.get("host") or rec.get("ip")
                port = rec.get("port")
                if host and port:
                    pairs.add(f"{host}:{port}")
        except ScanError as exc:
            self.progress.note(f"! naabu: {exc} — probing every host across "
                               f"the whole port profile instead")
            return None

        return sorted(pairs)

    def _correlate(self, directory: Path, hosts: list[str], tls_targets: list[str],
                   out_path: Path) -> None:
        """DNS and network analysis (dnsx, mapcidr) and TLS certificate
        reading (tlsx). Always runs, for every target kind and every scan —
        an IP/CIDR-only scan gets exactly the same analysis a domain scan
        does, nothing here is gated behind an opt-in checkbox. Writes one
        self-describing JSON sidecar alongside the httpx CSV. A tool being
        absent or a single step failing is recorded here and skipped — never
        allowed to fail a scan that has already succeeded at probing.
        """
        sidecar: dict = {
            "schema": 1,
            "reference_time": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.progress.started_at)),
            "collectors": {}, "dns": [], "ptr": [], "tls": [],
            "cidrs": {"aggregated": []}, "scan_cidrs": list(self.options.cidrs),
            "scan_domains": list(self.options.domains),
        }
        self._emit("correlating", "Analysing DNS and network data")

        domain_like = [h for h in hosts if not _is_ip(h)]
        # Includes `self._ptr_cache` keys, not just IP-shaped `hosts`/
        # `options.ips`: a CIDR-expanded address that got renamed to a PTR
        # hostname with no forward A record of its own (a generic ISP/
        # hosting reverse-DNS label, e.g. `*.static.provider.net`) is neither
        # IP-shaped in `hosts` nor recoverable via `dnsx_ips` — without this,
        # its already-fetched PTR record silently never reaches the sidecar.
        target_ips = ({h for h in hosts if _is_ip(h)} | set(self.options.ips)
                      | set(self._ptr_cache))
        dnsx_binary = tools.find("dnsx")
        dnsx_ips: set[str] = set()
        dnsx_inputs = dnsx_outputs = 0
        dnsx_ran = False
        dnsx_skip = ""

        if not dnsx_binary:
            dnsx_skip = f"dnsx not found — {tools.HINTS['dnsx']}"
        else:
            if domain_like:
                path = directory / "correlate_domains.txt"
                path.write_text("\n".join(domain_like) + "\n", encoding="utf-8")
                try:
                    for line in self._stream(
                            opts.dnsx_resolve_argv(dnsx_binary, input_path=str(path))):
                        rec = _parse_json_line(line)
                        if rec is None:
                            continue
                        sidecar["dns"].append(rec)
                        dnsx_outputs += 1
                        dnsx_ips.update(str(ip) for ip in (rec.get("a") or []))
                        dnsx_ips.update(str(ip) for ip in (rec.get("aaaa") or []))
                    dnsx_inputs += len(domain_like)
                    dnsx_ran = True
                except ScanError as exc:
                    dnsx_skip = str(exc)

            reverse_ips = sorted(dnsx_ips | target_ips)
            if reverse_ips:
                # Target-resolution already PTR-looked-up every bare IP/CIDR
                # target before probing (`_resolve_ip_cidr_targets`) — reuse
                # that answer instead of asking dnsx the same question again.
                cached = [ip for ip in reverse_ips if ip in self._ptr_cache]
                to_query = [ip for ip in reverse_ips if ip not in self._ptr_cache]
                for ip in cached:
                    sidecar["ptr"].append({"host": ip, "ptr": [self._ptr_cache[ip]]})
                    dnsx_outputs += 1
                dnsx_inputs += len(cached)
                if cached:
                    dnsx_ran = True
                if to_query:
                    path = directory / "correlate_ips.txt"
                    path.write_text("\n".join(to_query) + "\n", encoding="utf-8")
                    try:
                        for line in self._stream(
                                opts.dnsx_ptr_argv(dnsx_binary, input_path=str(path))):
                            rec = _parse_json_line(line)
                            if rec is None:
                                continue
                            sidecar["ptr"].append(rec)
                            dnsx_outputs += 1
                        dnsx_inputs += len(to_query)
                        dnsx_ran = True
                    except ScanError as exc:
                        dnsx_skip = dnsx_skip or str(exc)

        sidecar["collectors"]["dnsx"] = {
            "version": tools.describe("dnsx").version, "ran": dnsx_ran,
            "skip_reason": dnsx_skip, "inputs": dnsx_inputs, "outputs": dnsx_outputs,
        }

        sidecar["collectors"]["mapcidr"] = self._run_mapcidr_aggregate(
            directory, sorted(set(self.options.cidrs) | dnsx_ips | target_ips), sidecar)

        sidecar["collectors"]["tlsx"] = self._run_tlsx(directory, tls_targets, sidecar)

        # Always on: newly-discovered cert-SAN names are surfaced downstream
        # (ingest/correlate.py) — still recorded, not auto-probed, so probing
        # an unnamed name stays consent-based via the next scan's approval.
        sidecar["cert_discovery_enabled"] = True

        # Hostnames that exist ONLY because a bare IP/CIDR target had no name
        # of its own and got one via reverse-DNS fallback — see
        # `ingest/correlate.py::domains_from_records` for why these must not
        # silently count as "ours".
        sidecar["ptr_resolved_hosts"] = sorted(set(self._ptr_cache.values()))

        out_path.write_text(json.dumps(sidecar), encoding="utf-8")

    def _run_mapcidr_aggregate(self, directory: Path, cidr_input: list[str],
                               sidecar: dict) -> dict:
        binary = tools.find("mapcidr")
        if not binary:
            return {"version": "", "ran": False,
                    "skip_reason": f"mapcidr not found — {tools.HINTS['mapcidr']}",
                    "inputs": 0, "outputs": 0}
        if not cidr_input:
            return {"version": tools.describe("mapcidr").version, "ran": False,
                    "skip_reason": "nothing to aggregate", "inputs": 0, "outputs": 0}
        path = directory / "correlate_cidrs.txt"
        path.write_text("\n".join(cidr_input) + "\n", encoding="utf-8")
        try:
            aggregated = [
                line.strip() for line in
                self._stream(opts.mapcidr_aggregate_argv(binary, input_path=str(path)))
                if line.strip()
            ]
        except ScanError as exc:
            return {"version": tools.describe("mapcidr").version, "ran": False,
                    "skip_reason": str(exc), "inputs": len(cidr_input), "outputs": 0}
        sidecar["cidrs"]["aggregated"] = aggregated
        return {"version": tools.describe("mapcidr").version, "ran": True,
                "skip_reason": "", "inputs": len(cidr_input), "outputs": len(aggregated)}

    def _run_tlsx(self, directory: Path, tls_targets: list[str], sidecar: dict) -> dict:
        """`tls_targets` is httpx's own live, `scheme=="https"` `host:port`
        pairs (`_https_targets_from_csv`) — not the original target list.
        httpx already found out for real which host:ports speak TLS, which
        is more accurate than guessing from a port number or naabu's own
        (unreliable — confirmed against the real binary) `tls` field.
        """
        binary = tools.find("tlsx")
        if not binary:
            return {"version": "", "ran": False,
                    "skip_reason": f"tlsx not found — {tools.HINTS['tlsx']}",
                    "inputs": 0, "outputs": 0}
        if not tls_targets:
            return {"version": tools.describe("tlsx").version, "ran": False,
                    "skip_reason": "no live https endpoints to read", "inputs": 0, "outputs": 0}
        path = directory / "correlate_tls.txt"
        path.write_text("\n".join(tls_targets) + "\n", encoding="utf-8")
        outputs = 0
        try:
            for line in self._stream(opts.tlsx_argv(binary, self.options, input_path=str(path))):
                rec = _parse_json_line(line)
                if rec is None:
                    continue
                sidecar["tls"].append(rec)
                outputs += 1
        except ScanError as exc:
            return {"version": tools.describe("tlsx").version, "ran": False,
                    "skip_reason": str(exc), "inputs": len(tls_targets), "outputs": outputs}
        return {"version": tools.describe("tlsx").version, "ran": True,
                "skip_reason": "", "inputs": len(tls_targets), "outputs": outputs}

    def _probe(self, hosts_file: Path, csv_file: Path, *, ports_prescoped: bool = False) -> None:
        binary = tools.find("httpx")
        argv = opts.httpx_argv(binary, self.options,
                               input_path=str(hosts_file),
                               output_path=str(csv_file),
                               ports_prescoped=ports_prescoped)
        total = sum(1 for _ in hosts_file.open(encoding="utf-8"))
        self.progress.hosts_total = total
        self._emit("probing",
                   f"Probing {total} open host:port pair(s) found by naabu"
                   if ports_prescoped else
                   f"Probing {total} host(s) on the "
                   f"{opts.PORT_PROFILES[self.options.profile]['label']} profile")

        # httpx writes results to the output file; with -silent it prints nothing
        # to stdout. So progress comes from watching the file grow, which is the
        # only signal there is.
        watcher = threading.Thread(target=self._watch_output, args=(csv_file,),
                                   daemon=True)
        watcher.start()
        failure: ScanError | None = None
        try:
            for _line in self._stream(argv):
                pass
        except ScanError as exc:
            # httpx exiting non-zero does not mean it produced nothing. Keep what
            # it wrote and report the error as a warning — discarding thousands of
            # good rows because of one unsupported flag is the wrong trade.
            failure = exc
        finally:
            self._probe_done.set()
            watcher.join(timeout=3)

        written = _count_rows(csv_file)
        if failure is not None and not written:
            raise failure
        if failure is not None:
            self.progress.note(f"! {failure} — keeping the {written} row(s) it "
                               f"did write")

        self.progress.endpoints_found = _count_rows(csv_file)
        self._emit("probing",
                   f"Probe finished — {self.progress.endpoints_found} live "
                   f"endpoint(s) across {total} host(s)")

    def _watch_output(self, csv_file: Path) -> None:
        """Report progress by counting rows written so far."""
        while not self._probe_done.wait(2.0):
            count = _count_rows(csv_file)
            if count != self.progress.endpoints_found:
                self.progress.endpoints_found = count
                self._emit("probing", f"{count} live endpoint(s) so far")

    def _stream(self, argv: list[str]):
        """Run a command, yielding stdout lines. No shell, ever."""
        self._check_cancelled()
        try:
            process = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                # Its own process group, so cancellation reaches the workers.
                start_new_session=True,
            )
        except OSError as exc:
            raise ScanError(f"could not start {argv[0]}: {exc}") from exc

        with self._lock:
            self._processes.add(process)

        stderr_tail: list[str] = []

        def drain_stderr() -> None:
            for line in process.stderr or ():
                text = line.strip()
                if text:
                    stderr_tail.append(text)
                    del stderr_tail[:-20]

        watcher = threading.Thread(target=drain_stderr, daemon=True)
        watcher.start()

        try:
            for line in process.stdout or ():
                if self._cancelled.is_set():
                    break
                yield line
        finally:
            if process.stdout:
                process.stdout.close()
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
            watcher.join(timeout=2)
            with self._lock:
                self._processes.discard(process)

        self._check_cancelled()
        if process.returncode not in (0, None):
            detail = "; ".join(stderr_tail[-3:]) or "no error output"
            self._last_error = f"{Path(argv[0]).name} exited {process.returncode}: {detail}"
            raise ScanError(self._last_error)


def _count_rows(csv_file: Path) -> int:
    """Data rows in a partially-written CSV. Cheap, and tolerant of a torn write."""
    try:
        with csv_file.open("rb") as fh:
            return max(0, sum(1 for _ in fh) - 1)
    except (OSError, ValueError):
        return 0


def _https_targets_from_csv(csv_file: Path) -> list[str]:
    """`host:port` for every row httpx actually found live over HTTPS —
    what tlsx should read certificates from, rather than guessing from a
    port number or re-probing hosts httpx already confirmed dead. Column
    names (`host`, `port`, `scheme`) confirmed against real httpx CSV
    output, not guessed from its docs."""
    pairs: set[str] = set()
    try:
        with csv_file.open(encoding="utf-8", errors="replace", newline="") as fh:
            for row in csv.DictReader(fh):
                if (row.get("scheme") or "").strip().lower() != "https":
                    continue
                host, port = row.get("host"), row.get("port")
                if host and port:
                    pairs.add(f"{host}:{port}")
    except (OSError, csv.Error):
        return []
    return sorted(pairs)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _parse_json_line(line: str) -> dict | None:
    """One JSONL line from dnsx/tlsx, or None for a blank/unparsable line —
    tolerant on purpose, since a single malformed line from a bulk tool run
    should not lose every other line around it."""
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except ValueError:
        return None
