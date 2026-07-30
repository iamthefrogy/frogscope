# syntax=docker/dockerfile:1
# The line above pins the BuildKit frontend explicitly. Without it, a host
# with an older Docker CLI or DOCKER_BUILDKIT=0 falls back to the legacy
# builder, which does not understand `--mount=type=cache` below and fails
# the parse outright — this line guarantees BuildKit runs regardless of the
# host's default.
#
# Frogscope, with the scanners it drives.
#
# Three stages: two Go builders (one pure-Go/Alpine for everything that can be
# a fully static binary, one Debian-based just for naabu, which can't be —
# see that stage for why), then a slim Python image gets only the six
# resulting binaries, nothing else from either toolchain. The final image
# carries no Go compiler, which keeps it small and removes a large amount of
# attack surface from a container that is, by design, allowed to make
# outbound connections.

# ── Stage 1: build the pure-Go scanners ─────────────────────────────────────
# CGO_ENABLED=0 everywhere in this stage: a fully static binary is portable
# across any base image, which is what lets this Alpine build stage feed a
# completely different (Debian, stage 3) runtime image with no compatibility
# concern. Do not add CGO to anything built here — see naabu's stage below
# for what breaks when a tool needs it.
#
# 1.26+ required: httpx v1.10.0's go.mod pins `go 1.26` (mapcidr v1.1.97 only
# needed 1.24.0), and go install refuses to build against an older toolchain
# (GOTOOLCHAIN=local, no auto-upgrade in this image) — confirmed the hard way
# against a real build, same as the mapcidr bump before it.
FROM golang:1.26-alpine AS scanners

RUN apk add --no-cache git ca-certificates

# GOSUMDB=off: skip sum.golang.org checksum verification. That lookup is a
# frequent source of build flakes on fresh hosts (HTTP/2 stream resets,
# corporate proxies) even though the same build succeeds elsewhere once its
# module cache is warm. Versions above are already pinned, so the checksum
# check is not the thing guarding supply-chain integrity here.
# GOPROXY fallback: if proxy.golang.org itself is unreachable (corporate
# network, restrictive firewall), fall back to fetching straight from the
# module's VCS instead of failing the build outright.
ENV GOSUMDB=off \
    GOPROXY=https://proxy.golang.org,direct

# Pinned. An unpinned `@latest` means the image silently changes behaviour between
# builds, and a scanner that behaves differently makes a run-over-run comparison
# meaningless. Bump these deliberately.
#
# Do not go below httpx v1.7: earlier CSV output omits the `timestamp` column, and
# the run key and timeline ordering are derived from the scan's own timestamps.
# v1.7.0 ITSELF must not be used, though — confirmed by actually building that
# exact tag: its CSV writer emits list/object columns (`tech`, `a`, `aaaa`,
# `cpe`, ...) as raw Go struct/slice dumps (`[Google Tag Manager Gutenberg]`)
# instead of JSON arrays (`["Google Tag Manager","Gutenberg"]`), and drops the
# `host_ip` column entirely, repurposing `host` to hold the IP instead of the
# hostname. `ingest/loader.py`'s `parse_json_array()` can't parse that format,
# so every list/object field (technologies, CPEs, WordPress plugins, DNS
# records) silently comes back empty — no error, no warning, just quietly
# missing data. v1.10.0 is confirmed correct (JSON arrays, `host`/`host_ip`
# both present) via the identical `go install` build used here.
ARG SUBFINDER_VERSION=v2.6.6
ARG HTTPX_VERSION=v1.10.0
# dnsx/mapcidr/tlsx (v2): DNS/network analysis and TLS certificate reading,
# both unconditional now. Pinned to the exact versions the field names in
# frogscope/ingest/correlate.py were verified against — see
# tests/fixtures/correlation/README.md before bumping any of the three; a
# version bump can silently change field casing or flag behaviour (both
# happened during development of this feature).
ARG DNSX_VERSION=v1.2.2
ARG MAPCIDR_VERSION=v1.1.97
ARG TLSX_VERSION=v1.2.2

# Each install retries up to 5x on failure. A dropped HTTP/2 stream to the
# module proxy (the exact failure this was built to survive) is transient —
# one retry a few seconds later almost always succeeds, so a fresh host on a
# flaky network doesn't need a full `docker build` re-run to get past it.
RUN --mount=type=cache,target=/root/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -e; \
    for pkg in \
      github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION} \
      github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION} \
      github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VERSION} \
      github.com/projectdiscovery/mapcidr/cmd/mapcidr@${MAPCIDR_VERSION} \
      github.com/projectdiscovery/tlsx/cmd/tlsx@${TLSX_VERSION} \
    ; do \
      n=0; \
      until CGO_ENABLED=0 go install -trimpath -ldflags="-s -w" "$pkg"; do \
        n=$((n + 1)); \
        if [ "$n" -ge 5 ]; then echo "giving up on $pkg after $n attempts" >&2; exit 1; fi; \
        echo "go install $pkg failed, retry $n/5 in 5s" >&2; \
        sleep 5; \
      done; \
    done

# ── Stage 2: build naabu — needs its own builder ────────────────────────────
# naabu links against libpcap (gopacket/pcap) and cannot build with
# CGO_ENABLED=0 at all — confirmed the hard way against a real build, a
# pure-Go attempt fails outright with "undefined: pcapErrorNotActivated" and
# a dozen similar linker errors. CGO means a dynamically-linked binary tied
# to whatever libc built it, so it CANNOT come from the Alpine (musl) stage
# above — the runtime stage below is Debian (glibc), and an Alpine-built CGO
# binary will not run there at all. This stage uses a Debian-based Go image
# specifically so naabu's glibc linkage matches the runtime stage.
FROM golang:1.24-bookworm AS naabu-builder

# apt-get update retries: mirror hiccups on a fresh host are the same class
# of flake as the go module proxy above.
RUN for i in 1 2 3 4 5; do apt-get update && break || sleep 5; done \
 && apt-get install -y --no-install-recommends libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

# See the scanners stage above for why GOSUMDB/GOPROXY are set here too.
ENV GOSUMDB=off \
    GOPROXY=https://proxy.golang.org,direct

# naabu: the open-port pre-filter ahead of httpx/tlsx. Pinned to the version
# `naabu_argv()`/`_port_scan()` were verified against a real install.
ARG NAABU_VERSION=v2.3.5

# Retries up to 5x — see the scanners stage above for why.
RUN --mount=type=cache,target=/root/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -e; \
    n=0; \
    until CGO_ENABLED=1 go install -trimpath -ldflags="-s -w" \
      github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION}; do \
      n=$((n + 1)); \
      if [ "$n" -ge 5 ]; then echo "giving up on naabu after $n attempts" >&2; exit 1; fi; \
      echo "go install naabu failed, retry $n/5 in 5s" >&2; \
      sleep 5; \
    done

# ── Stage 3: the application ────────────────────────────────────────────────
FROM python:3.12-slim AS app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    FROGSCOPE_CONFIG_DIR=/app/config \
    FROGSCOPE_DATA_DIR=/data

# ca-certificates so the scanners can validate TLS. libpcap0.8 is the
# runtime counterpart to naabu-builder's libpcap-dev — naabu dynamically
# links against it, so it must be present here even though nothing else in
# this image touches it.
RUN for i in 1 2 3 4 5; do apt-get update && break || sleep 5; done \
 && apt-get install -y --no-install-recommends ca-certificates libpcap0.8 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=scanners      /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=scanners      /go/bin/httpx     /usr/local/bin/httpx
COPY --from=scanners      /go/bin/dnsx      /usr/local/bin/dnsx
COPY --from=scanners      /go/bin/mapcidr   /usr/local/bin/mapcidr
COPY --from=scanners      /go/bin/tlsx      /usr/local/bin/tlsx
COPY --from=naabu-builder /go/bin/naabu     /usr/local/bin/naabu

WORKDIR /app

# Dependencies before source, so a code change does not re-resolve them.
COPY pyproject.toml README.md ./
COPY frogscope ./frogscope
RUN pip install .

COPY config ./config
COPY examples ./examples

# Runs unprivileged. Scanning needs no elevated capability, and a container that
# reaches the internet should not be root.
RUN useradd --create-home --uid 10001 frogscope \
 && mkdir -p /data \
 && chown -R frogscope:frogscope /data /app
USER frogscope

# The database and archived scan files. Mount a volume or they vanish with the
# container.
VOLUME ["/data"]

EXPOSE 8099

# 0.0.0.0 inside the container only — compose publishes it to 127.0.0.1 on the
# host, so it is still not reachable from the network.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8099/healthz')"

ENTRYPOINT ["frogscope"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8099"]
