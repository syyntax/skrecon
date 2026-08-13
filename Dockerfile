# birdseye / skrecon — reproducible environment bundling the external recon tools.
#
# The Python core is stdlib-only; this image adds the C/Go/Ruby binaries the active
# and some passive modules orchestrate, so an engagement runs identically anywhere.
# Pin tool versions in a real build; @latest is used here for clarity.

# ---- Stage 1: fetch the ProjectDiscovery / Go tools ----
# These are pulled through the Go module proxy. A "proxy.golang.org ... connection
# reset by peer" failure is a NETWORK issue reaching the proxy, not a Dockerfile bug.
# The retry loop rides out transient resets; GOPROXY is overridable for restricted
# networks, for example:
#   docker build --build-arg GOPROXY=direct .                  # straight from GitHub
#   docker build --build-arg HTTPS_PROXY=http://host:8080 .    # behind a corporate proxy
FROM golang:1.22-bookworm AS gotools
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}
# Pin versions in a real build (e.g. subfinder@v2.6.6); @latest is used here for clarity.
RUN set -eu; \
    retry() { for i in 1 2 3 4 5; do "$@" && return 0; \
        echo "attempt $i failed; retrying in 10s..."; sleep 10; done; return 1; }; \
    retry go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest; \
    retry go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest; \
    retry go install github.com/sensepost/gowitness@latest

# ---- Stage 2: runtime ----
FROM python:3.11-slim-bookworm

# System recon tools:
#   nmap, masscan  -> active discovery (Phase 3)
#   whatweb        -> tech fingerprint (Phase 4)
#   chromium       -> gowitness screenshots (Phase 4)
#   dnsutils, git, curl, ca-certificates -> support
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap masscan whatweb chromium dnsutils git curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=gotools /go/bin/subfinder /go/bin/nuclei /go/bin/gowitness /usr/local/bin/

WORKDIR /opt/skrecon
COPY . /opt/skrecon

# Install skrecon + its Python tool bindings (dnspython, dnstwist, cryptography,
# theHarvester, wafw00f). shodan/requests come with the passive extra.
RUN pip install --no-cache-dir --retries 5 --timeout 60 -e ".[passive,vault]" wafw00f theHarvester

# Engagements persist to a mounted volume; secrets come from the environment.
ENV SKRECON_OUTPUT_DIR=/engagements
VOLUME ["/engagements"]

# NOTE: masscan requires raw-socket privileges — run with --cap-add=NET_RAW
# (or --privileged) and only against authorized, in-scope targets.
ENTRYPOINT ["skrecon"]
CMD ["--help"]
