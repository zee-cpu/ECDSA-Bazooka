# Single "does-everything" image: core tool + sieve stack (g6k dim 192) prebuilt.
# Same image runs easy cases on a laptop and L=2 on a big server. ~2 GB.
#
# Build ARG SKIP_SIEVE lets CI/core builds skip the slow g6k build:
#   docker build -t ecdsa-bazooka:local .                       # full image (default)
#   docker build --build-arg SKIP_SIEVE=1 -t ecdsa-bazooka:core .  # fast core-only build
FROM ubuntu:24.04

ARG SKIP_SIEVE=0

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        git build-essential cmake pkg-config \
        libgmp-dev libgmpxx4ldbl libfplll-dev libfplll8t64 libmpfr-dev \
        autoconf automake libtool \
        python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/ecdsa-bazooka
COPY . /opt/ecdsa-bazooka

# Build the C++ tool (includes the bazooka_predicate shim target).
RUN cmake --preset release && cmake --build --preset release -j"$(nproc)"

# Build the full sieve stack (fplll+fpylll+g6k at dim 192) and write sieve-env.sh.
# The binary auto-locates /opt/ecdsa-bazooka/worker/sieve-env.sh at runtime.
# Skipped when SKIP_SIEVE=1 (fast core-only build for CI).
RUN if [ "$SKIP_SIEVE" = "0" ]; then \
        ./worker/bootstrap.sh --build-g6k --max-sieving-dim 192 --jobs "$(nproc)"; \
    fi

ENTRYPOINT ["/opt/ecdsa-bazooka/build/ecdsa_nonce_recovery"]
CMD ["--help"]
