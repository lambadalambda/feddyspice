FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    xz-utils \
    libssl-dev \
    libsqlite3-dev \
  && rm -rf /var/lib/apt/lists/*

ARG ZIG_VERSION=0.15.2
ARG TARGETARCH
RUN case "${TARGETARCH}" in \
      amd64) zig_arch=x86_64 ;; \
      arm64) zig_arch=aarch64 ;; \
      *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
  && curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-${zig_arch}-linux-${ZIG_VERSION}.tar.xz" -o /tmp/zig.tar.xz \
  && tar -C /opt -xf /tmp/zig.tar.xz \
  && mv "/opt/zig-${zig_arch}-linux-${ZIG_VERSION}" /opt/zig \
  && ln -s /opt/zig/zig /usr/local/bin/zig

WORKDIR /src
COPY build.zig build.zig.zon ./
COPY src ./src

RUN zig build -Doptimize=ReleaseSafe

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libssl3 \
    libsqlite3-0 \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/zig-out/bin/feddyspice /usr/local/bin/feddyspice

ENV FEDDYSPICE_LISTEN=0.0.0.0:8080 \
    FEDDYSPICE_DB_PATH=/data/feddyspice.sqlite3

VOLUME ["/data"]
EXPOSE 8080

CMD ["feddyspice"]
