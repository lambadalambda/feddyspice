FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    xz-utils \
    libssl-dev \
    libsqlite3-dev \
  && rm -rf /var/lib/apt/lists/*

ARG ZIG_VERSION=0.15.2
RUN curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz" -o /tmp/zig.tar.xz \
  && tar -C /opt -xf /tmp/zig.tar.xz \
  && mv "/opt/zig-linux-x86_64-${ZIG_VERSION}" /opt/zig \
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
