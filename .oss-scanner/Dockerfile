# Build only from a clean checkout of the public elo-now/elo-now repository.
# Keep sources, compilers, dependency caches and tests for the offline scanner.
FROM node:24-bookworm-slim AS node
FROM rust:1.98.1-trixie

ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_BUILD_JOBS=2 \
    CARGO_INCREMENTAL=0 \
    CARGO_PROFILE_DEV_DEBUG=1 \
    CARGO_PROFILE_TEST_DEBUG=1 \
    RUSTFLAGS="-C force-frame-pointers=yes" \
    RUST_TEST_THREADS=2 \
    npm_config_audit=false \
    npm_config_fund=false

RUN apt-get update && apt-get install -y --no-install-recommends \
      age build-essential ca-certificates clang cmake curl git \
      libayatana-appindicator3-dev librsvg2-dev libssl-dev \
      libwebkit2gtk-4.1-dev libxdo-dev perl pkg-config \
      python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

COPY . /src
WORKDIR /src
RUN rustup component add rustfmt clippy \
    && cargo fetch --locked --target "$(rustc -vV | sed -n 's/^host: //p')" \
    && npm --prefix apps/desktop ci --ignore-scripts \
    && npm --prefix apps/desktop run build

RUN cargo build --locked --offline \
      -p elo-core -p elo-cli -p elo-team -p elo-witness -p elo-storage \
      -p elo-wake -p elo-call-service -p elo-desktop \
      -p tauri-plugin-elo-push -p tauri-plugin-elo-privacy \
      --features elo-desktop/mobile-push,elo-desktop/custom-protocol \
    && cargo test --locked --offline --no-run \
      -p elo-core -p elo-cli -p elo-team -p elo-witness -p elo-storage \
      -p elo-wake -p elo-call-service \
    && cargo test --locked --offline --no-run -p elo-core --example witnessed_space_qa \
    && cargo test --locked --offline --no-run -p elo-desktop --lib

ENV CARGO_NET_OFFLINE=true
CMD ["bash"]
