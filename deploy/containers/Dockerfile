# syntax=docker/dockerfile:1
# Override these versioned tags with reviewed registry digests for release builds.
ARG RUST_IMAGE=rust:1.98.1-trixie
ARG RUNTIME_IMAGE=debian:13-slim
FROM ${RUST_IMAGE} AS build
ARG CARGO_BUILD_JOBS=2
ENV CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}
RUN apt-get update && apt-get install -y --no-install-recommends cmake clang perl pkg-config python3 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /source
COPY . .
RUN cp Cargo.lock /tmp/reviewed.lock \
    && cargo metadata --format-version 1 --filter-platform "$(rustc -vV | sed -n 's/^host: //p')" > /tmp/server-metadata.json \
    && python3 deploy/containers/verify_lock.py /tmp/reviewed.lock Cargo.lock
RUN cargo build --release --locked -p elo-team -p elo-witness -p elo-storage -p elo-wake -p elo-call-service

FROM ${RUNTIME_IMAGE} AS runtime
ARG ELO_VERSION
RUN test -n "$ELO_VERSION" && apt-get update && apt-get install -y --no-install-recommends ca-certificates curl openssl python3 \
    && rm -rf /var/lib/apt/lists/*
LABEL org.opencontainers.image.title="elo.now server" \
      org.opencontainers.image.version="${ELO_VERSION}" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
COPY --chmod=755 deploy/containers/entrypoint.sh /usr/local/bin/elo-entrypoint
COPY --chmod=644 deploy/containers/activate.py /opt/elo/activate.py
RUN chmod 755 /opt/elo
COPY LICENSE /usr/share/doc/elo/LICENSE
COPY --from=build /source/Cargo.lock /usr/share/doc/elo/Cargo.lock
WORKDIR /tmp
ENTRYPOINT ["/usr/local/bin/elo-entrypoint"]
STOPSIGNAL SIGINT

FROM runtime AS api
COPY --from=build /source/target/release/elo-team /usr/local/bin/elo-team
USER 21001:21001
CMD ["elo-team", "host", "--config", "/etc/elo/api/config.json", "--bind", "127.0.0.1:18900"]

FROM runtime AS witness
COPY --from=build /source/target/release/elo-witness /usr/local/bin/elo-witness
USER 21002:21002
CMD ["elo-witness", "--config", "/etc/elo/witness/config.json"]

FROM runtime AS storage
COPY --from=build /source/target/release/elo-storage /usr/local/bin/elo-storage
USER 21003:21003
CMD ["elo-storage", "--config", "/etc/elo/storage/config.json"]


FROM runtime AS wake
COPY --from=build /source/target/release/elo-wake /usr/local/bin/elo-wake
COPY --chmod=644 deploy/containers/wake.py /opt/elo/wake.py
USER 21006:21006
CMD ["python3", "/opt/elo/wake.py"]

FROM runtime AS calls
COPY --from=build /source/target/release/elo-call-service /usr/local/bin/elo-call-service
USER 21007:21007
CMD ["elo-call-service", "--config", "/etc/elo/calls/config.json"]

FROM storage AS storage-mega
USER root
COPY --chmod=755 deploy/containers/install_mega.sh /opt/elo/install_mega.sh
RUN /opt/elo/install_mega.sh && rm /opt/elo/install_mega.sh
COPY --chmod=644 deploy/storage/mega_folder.py /opt/elo/storage/mega_folder.py
RUN chmod 755 /opt/elo/storage
USER 21003:21003
