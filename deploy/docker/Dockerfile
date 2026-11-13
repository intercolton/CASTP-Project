# Сборка сервера диагностики. Образ не заменяет проверку на чистой Ubuntu.
# rust:1.89-bookworm — MSRV. Дайджест: multi-arch index с Docker Hub (2026-11-10).
FROM rust:1.89-bookworm@sha256:948f9b08a66e7fe01b03a98ef1c7568292e07ec2e4fe90d88c07bb14563c84ff AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p probe-server

# Дайджест: multi-arch index debian:bookworm-slim с Docker Hub (2026-11-11).
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN useradd --system --create-home --home-dir /var/lib/astp-probe astp
COPY --from=build /src/target/release/astp-probe-server /usr/local/bin/astp-probe-server
USER astp
EXPOSE 8443/tcp 8443/udp
ENTRYPOINT ["astp-probe-server"]
CMD ["--config", "/etc/astp-probe/server.toml"]
