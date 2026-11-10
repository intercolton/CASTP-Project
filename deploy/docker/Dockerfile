# Сборка сервера диагностики. Образ не заменяет проверку на чистой Ubuntu.
# rust:1.89-bookworm — MSRV. Дайджест: multi-arch index с Docker Hub (2026-11-10).
FROM rust:1.89-bookworm@sha256:948f9b08a66e7fe01b03a98ef1c7568292e07ec2e4fe90d88c07bb14563c84ff AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p probe-server

FROM debian:bookworm-slim
RUN useradd --system --create-home --home-dir /var/lib/astp-probe astp
COPY --from=build /src/target/release/astp-probe-server /usr/local/bin/astp-probe-server
USER astp
EXPOSE 443/tcp 443/udp
ENTRYPOINT ["astp-probe-server"]
CMD ["--config", "/etc/astp-probe/server.toml"]
