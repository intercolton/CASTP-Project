# Сборка сервера диагностики. Образ не заменяет проверку на чистой Ubuntu.
FROM rust:1-bookworm AS build
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
