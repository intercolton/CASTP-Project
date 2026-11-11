# VPN ASTP-M v1: установка и эксплуатация

Устройство и решения — в [design/](design/README.md). Здесь — как поднять сервер и клиент.

## Требования

- Linux, `/dev/net/tun`, iproute2 (`ip`); у процесса `CAP_NET_ADMIN` (юниты из `deploy/systemd/` дают его без root).
- Сервер: публичный сертификат с ключом Ed25519 или ECDSA P-256 (RSA и P-384 для своего ключа не принимаются).

## Сервер

1. `astp-server keygen` — печатает секрет клиента и путь сессии. Путь один на сервер; секрет — на каждого клиента.
2. `/etc/astp/server.toml` по образцу `configs/astp-server.example.toml`. Секреты — в `/etc/astp/server.env` (`ASTP_CLIENT_LAPTOP=...`, права `0600`), в TOML — `secret_env`.
3. В юните `deploy/systemd/astp-server.service` сертификат читается через `LoadCredential=`; в `server.toml` тогда:
   ```toml
   cert_file = "/run/credentials/astp-server.service/cert.pem"
   key_file = "/run/credentials/astp-server.service/key.pem"
   ```
4. `astp-server check --config /etc/astp/server.toml` — проверка без запуска.
5. Выход клиентов в интернет настраивается отдельно (сервер правила не трогает):
   ```bash
   sysctl -w net.ipv4.ip_forward=1
   nft add table ip astp
   nft add chain ip astp post '{ type nat hook postrouting priority 100; }'
   nft add rule ip astp post ip saddr 10.77.0.0/24 oifname "eth0" masquerade
   ```
   `eth0` — внешний интерфейс сервера.

Сервер на 443 для постороннего — обычный сайт: `/` отдаёт страницу, остальное — 404. Свои страницы — секция `[decoy]`.

## Клиент

1. `/etc/astp/client.toml` по образцу `configs/astp-client.example.toml`; секрет — в `/etc/astp/client.env` (`ASTP_SECRET=...`).
2. `astp-client --check --config /etc/astp/client.toml`.
3. `systemctl enable --now astp-client` или `astp-client --config ...` от root.

Клиент получает адрес, MTU, DNS и маршруты от сервера. Маршрут по умолчанию ставится двумя половинами (`0.0.0.0/1`, `128.0.0.0/1`), к самому серверу — маршрут через прежний шлюз. При остановке клиент удаляет свои маршруты; устройство исчезает вместе с процессом. При обрыве клиент переподключается с паузой от 1 до 60 с.

DNS сервера применяется только при `set_dns = true` и наличии `resolvectl` (systemd-resolved).

## Что проверено и что нет

- Сессия, транспорт (HTTP/2 и HTTP/3), аутентификация, сайт-прикрытие, маршрутизация между клиентами и защита от подмены адреса проверены автотестами на localhost; TUN-устройство — отдельным тестом с настоящим устройством (нужен root).
- `scripts/vpn-netns-smoke.sh` (root): две сетевые области имён, соединённые veth, вместо двух машин; настоящие TUN у сервера и клиента, HTTP/2 и HTTP/3, `ping` в обе стороны через туннель, удаление маршрутов клиентом при выходе. Прогнан успешно.
- Выход клиентов в интернет через NAT и работа через реальные сети (потери, MTU, фильтры) ещё не проверялись.
