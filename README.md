# ASTP Network Probe

Клиент-серверная диагностика сети для проекта ASTP-M. Пробник измеряет доступность TCP, TLS, HTTP/2, QUIC и HTTP/3 на собственных тестовых узлах. Пробник — не VPN и не средство обхода фильтрации.

В том же Cargo workspace лежит каркас VPN ASTP-M (крейты `astp-*`). Это не пробник и не подменяет `astp-probe` / `astp-probe-server`. Туннель и handshake ещё не реализованы: бинарники `astp-client` и `astp-server` завершаются с кодом 1 и сообщением `not implemented`.

Шлюз ASTP-M по умолчанию займёт порт 443 (UDP и TCP). Пробник запускается на другом порту или на другой машине: примеры конфигурации, Docker и systemd используют порт 8443 (TCP и UDP). Раскладка портов на узлах каскада — в `docs/architecture.md`. Публичный ALPN на проводе — `h3` (QUIC) и `h2` (TCP + TLS). Токен `astp-m/1` только запасной и внутренний, не дефолт публичного профиля. ALPN-мультиплекс пробника и VPN не планируется.

Проект лицензирован под MIT. Текст лицензии — в файле `LICENSE`.

Отдельные идеи и, позже, отдельные куски кода могут опираться на [ZeroTworu/anet](https://github.com/ZeroTworu/anet) @ `0c0ffce`. Проводной совместимости с anet нет, форка репозитория anet нет. Лицензия anet — `LICENSES/anet-LICENSE.md`. Строка атрибуции: `Based on ZeroTworu/anet @0c0ffce` (см. `THIRD_PARTY_NOTICES`). Любой позже перенесённый из anet файл, даже переписанный по мотивам, обязан содержать в заголовке источник и SHA, например `// Based on ZeroTworu/anet @0c0ffce: anet-common/src/padding_utils.rs`. Такой код адаптируется под edition 2021 и rustc 1.89. Перенос из anet сам по себе `workspace.package.rust-version` не повышает.

Toolchain — Rust 1.89 (MSRV), edition 2021. Это не Rust 1.98 и не edition 2024. MSRV поднят с 1.85, потому что в `Cargo.lock` стоят `uuid` 1.29.0 (`rust-version` 1.89.0), `time` 0.3.55 (`rust-version` 1.88.0) и `rcgen` 0.14.10 (`rust-version` 1.88). Понизить эти версии в lockfile технически можно; проект решил этого не делать.

Эталон сборки и CI — Ubuntu 24.04 x86_64. Целевой сервер v1 — Linux VPS с ядром не ниже 5.15, архитектуры x86_64 и aarch64: основной артефакт — musl и Docker, запасной — glibc. Туннельный режим требует `/dev/net/tun` и `CAP_NET_ADMIN`. Параллельный каскад (два сервера) в v1 не входит. Этот каркас не содержит платформенных зависимостей, Docker-образа VPN и CI-матрицы.

## Структура

```text
├── Cargo.toml
├── LICENSE
├── THIRD_PARTY_NOTICES
├── LICENSES/
│   └── anet-LICENSE.md
├── crates/
│   ├── probe-common/      общая схема событий, конфигурация, JSONL
│   ├── probe-client/      CLI astp-probe
│   ├── probe-server/      сервер диагностики astp-probe-server
│   ├── probe-analyzer/    разбор журналов (ещё не реализован)
│   ├── probe-report/      HTML-отчёт (ещё не реализован)
│   ├── astp-types/        каркас типов ASTP-M (VPN в разработке, не пробник)
│   ├── astp-frame/        кодек кадров ASTP-M v1 (не пробник, не транспорт)
│   ├── astp-crypto/       TLS 1.3 и контракт Authenticator (не пробник, не транспорт)
│   ├── astp-transport/    каркас транспорта ASTP-M (VPN в разработке, не пробник)
│   ├── astp-session/      каркас сессии ASTP-M (VPN в разработке, не пробник)
│   ├── astp-tun/          каркас TUN ASTP-M (VPN в разработке, не пробник)
│   ├── astp-client/       CLI astp-client (VPN в разработке, не пробник)
│   └── astp-server/       сервер astp-server (VPN в разработке, не пробник)
├── configs/               примеры TOML
├── deploy/
│   ├── systemd/
│   └── docker/
├── tests/
│   ├── integration/       где будут сквозные сценарии уровня репозитория
│   └── fixtures/
├── docs/
└── scripts/
```

Интеграционные тесты клиента и сервера пробника на localhost сейчас лежат в `crates/probe-server/tests/`. Так Cargo поднимает оба крейта в одном процессе.

## Что уже есть

- Cargo workspace и общие типы событий.
- Конфигурация клиента и сервера, проверка лимитов.
- Запись и ротация JSONL.
- Диагностический сервер: TCP/TLS, HTTP/1.1, HTTP/2, QUIC и HTTP/3, echo, download, длительная сессия.
- CLI пробника: `test`, `status` и `run` (расписание с джиттером, кампания `--campaign 14d`). Команда `report` ещё не выполняет отчёт.
- Каркас крейтов `astp-*`. Бинарники `astp-client` и `astp-server` отказываются: в stderr есть `not implemented`, код выхода 1.
- Кадры прикладного слоя (спека 0.3 §5) кодирует `astp-frame`. `astp-crypto` задаёт конфиг TLS 1.3 и контракт аутентификатора. Туннель, слушатели QUIC/TCP, handshake сессии и TUN ещё не реализованы.

Неподдерживаемая команда завершается ошибкой. Успех теста не подменяется заглушкой.

## Сборка

```bash
cargo test --workspace
cargo build --release --workspace
```

Бинарники пробника: `astp-probe`, `astp-probe-server`.

Бинарники каркаса VPN: `astp-client`, `astp-server` (пока `not implemented`).

Дальше по ТЗ пробника: доставка результатов, анализатор, HTML-отчёт и проверка на эталонной Ubuntu 24.04 x86_64.
