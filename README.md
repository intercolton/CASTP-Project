# ASTP Network Probe

Клиент-серверная диагностика сети для проекта ASTP-M. Репозиторий измеряет доступность TCP, TLS, HTTP/2, QUIC и HTTP/3 на собственных тестовых узлах. Это не VPN и не средство обхода фильтрации.

Лицензия пока двойная: `MIT OR Apache-2.0`. По ходу Лицензирование может измениться, но стремлюсь к MIT.

## Структура

```text
├── Cargo.toml
├── crates/
│   ├── probe-common/      общая схема событий, конфигурация, JSONL
│   ├── probe-client/      CLI astp-probe
│   ├── probe-server/      сервер диагностики astp-probe-server
│   ├── probe-analyzer/    разбор журналов (ещё не реализован)
│   └── probe-report/      HTML-отчёт (ещё не реализован)
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

Интеграционные тесты клиента и сервера на localhost сейчас лежат в `crates/probe-server/tests/`. Так Cargo поднимает оба крейта в одном процессе.

## Что уже есть

- Cargo workspace и общие типы событий.
- Конфигурация клиента и сервера, проверка лимитов.
- Запись и ротация JSONL.
- Диагностический сервер: TCP/TLS, HTTP/1.1, HTTP/2, QUIC и HTTP/3, echo, download, длительная сессия.
- CLI: `test` и `status`. Команды `run` и `report` разобраны, но ещё не выполняют расписание и отчёт.
- Туннель, TUN, handshake ASTP-M и обход фильтрации в этот репозиторий не входят.

Неподдерживаемая команда завершается ошибкой. Успех теста не подменяется заглушкой.

## Сборка

```bash
cargo test --workspace
cargo build --release --workspace
```

Бинарники: `astp-probe`, `astp-probe-server`.

Дальше по ТЗ: планировщик, доставка результатов, анализатор, HTML-отчёт, systemd и проверка на Ubuntu 24.04.
