# Диагностика и удаление

## Проверка конфигурации сервера

```bash
astp-probe-server --config configs/server.example.toml --check
```

Команда читает TOML и сертификаты, порт не занимает. Для примера нужны реальные `cert_file` и `key_file`.

## Клиент один раз

```bash
astp-probe test --config configs/client.example.toml --tcp --tls
astp-probe status --config configs/client.example.toml
```

Ненулевой код выхода означает, что хотя бы одна проба не удалась. Текст строки содержит код ошибки из схемы, например `tcp_timeout` или `tls_certificate_error`.

## Где лежат журналы

Клиент пишет `data_dir/events.jsonl`. Сервер пишет `data_dir/server-events.jsonl`. Каталог создаётся при открытии журнала, то есть при старте сервера или первой пробе клиента, даже если событий ещё нет. При превышении размера файл переименовывается в `events.jsonl.1`, и так далее.

## Частые случаи

| Наблюдение | Куда смотреть |
|---|---|
| `tls_certificate_error` | Имя в сертификате, `tls_server_name`, файл `ca_file`. Пустой или нечитаемый `ca_file` клиент отвергает при запуске, а не на каждой пробе |
| `tcp_refused` | Слушает ли сервер указанный порт |
| `quic_timeout` при живом TCP | UDP/443, а не вывод «это DPI» |
| `unsupported` | Эта сборка или эта ОС так не умеет. На Linux привязка к интерфейсу есть, на Windows нет |

## Удаление

Остановите процесс или сервис, удалите бинарники и каталоги `/etc/astp-probe` и `/var/lib/astp-probe`, если ставили их вручную. Юниты systemd из `deploy/systemd/` снимаются через `systemctl disable --now`, когда установка будет доведена до конца. Сейчас это заготовки, на чистой Ubuntu они ещё не прогонялись.
