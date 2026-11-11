# systemd

Юниты рассчитаны на установку бинарников в `/usr/local/bin` и конфигурации в `/etc/astp-probe`.

Оба юнита работают от временного непривилегированного пользователя (`DynamicUser=yes`). Каталог данных `/var/lib/astp-probe` systemd создаёт сам (`StateDirectory=`) и отдаёт этому пользователю; создавать его заранее не нужно. В TOML `data_dir` должен указывать на `/var/lib/astp-probe`.

## Сервер

Пример слушает порт 8443 (TCP и UDP), для него привилегии не нужны, и юнит не даёт процессу никаких capabilities (`CapabilityBoundingSet=` пустой). Если пробник ставится на отдельную машину без шлюза и должен слушать порт ниже 1024, добавьте в юнит:

```ini
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

Сертификат и ключ лежат в `/etc/astp-probe/cert.pem` и `/etc/astp-probe/key.pem` с правами только для root (`0600`). systemd копирует их через `LoadCredential=` в `/run/credentials/astp-probe-server.service/`, откуда их может читать только процесс сервиса. Поэтому в `server.toml` для systemd пути другие, чем в примере:

```toml
[tls]
cert_file = "/run/credentials/astp-probe-server.service/cert.pem"
key_file = "/run/credentials/astp-probe-server.service/key.pem"
```

После обновления сертификата (например, certbot) нужен `systemctl restart astp-probe-server`: копия в `/run/credentials` обновляется только при запуске.

## Клиент

`astp-probe run` выполняет расписание из `[schedule]` до остановки; по SIGTERM процесс завершается сразу, прерывая идущую пробу. `StartLimitIntervalSec=60`/`StartLimitBurst=5` ограничивают перезапуски при ошибках (например, при неверном конфиге). Для кампании фиксированной длины добавьте к `ExecStart` `--campaign 14d`: по её окончании процесс выходит с кодом 0, и `Restart=on-failure` его не перезапускает.

Для `client.bind_interface` (SO_BINDTODEVICE) юнит даёт `CAP_NET_RAW`. На ядрах Linux 5.7+ привязка к интерфейсу работает и без него; если `bind_interface` не используется, строки `AmbientCapabilities`/`CapabilityBoundingSet` можно убрать.

На чистой Ubuntu 24.04 эта установка пока не прогонялась.
