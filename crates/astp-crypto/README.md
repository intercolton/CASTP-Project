# astp-crypto

Конфигурация TLS для ASTP-M и контракт аутентификатора. Это не пробник и не транспорт: сокетов, QUIC, HTTP и боевого формата учётных данных здесь нет.

## Инварианты

- Только TLS 1.3. Версия задаётся в конфиге (`TLS13`). Feature `tls12` у rustls во workspace не выключается: она нужна пробнику.
- Без 0-RTT. У сервера `max_early_data_size = 0` и `send_half_rtt_data = false`. У клиента `enable_early_data = false`.
- Имя сервера проверяется всегда. Публичного API, которое отключает проверку сертификата или имени, нет. Литерал IP без `tls_server_name` — ошибка конфигурации.
- ALPN сервера: `h3`, затем `h2` (константы `astp-types`). Клиент: `h3`, `h2` для QUIC и `h2` для TCP. `astp-m/1` по умолчанию не предлагается.
- mTLS выключен, пока явно не задан `ClientAuth::Required`.
- Привязка к каналу — TLS exporter: метка `EXPORTER-ASTP-M auth v1` (`CHANNEL_BINDING_LABEL`), длина 32 (`CHANNEL_BINDING_LEN`), контекст пустой (`None`).

## Тестовый аутентификатор

`StaticTokenAuthenticator` (HMAC-SHA256 от binding через ring, сравнение `subtle::ConstantTimeEq`) доступен с feature `test-util` и в тестах этого крейта. Это не формат учётных данных для продакшена. Любая `AuthError` пишется в лог; для удалённой стороны варианты не различаются.
