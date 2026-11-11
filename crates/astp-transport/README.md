# astp-transport

QUIC и HTTP/3 для ASTP-M. Это не пробник: `probe-*` сюда не входит.

Клиент набирает адрес, который ему уже разрезолвили. Имя для проверки сертификата берётся только из `astp_crypto::ClientTls`. Отдельной строки SNI у `quic::connect` нет.

## Пины

В workspace зависимости стоят с `=`, без `^`:

| Крейт | Версия |
|---|---|
| quinn | 0.11 (feature `rustls-ring`, как в workspace) |
| h3 | `=0.0.8` |
| h3-quinn | `=0.0.10` |
| h3-datagram | `=0.0.2` |

Почему так. `h3-datagram` 0.0.2 собран против `h3` 0.0.8 и включает у него feature `i-implement-a-third-party-backend-and-opt-into-breaking-changes`: без этой feature крейт не видит внутренности `h3`, через которые привязаны datagram к соединению. Feature унифицируется на весь workspace (в том числе на `probe-server`). Она делает публичными внутренние модули `h3` и снимает `non_exhaustive` с части вариантов ошибок. Поведение протокола не меняется. `h3-quinn` 0.0.10 с feature `datagram` реализует трейты `h3-datagram` для quinn 0.11. Другой тройки версий, которая собирается вместе на rustc 1.89 без форка и без `[patch]`, в брифе нет, поэтому версии зафиксированы точно.

У `h3-datagram` 0.0.2 `Datagram::encode` записывает quarter stream id в локальный буфер и затем этот буфер выбрасывает. На проводе остаётся нулевой заголовок. Для stream id 0 это и есть правильный quarter stream id, поэтому первый клиентский запрос (id 0) привязан верно. Второй bidirectional-запрос на том же соединении будет помечен как stream 0, пока крейт не исправят. В этой задаче на соединение открывается один `POST`. Grease выключен (`send_grease(false)`), чтобы первый запрос оставался id 0.

## Что делает слушатель

- TLS 1.3 через `quinn::crypto::rustls::QuicServerConfig::try_from`. Если `max_early_data_size != 0`, это ошибка `ZeroRttEnabled`, конфиг молча не переписывается. То же для `send_half_rtt_data`. Список версий протокола rustls наружу не отдаёт; конфиг, который строит `astp_crypto::server_config`, включает только TLS 1.3.
- Handshake оборачивается в `handshake_timeout` (по умолчанию 10 с). Незавершённых handshake не больше `max_pending_handshakes` (256): дальше `incoming.refuse()`. Если адрес не подтверждён и незавершённых уже не меньше `retry_threshold` (128), вызывается `incoming.retry()`.
- `max_idle_timeout` 30 с. Keep-alive 10 с только у клиента. Datagram включены (`datagram_receive_buffer_size` и `datagram_send_buffer_size`, по умолчанию 8 МиБ, чтобы эхо на loopback не выбрасывало кадры из буфера quinn).
- После handshake ALPN `h3` уходит в HTTP/3. Любое другое значение, включая `h2`, закрывает соединение кодом приложения 0 и пустой причиной. В брифе это записано как `H3_NO_ERROR / 0`. По RFC 9114 `H3_NO_ERROR` равен `0x100`; число в коде — ноль из брифа, текст причины пустой.
- Привязка к каналу — тот же exporter, что в задаче 3 (`EXPORTER-ASTP-M auth v1`, 32 байта, пустой контекст). Реализация `TlsSession` для `quinn::Connection` живёт в `astp-crypto` под feature `quinn`. Quinn передаёт контекст как `Some(&[])`; rustls хеширует это так же, как `None`.

## HTTP/3

`POST` на путь из `Http3Options` (в этой задаче `/t`) отдаётся вызывающему как туннель. Остальные запросы получают 404 с пустым телом.

Тело туннеля читается через `astp_frame::FrameReader`. Ошибка кадра или таймаут чтения кадра (`frame_read_timeout`, по умолчанию 10 с) закрывает поток и соединение. Таймаут и `max_connections` (1024) ограничивают удержание буфера `FrameReader`: после 4 КиБ + 8 байт читатель может держать до 64 КиБ на соединение.

HTTP datagram (RFC 9297) привязаны к этому запросу через quarter stream id и API `h3-datagram`. Закрытие тела запроса снимает приём datagram этого потока.

Какой из двух путей основной для QUIC, решает замер `tests/datagram_vs_stream.rs`. Константа `QUIC_PRIMARY_DATAGRAMS` и раздел в `docs/architecture.md` фиксируют выбор. Поток не удаляется: он нужен для HTTP/2 в задаче 7.
