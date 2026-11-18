# Состояние проекта и рабочая память

Обновлено 18 ноября 2026, текущая ветка — `main` (ревизия и полная расчистка после `0.7.0`).

## Где что лежит

| Путь | Что это |
|---|---|
| `fnport/` | Пакет для OpenWrt: служба `fnportd.uc`, проверка провайдера `fnport-check.uc`, обновление `fnport-update.uc`, конфиг/контроллер подключений (`connections-config.uc`, `fnport-connectionsctl.uc`, `fnport-connections-install.sh`), фейки `quic_initial_*.bin` |
| `luci-app-fnport/` | Веб-интерфейс LuCI (`settings.js`, `status.js`, `check.js`, `connections.js`), ACL `rpcd` и переводы `po/ru/fnport.po` |
| `windows/internal/vpn/` | Единый общий пакет VPN/подписок/DNS для Windows и OpenWrt: `awg.go`, `uri.go`, `sub.go`, `dns.go`, `domains.go`, `exit.go`, `warp_reg.go` |
| `windows/internal/wnet/` | Низкоуровневая сеть Windows: физический адаптер, Wintun с DNS (`10.254.77.1`), отправка с TTL, сопоставление процессов |
| `windows/fnport/` | Приложение для Windows на Go + Gio: игровой движок (`engine.go`, `prober.go`, `tcp.go`), DNS-брокер (`dns_broker.go`), туннели (`warp.go`, `connection_awg.go`, `transport.go`), проверка провайдера (`check.go`), интерфейс (`ui.go`, `connections_ui.go`, `subscription_ui.go`) |
| `windows/router/` | Демон-помощник `fnport-connections-helper` для OpenWrt (`main_linux.go`, `service_linux.go`, `native_linux.go`, `firewall_linux.go`, `dns.go`, `config.go`) |
| `windows/probe/` | Консольная утилита-зонд (в релиз не входит) |
| `.github/workflows/build.yml` | CI: пакеты OpenWrt 24.10/25.12, приложение Windows, компоненты роутера (7 архитектур) и подписанные build attestations |

## Что сделано в ревизии после 0.7.0

1. **Единое ядро протоколов и парсеров (`windows/internal/vpn/`).**
   - Убрано дублирование между `windows/fnport` и `windows/router`.
   - Нативно внутри `fnport`: **WARP** (регистрация ключа с разбиением TLS ClientHello и поддержкой `.conf`) и объединённый **AmneziaWG / WireGuard** (принимает как обычный `.conf` WireGuard, так и `.conf` AmneziaWG 1.5 с проверкой шаблонов `I1–I5` до передачи в `amneziawg-go`).
   - Через `sing-box` оставлены только протоколы с полноценным UDP (для голосового Discord): **VLESS** (`vless://`), **Hysteria 2** (`hy2://`, `hysteria2://`, включая `mport`), **Shadowsocks** (`ss://`, AEAD и SS-2022), **Trojan** (`trojan://`), **SOCKS5** (`socks5://`), одиночный JSON outbound и **подписки `https://`** на обеих платформах.
   - Маяки Epic (`*.ds.on.epicgames.com`, `qosping-*.ol.epicgames.com`) жёстко исключены из доменных списков туннеля (`vpn.IsEpicBeacon`), чтобы пинг на главной и проверка провайдера всегда измеряли реальный маршрут.

2. **Селективная маршрутизация Windows без глобального `0.0.0.0/1`.**
   - Убран глобальный перехват всего трафика ПК (`0.0.0.0/1` + `128.0.0.0/1`), кроме случая, когда пользователь явно выбрал отдельные `.exe`-процессы.
   - На адаптере Wintun выставляется локальный DNS `10.254.77.1` (`winDNSBroker` по UDP и TCP): домены выбранных сервисов резолвятся через туннель (DoH) с динамическим добавлением `/32`-маршрутов и упреждающим прогревом каждые 2 минуты, а все остальные домены идут напрямую через DNS физического адаптера.
   - Голосовые серверы Discord покрываются 8 подсетями UDP `50000–65535`.
   - Восстановлен конвейер `tryDirect` / `markWarpBad` / логирование зависших свыше 10 с запросов к сервисам Epic.

3. **Минимальный статический `sing-box.exe` (вариант 2B) и сохранность настроек.**
   - `windows/core.sh` собирает статический `sing-box 1.14.4` (`CGO_ENABLED=0`, `with_quic,with_utls`) из зафиксированного исходного архива без `libcronet.dll` (`-9.1 МБ`) и лишних текстовых файлов в ZIP.
   - Для `sing-box 1.14` в генерируемом конфиге задан `default_domain_resolver` со стратегией `ipv4_only` и bootstrap-сервером `77.88.8.8` на физическом интерфейсе.
   - Добавлен автоматический бэкап и подхват настроек из `%LOCALAPPDATA%\fnport\settings-backup.json` (`0600`) при запуске обновлённой версии из новой папки без `fnport.json`, а также тихая фоновая проверка выхода новой версии один раз за сессию.

4. **Чистка GUI Windows и паритет с OpenWrt.**
   - Полностью удалён мёртвый `legacyWarpTab` и инородные плавающие списки (`op.Defer`). Вкладка «Подключения» переписана в родной эстетике Opus: плавный 4-позиционный переключатель (`Выкл` / `WARP` / `AmneziaWG` / `VPN`), встроенный список серверов подписки с векторными флагами и бейджами протоколов.
   - На OpenWrt:
     - В `fnportd.uc` перенесена автоподстройка `fake_ttl` при плавающей границе ТСПУ, в `fnport-check.uc` — скан меньших TTL (`cur - 1 .. 1` с подтверждением), когда фейк на текущем TTL гасит маяк.
     - В `windows/router/` добавлены загрузка и выбор серверов подписки `https://`, запоминание рабочего адреса WARP, перебор двух UDP-портов и приманка QUIC `I1`, периодический healthcheck туннеля, UDP-first локальный DNS и `LeaseCache` без лишних перезаписей `nft` на каждый DNS-запрос.
     - Тяжёлые зависимости туннеля (`kmod-nft-tproxy`, `kmod-tun`, `ip-full`, `ca-bundle`) вынесены из базового `fnport/Makefile` в установщик компонентов `fnport-connections-install.sh`, исправлено определение `armv7`/`armv6`/`armv5`, в `install.sh` добавлено сохранение `/etc/config/fnport_connections`.
     - Все файлы `ucode`, JS и shell приведены к чистому единому форматированию.

## Правила проекта

- Единственный автор в истории Git — `YUNGSLXRD` (никаких `Co-Authored-By` и упоминаний ИИ).
- Не коммитить собранные бинарники и `.zip`-архивы в рабочие ветки.
- Секреты (ключи, UUID, ссылки профилей, `subscriptionUrl`) никогда не выводить и не коммитить.
- Релизы, действия на живом роутере и ответы в GitHub Issues — только после явного подтверждения владельца.
