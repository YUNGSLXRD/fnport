# Сторонние файлы

## quic_initial_vk_com.bin

Файл [`fnport/files/quic_initial_vk_com.bin`](fnport/files/quic_initial_vk_com.bin) (фейковый QUIC Initial
с SNI vk.com) взят без изменений из [zapret](https://github.com/bol-van/zapret) (автор bol-van),
[`files/fake/quic_initial_vk_com.bin`](https://github.com/bol-van/zapret/blob/2aaa2f7cf3c33b282727784738059d73279bc60f/files/fake/quic_initial_vk_com.bin).

Распространяется по лицензии zapret (MIT), её текст лежит рядом с файлом:
[`fnport/files/quic_initial_vk_com.bin.LICENSE`](fnport/files/quic_initial_vk_com.bin.LICENSE).
В пакете она устанавливается в `/usr/share/fnport/quic_initial_vk_com.bin.LICENSE`.

## quic_initial_gosuslugi_ru.bin, quic_initial_ozon_ru.bin

Запасные фейки [`quic_initial_gosuslugi_ru.bin`](fnport/files/quic_initial_gosuslugi_ru.bin) и
[`quic_initial_ozon_ru.bin`](fnport/files/quic_initial_ozon_ru.bin) сделаны из `quic_initial_vk_com.bin`
скриптом [`tools/make_quic_fake.py`](tools/make_quic_fake.py): тот же ClientHello с другим именем сервера,
заново зашифрованный ключами QUIC Initial. Как производные от файла zapret, они распространяются по его
лицензии (MIT), текст лежит рядом с каждым файлом (`*.bin.LICENSE`) и ставится вместе с ними в `/usr/share/fnport/`.

## Образ диска (`fnport-…-x86-64.vhd.zip`)

Образ собран из официального [OpenWrt Image Builder](https://openwrt.org/docs/guide-user/additional-software/imagebuilder)
(x86/64, версия указана в имени файла) с пакетами fnport. Входящие в него программы OpenWrt распространяются
по своим лицензиям, в основном GPL-2.0; исходный код каждой версии доступен на
[git.openwrt.org](https://git.openwrt.org/?p=openwrt/openwrt.git) (тег `v<версия>`) и
[github.com/openwrt](https://github.com/openwrt), исходники пакетов — в
[downloads.openwrt.org](https://downloads.openwrt.org/releases/). Настройки первого запуска образа —
в [`image/`](image/) этого репозитория.

## fnport для Windows (`fnport-windows-….zip`)

- **`wintun.dll`** 0.14.1 (x64) от WireGuard LLC, без изменений, с их подписью. Распространяется по
  [лицензии Wintun для готовых сборок](windows/third_party/wintun-LICENSE.txt), которая лежит в архиве рядом с DLL
  (`wintun-LICENSE.txt`). Откуда взят и как сверяется — в [windows/README.md](windows/README.md#сторонние-файлы).
- **Шрифт [Inter](https://github.com/rsms/inter)** (Rasmus Andersson) — SIL Open Font License 1.1. В программу
  вшиты начертания Regular и SemiBold, сделанные из вариативного шрифта скриптом
  [`windows/internal/fonts/make.sh`](windows/internal/fonts/make.sh); лицензия — в
  [`windows/internal/fonts/OFL.txt`](windows/internal/fonts/OFL.txt) и в архиве (`font-Inter-OFL.txt`).
- **Фейки** в папке `fakes` — те же файлы, что выше, с лицензией zapret (`fakes/LICENSE.txt`, `quic-fakes-LICENSE.txt`).
- **Библиотеки Go**, вошедшие в программу: Go (BSD-3-Clause), Gio (`gioui.org`, MIT или Unlicense, со шрифтом
  Go Mono), gVisor (Apache 2.0), библиотеки WireGuard и Wintun для Go (MIT), `golang.org/x/*` (BSD-3-Clause)
  и другие. Тексты всех лицензий собирает `windows/build.sh` в `third-party-licenses.txt` в архиве.
