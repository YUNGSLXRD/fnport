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
