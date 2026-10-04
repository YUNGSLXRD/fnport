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
