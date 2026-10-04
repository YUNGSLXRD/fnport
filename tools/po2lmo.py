#!/usr/bin/env python3
"""Compile a gettext .po file into a LuCI .lmo catalog (port of luci-base po2lmo).

usage: po2lmo.py input.po output.lmo
"""
import re
import struct
import sys

M = 0xffffffff


def sfh_hash(data: bytes, init: int) -> int:
    """Paul Hsieh's SuperFastHash as used by LuCI (lmo.c)."""
    n = len(data)
    if n == 0:
        return 0
    h = init & M
    rem = n & 3
    i = 0
    g16 = lambda k: data[k] | (data[k + 1] << 8)
    s8 = lambda b: b - 256 if b > 127 else b
    for _ in range(n >> 2):
        h = (h + g16(i)) & M
        tmp = ((g16(i + 2) << 11) ^ h) & M
        h = ((h << 16) ^ tmp) & M
        i += 4
        h = (h + (h >> 11)) & M
    if rem == 3:
        h = (h + g16(i)) & M
        h ^= (h << 16) & M
        h ^= (s8(data[i + 2]) << 18) & M
        h = (h + (h >> 11)) & M
    elif rem == 2:
        h = (h + g16(i)) & M
        h ^= (h << 11) & M
        h = (h + (h >> 17)) & M
    elif rem == 1:
        h = (h + s8(data[i])) & M
        h ^= (h << 10) & M
        h = (h + (h >> 1)) & M
    h ^= (h << 3) & M
    h = (h + (h >> 5)) & M
    h ^= (h << 4) & M
    h = (h + (h >> 17)) & M
    h ^= (h << 25) & M
    h = (h + (h >> 6)) & M
    return h


def parse_po(text):
    msgs, cur, key = [], {}, None

    def unq(s):
        return s.encode().decode('unicode_escape').encode('latin-1').decode('utf-8')

    for line in text.splitlines() + [""]:
        line = line.strip()
        m = re.match(r'^(msgid|msgstr)\s+"(.*)"$', line)
        if m:
            if m.group(1) == 'msgid' and 'msgid' in cur:
                msgs.append(cur)
                cur = {}
            key = m.group(1)
            cur[key] = unq(m.group(2))
        elif line.startswith('"') and key:
            cur[key] += unq(line[1:-1])
    if cur:
        msgs.append(cur)
    return [(m['msgid'], m['msgstr']) for m in msgs if m.get('msgid') and m.get('msgstr')]


def main(src, dst):
    out, entries, off = bytearray(), [], 0
    for mid, mstr in parse_po(open(src, encoding='utf-8').read()):
        k, v = mid.encode(), mstr.encode()
        kid, vid = sfh_hash(k, len(k)), sfh_hash(v, len(v))
        if kid == vid:
            continue
        entries.append((kid, 1, off, len(v)))
        pad = (4 - len(v) % 4) % 4
        out += v + b'\0' * pad
        off += len(v) + pad
    for e in sorted(entries):
        out += struct.pack('>IIII', *e)
    out += struct.pack('>I', off)
    open(dst, 'wb').write(out)
    print(f"{len(entries)} entries -> {dst}")


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
