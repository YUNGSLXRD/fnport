#!/usr/bin/env python3
"""Make a fake QUIC Initial with another SNI from an existing one (RFC 9000/9001, QUIC v1).

    make_quic_fake.py show FAKE.bin                 decrypt FAKE.bin, print its SNI and frames
    make_quic_fake.py make FAKE.bin DOMAIN OUT.bin  same ClientHello with DOMAIN as SNI

The template's ClientHello (a real browser's, from zapret) is kept byte for byte except the
server name; it goes into one CRYPTO frame, PADDING keeps the packet size, and the packet is
encrypted with Initial keys from a fresh random DCID. Pure Python, no third-party modules.
"""
import hashlib
import hmac
import os
import struct
import sys

# ---- AES-128 (encryption only: GCM and header protection never decrypt blocks) ----

SBOX = [0] * 256


def _init_sbox():
    p = q = 1
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ (q << 1 | q >> 7) ^ (q << 2 | q >> 6) ^ (q << 3 | q >> 5) ^ (q << 4 | q >> 4)
        SBOX[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    SBOX[0] = 0x63


_init_sbox()


def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def aes_expand(key):
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [sum(w[r * 4:r * 4 + 4], []) for r in range(11)]


def aes_block(rk, block):
    s = [b ^ k for b, k in zip(block, rk[0])]
    for r in range(1, 11):
        s = [SBOX[b] for b in s]
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]  # ShiftRows (column-major state)
        if r != 10:
            m = []
            for c in range(4):
                a = s[c * 4:c * 4 + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                m += [a[i] ^ t ^ _xtime(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
            s = m
        s = [b ^ k for b, k in zip(s, rk[r])]
    return bytes(s)


# ---- AES-128-GCM ----

def _gmul(x, y):
    r, z, v = 0xE1 << 120, 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ r if v & 1 else v >> 1
    return z


def _ghash(h, aad, ct):
    def blocks(b):
        b += b'\0' * (-len(b) % 16)
        return [int.from_bytes(b[i:i + 16], 'big') for i in range(0, len(b), 16)]
    x = 0
    for blk in blocks(aad) + blocks(ct) + [(len(aad) * 8) << 64 | len(ct) * 8]:
        x = _gmul(x ^ blk, h)
    return x


def _ctr(rk, j0, data):
    out = bytearray()
    for i in range(0, len(data), 16):
        ctr = j0[:12] + struct.pack('>I', (int.from_bytes(j0[12:], 'big') + 1 + i // 16) & 0xFFFFFFFF)
        out += bytes(a ^ b for a, b in zip(data[i:i + 16], aes_block(rk, ctr)))
    return bytes(out)


def gcm_encrypt(key, nonce, aad, pt):
    rk = aes_expand(key)
    h = int.from_bytes(aes_block(rk, b'\0' * 16), 'big')
    j0 = nonce + b'\0\0\0\1'
    ct = _ctr(rk, j0, pt)
    tag = (int.from_bytes(aes_block(rk, j0), 'big') ^ _ghash(h, aad, ct)).to_bytes(16, 'big')
    return ct + tag


def gcm_decrypt(key, nonce, aad, data):
    rk = aes_expand(key)
    h = int.from_bytes(aes_block(rk, b'\0' * 16), 'big')
    j0 = nonce + b'\0\0\0\1'
    ct, tag = data[:-16], data[-16:]
    want = (int.from_bytes(aes_block(rk, j0), 'big') ^ _ghash(h, aad, ct)).to_bytes(16, 'big')
    if not hmac.compare_digest(tag, want):
        raise ValueError('authentication tag mismatch')
    return _ctr(rk, j0, ct)


# ---- QUIC v1 Initial keys (RFC 9001, 5.2) ----

INITIAL_SALT = bytes.fromhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a')


def _expand_label(secret, label, length):
    info = struct.pack('>H', length) + bytes([len(b'tls13 ' + label)]) + b'tls13 ' + label + b'\0'
    out, t, i = b'', b'', 1
    while len(out) < length:
        t = hmac.new(secret, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def client_keys(dcid):
    initial = hmac.new(INITIAL_SALT, dcid, hashlib.sha256).digest()
    secret = _expand_label(initial, b'client in', 32)
    return _expand_label(secret, b'quic key', 16), _expand_label(secret, b'quic iv', 12), _expand_label(secret, b'quic hp', 16)


def _varint(b, i):
    n = 1 << (b[i] >> 6)
    v = b[i] & 0x3F
    for j in range(1, n):
        v = v << 8 | b[i + j]
    return v, i + n


def _enc_varint(v, size=None):
    for n, top in ((1, 0), (2, 0x40), (4, 0x80), (8, 0xC0)):
        if (size or 0) <= n and v < 1 << (8 * n - 2):
            return (v | top << (8 * n - 8)).to_bytes(n, 'big')
    raise ValueError(v)


def decrypt_initial(pkt):
    """-> (dcid, scid, token, frames plaintext, total length of the Initial in pkt)"""
    if pkt[0] & 0xF0 != 0xC0 or pkt[1:5] != b'\0\0\0\1':
        raise ValueError('not a QUIC v1 Initial')
    i = 5
    dcid = pkt[i + 1:i + 1 + pkt[i]]; i += 1 + pkt[i]
    scid = pkt[i + 1:i + 1 + pkt[i]]; i += 1 + pkt[i]
    tlen, i = _varint(pkt, i)
    token = pkt[i:i + tlen]; i += tlen
    length, pn_off = _varint(pkt, i)
    key, iv, hp = client_keys(dcid)
    mask = aes_block(aes_expand(hp), pkt[pn_off + 4:pn_off + 20])
    first = pkt[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 3) + 1
    pn = bytes(a ^ b for a, b in zip(pkt[pn_off:pn_off + pn_len], mask[1:]))
    header = bytes([first]) + pkt[1:pn_off] + pn
    nonce = (int.from_bytes(iv, 'big') ^ int.from_bytes(pn, 'big')).to_bytes(12, 'big')
    pt = gcm_decrypt(key, nonce, header, pkt[pn_off + pn_len:pn_off + length])
    return dcid, scid, token, pt, pn_off + length


def encrypt_initial(dcid, scid, token, pt, pn=0, pn_len=1):
    key, iv, hp = client_keys(dcid)
    length = pn_len + len(pt) + 16
    header = bytes([0xC0 | (pn_len - 1)]) + b'\0\0\0\1' + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    header += _enc_varint(len(token)) + token + _enc_varint(length, 2)
    pn_off = len(header)
    pnb = pn.to_bytes(pn_len, 'big')
    nonce = (int.from_bytes(iv, 'big') ^ pn).to_bytes(12, 'big')
    ct = gcm_encrypt(key, nonce, header + pnb, pt)
    pkt = bytearray(header + pnb + ct)
    mask = aes_block(aes_expand(hp), bytes(pkt[pn_off + 4:pn_off + 20]))
    pkt[0] ^= mask[0] & 0x0F
    for j in range(pn_len):
        pkt[pn_off + j] ^= mask[1 + j]
    return bytes(pkt)


# ---- frames and the ClientHello ----

def crypto_stream(pt):
    """reassemble CRYPTO frames -> bytes; also return the frame types seen"""
    i, chunks, seen = 0, {}, []
    while i < len(pt):
        t = pt[i]
        if t == 0x00:                      # PADDING
            i += 1
            if not seen or seen[-1] != 'PADDING':
                seen.append('PADDING')
        elif t == 0x01:                    # PING
            i += 1
            seen.append('PING')
        elif t == 0x06:                    # CRYPTO
            off, i = _varint(pt, i + 1)
            ln, i = _varint(pt, i)
            chunks[off] = pt[i:i + ln]
            i += ln
            seen.append('CRYPTO(%d+%d)' % (off, ln))
        else:
            raise ValueError('unexpected frame type 0x%02x' % t)
    data = b''
    for off in sorted(chunks):
        if off != len(data):
            raise ValueError('gap in the CRYPTO stream')
        data += chunks[off]
    return data, seen


def _extensions(ch):
    """ClientHello (handshake message) -> (offset of the extensions block length, [(type, start, end)])"""
    if ch[0] != 1:
        raise ValueError('not a ClientHello')
    i = 4 + 2 + 32                         # handshake header, version, random
    i += 1 + ch[i]                         # session id
    i += 2 + struct.unpack('>H', ch[i:i + 2])[0]  # cipher suites
    i += 1 + ch[i]                         # compression methods
    ext_len_at = i
    end = i + 2 + struct.unpack('>H', ch[i:i + 2])[0]
    i += 2
    exts = []
    while i < end:
        t, ln = struct.unpack('>HH', ch[i:i + 4])
        exts.append((t, i, i + 4 + ln))
        i += 4 + ln
    return ext_len_at, exts


def _extensions_raw(ch, ext_len_at):
    """walk extensions until the end of the buffer (lengths above may be stale mid-edit)"""
    i, exts = ext_len_at + 2, []
    while i + 4 <= len(ch):
        t, ln = struct.unpack('>HH', ch[i:i + 4])
        exts.append((t, i, i + 4 + ln))
        i += 4 + ln
    return ext_len_at, exts


def get_sni(ch):
    for t, a, b in _extensions(ch)[1]:
        if t == 0:
            return ch[a + 9:b].decode()
    return None


def set_sni(ch, name):
    name = name.encode('ascii')
    ext_len_at, exts = _extensions(ch)
    for t, a, b in exts:
        if t == 0:
            sni = struct.pack('>HHHBH', 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
            ch = ch[:a] + sni + ch[b:]
            delta = len(sni) - (b - a)
            break
    else:
        raise ValueError('no server_name extension')
    # like a browser, give the length back through the padding extension: same ClientHello size
    _, exts = _extensions_raw(ch, ext_len_at)
    for t, a, b in exts:
        if t == 0x15 and b - a - 4 >= delta:
            pad = b - a - 4 - delta
            ch = ch[:a] + struct.pack('>HH', 0x15, pad) + b'\0' * pad + ch[b:]
            delta = 0
            break
    ext_len = struct.unpack('>H', ch[ext_len_at:ext_len_at + 2])[0] + delta
    ch = ch[:ext_len_at] + struct.pack('>H', ext_len) + ch[ext_len_at + 2:]
    body = len(ch) - 4
    return ch[:1] + body.to_bytes(3, 'big') + ch[4:]


def main(argv):
    if len(argv) >= 2 and argv[0] == 'show':
        pkt = open(argv[1], 'rb').read()
        dcid, scid, token, pt, ln = decrypt_initial(pkt)
        ch, seen = crypto_stream(pt)
        print('%s: %d bytes (Initial %d), DCID %s, SCID %s, token %d bytes' % (argv[1], len(pkt), ln, dcid.hex(), scid.hex() or '-', len(token)))
        print('frames:', ' '.join(seen))
        print('ClientHello %d bytes, SNI %s' % (len(ch), get_sni(ch)))
        return 0
    if len(argv) == 4 and argv[0] == 'make':
        pkt = open(argv[1], 'rb').read()
        _, scid, token, pt, ln = decrypt_initial(pkt)
        ch, _ = crypto_stream(pt)
        ch = set_sni(ch, argv[2])
        frame = b'\x06' + _enc_varint(0) + _enc_varint(len(ch)) + ch
        if len(frame) > len(pt):
            raise ValueError('the new name does not fit into the template')
        new_pt = frame + b'\0' * (len(pt) - len(frame))   # PADDING keeps the size
        out = encrypt_initial(os.urandom(8), scid, token, new_pt)
        out += pkt[ln:]                                       # anything coalesced after the Initial
        # read it back the way a DPI box would
        if get_sni(crypto_stream(decrypt_initial(out)[3])[0]) != argv[2]:
            raise ValueError('round trip failed')
        open(argv[3], 'wb').write(out)
        print('%s: %d bytes, SNI %s' % (argv[3], len(out), argv[2]))
        return 0
    print(__doc__.strip(), file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
