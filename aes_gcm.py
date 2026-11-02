"""Minimal AES-GCM (128/192/256-bit keys) decryption — pure stdlib.

The Artificial Analysis site ships its complete model dataset as
`/data/<hash>.txt`: AES-GCM ciphertext (tag appended) whose plaintext is gzip
compressed JSON. This module implements just enough AES + GHASH to open it
without pulling in pycryptodome/cryptography.

Verified against FIPS-197 AES-256 vector and the site's live payload.
"""

TAG_LEN = 16

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)

_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D]
_R = 0xE1 << 120


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x11B) if a & 0x100 else a


def _expand_key(key: bytes) -> list:
    """Return AES round keys as a flat list of 4-byte words."""
    nk = len(key) // 4
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24 or 32 bytes")
    nr = nk + 6
    w = [list(key[4 * i : 4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w


def _encrypt_block(block: bytes, w: list) -> bytes:
    nr = len(w) // 4 - 1
    s = [b ^ w[i // 4][i % 4] for i, b in enumerate(block)]

    def mix(a, b, c, d):
        return (
            _xtime(a) ^ (_xtime(b) ^ b) ^ c ^ d,
            a ^ _xtime(b) ^ (_xtime(c) ^ c) ^ d,
            a ^ b ^ _xtime(c) ^ (_xtime(d) ^ d),
            (_xtime(a) ^ a) ^ b ^ c ^ _xtime(d),
        )

    for rnd in range(1, nr + 1):
        s = [_SBOX[b] for b in s]
        s = [s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3],
             s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]]
        if rnd != nr:
            out = []
            for c in range(4):
                out.extend(mix(*s[4 * c : 4 * c + 4]))
            s = out
        s = [s[i] ^ w[4 * rnd + i // 4][i % 4] for i in range(16)]
    return bytes(s)


def _gmul(x: int, y: int) -> int:
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ _R if v & 1 else v >> 1
    return z


def _ghash(h: int, data: bytes) -> int:
    y = 0
    for i in range(0, len(data), 16):
        blk = data[i : i + 16]
        if len(blk) < 16:
            blk = blk + b"\x00" * (16 - len(blk))
        y = _gmul(y ^ int.from_bytes(blk, "big"), h)
    return y


def decrypt(key: bytes, iv: bytes, blob: bytes) -> bytes:
    """AES-GCM decrypt; `blob` is ciphertext followed by the 16-byte tag."""
    if len(blob) < TAG_LEN:
        raise ValueError("ciphertext too short")
    ct, tag = blob[:-TAG_LEN], blob[-TAG_LEN:]
    w = _expand_key(key)
    h = int.from_bytes(_encrypt_block(b"\x00" * 16, w), "big")
    j0 = iv + b"\x00\x00\x00\x01" if len(iv) == 12 else None
    if j0 is None:
        raise ValueError("only 12-byte IVs supported")
    # GHASH over ciphertext only (no AAD), then lengths block
    lens = (0).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big")
    s = _ghash(h, ct + b"\x00" * (-len(ct) % 16) + lens)
    ek_j0 = int.from_bytes(_encrypt_block(j0, w), "big")
    expect = (ek_j0 ^ s).to_bytes(16, "big")
    if expect != tag:
        raise ValueError("GCM tag mismatch — payload or key changed")

    out = bytearray()
    ctr = int.from_bytes(j0, "big")
    for off in range(0, len(ct), 16):
        ctr = (ctr & ~0xFFFFFFFF) | ((ctr + 1) & 0xFFFFFFFF)
        ks = _encrypt_block(ctr.to_bytes(16, "big"), w)
        out += bytes(a ^ b for a, b in zip(ct[off : off + 16], ks))
    return bytes(out)
