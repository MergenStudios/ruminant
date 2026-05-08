import os
import hashlib
import math
import hmac

try:
    if "RUMINANT_NATIVE_MODE" in os.environ:
        raise Exception()

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        class AES:
            def __init__(self, key):
                assert len(key) in (16, 24, 32), "Unknown AES key length"
                self.cipher = Cipher(algorithms.AES(key), modes.ECB())

            def encrypt(self, block):
                encryptor = self.cipher.encryptor()
                return encryptor.update(block) + encryptor.finalize()

            def decrypt(self, block):
                decryptor = self.cipher.decryptor()
                return decryptor.update(block) + decryptor.finalize()

    except ModuleNotFoundError:
        # fallback
        from Crypto.Cipher import AES as _AES

        class AES:
            def __init__(self, key):
                assert len(key) in (16, 24, 32), "Unknown AES key length"
                self.cipher = _AES.new(key, _AES.MODE_ECB)

            def encrypt(self, block):
                return self.cipher.encrypt(block)

            def decrypt(self, block):
                return self.cipher.decrypt(block)

except Exception:

    class AES:
        SBOX = list(
            bytes.fromhex(
                "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
                + "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
                + "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
                + "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
                + "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
                + "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
                + "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
                + "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
            )
        )

        iSBOX = list(
            bytes.fromhex(
                "52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb"
                + "547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd125"
                + "72f8f66486689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d84"
                + "90d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b"
                + "3a9111414f67dcea97f2cfcef0b4e67396ac7422e7ad3585e2f937e81c75df6e"
                + "47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af4"
                + "1fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cef"
                + "a0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e169146355210c7d"
            )
        )

        RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

        def xtime(a):
            return (((a << 1) ^ 0x1b) & 0xff) if (a & 0x80) else (a << 1)

        def gmul(a, b):
            p = 0
            for _ in range(8):
                if b & 1:
                    p ^= a
                a = (((a << 1) ^ 0x1b) & 0xff) if (a & 0x80) else (a << 1)
                b >>= 1
            return p

        T0 = []
        for i in range(256):
            s = SBOX[i]
            t = (xtime(s) << 24) | (s << 16) | (s << 8) | (xtime(s) ^ s)
            T0.append(t & 0xffffffff)

        T1 = [((x << 24) | (x >> 8)) & 0xffffffff for x in T0]
        T2 = [((x << 16) | (x >> 16)) & 0xffffffff for x in T0]
        T3 = [((x << 8) | (x >> 24)) & 0xffffffff for x in T0]

        iT0 = []
        for i in range(256):
            s = iSBOX[i]
            t = (
                (gmul(s, 0x0e) << 24)
                | (gmul(s, 0x09) << 16)
                | (gmul(s, 0x0d) << 8)
                | gmul(s, 0x0b)
            )
            iT0.append(t & 0xffffffff)

        iT1 = [((x << 24) | (x >> 8)) & 0xffffffff for x in iT0]
        iT2 = [((x << 16) | (x >> 16)) & 0xffffffff for x in iT0]
        iT3 = [((x << 8) | (x >> 24)) & 0xffffffff for x in iT0]

        def __init__(self, key):
            self.key_size = len(key)
            assert self.key_size in (16, 24, 32), "Unknown AES key length"

            self.rounds = {16: 10, 24: 12, 32: 14}[self.key_size]
            self.round_keys = self._expand_key(key)

        def _expand_key(self, key):
            w = [int.from_bytes(key[i : i + 4]) for i in range(0, self.key_size, 4)]
            n = self.key_size // 4

            for i in range(n, 4 * (self.rounds + 1)):
                temp = w[i - 1]

                if i % n == 0:
                    temp = (
                        (self.SBOX[(temp >> 16) & 0xff] << 24)
                        ^ (self.SBOX[(temp >> 8) & 0xff] << 16)
                        ^ (self.SBOX[temp & 0xff] << 8)
                        ^ (self.SBOX[(temp >> 24) & 0xff])
                    ) ^ (self.RCON[i // n] << 24)
                elif n > 6 and i % n == 4:
                    temp = (
                        (self.SBOX[(temp >> 24) & 0xff] << 24)
                        ^ (self.SBOX[(temp >> 16) & 0xff] << 16)
                        ^ (self.SBOX[(temp >> 8) & 0xff] << 8)
                        ^ (self.SBOX[temp & 0xff])
                    )

                w.append(w[i - n] ^ temp)

            return w

        def encrypt(self, block):
            s = [int.from_bytes(block[i : i + 4]) for i in range(0, 16, 4)]

            for i in range(4):
                s[i] ^= self.round_keys[i]

            for r in range(1, self.rounds):
                rk = self.round_keys[r * 4 : (r + 1) * 4]
                t0 = (
                    self.T0[s[0] >> 24]
                    ^ self.T1[(s[1] >> 16) & 0xff]
                    ^ self.T2[(s[2] >> 8) & 0xff]
                    ^ self.T3[s[3] & 0xff]
                    ^ rk[0]
                )
                t1 = (
                    self.T0[s[1] >> 24]
                    ^ self.T1[(s[2] >> 16) & 0xff]
                    ^ self.T2[(s[3] >> 8) & 0xff]
                    ^ self.T3[s[0] & 0xff]
                    ^ rk[1]
                )
                t2 = (
                    self.T0[s[2] >> 24]
                    ^ self.T1[(s[3] >> 16) & 0xff]
                    ^ self.T2[(s[0] >> 8) & 0xff]
                    ^ self.T3[s[1] & 0xff]
                    ^ rk[2]
                )
                t3 = (
                    self.T0[s[3] >> 24]
                    ^ self.T1[(s[0] >> 16) & 0xff]
                    ^ self.T2[(s[1] >> 8) & 0xff]
                    ^ self.T3[s[2] & 0xff]
                    ^ rk[3]
                )
                s = [t0, t1, t2, t3]

            res = bytearray()
            rk = self.round_keys[self.rounds * 4 :]

            indices = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]

            flat_state = b"".join([x.to_bytes(4, "big") for x in s])
            for i in range(16):
                res.append(
                    self.SBOX[flat_state[indices[i]]]
                    ^ (rk[i // 4] >> (24 - 8 * (i % 4)) & 0xff)
                )

            return bytes(res)

        def decrypt(self, block):
            s = [int.from_bytes(block[i : i + 4]) for i in range(0, 16, 4)]

            rk_start = self.rounds * 4
            for i in range(4):
                s[i] ^= self.round_keys[rk_start + i]

            for r in range(self.rounds - 1, 0, -1):
                rk = self.round_keys[r * 4 : (r + 1) * 4]

                transformed_rk = []
                for k in rk:
                    tk = (
                        self.iT0[self.SBOX[(k >> 24) & 0xff]]
                        ^ self.iT1[self.SBOX[(k >> 16) & 0xff]]
                        ^ self.iT2[self.SBOX[(k >> 8) & 0xff]]
                        ^ self.iT3[self.SBOX[k & 0xff]]
                    )
                    transformed_rk.append(tk)

                t0 = (
                    self.iT0[s[0] >> 24]
                    ^ self.iT1[(s[3] >> 16) & 0xff]
                    ^ self.iT2[(s[2] >> 8) & 0xff]
                    ^ self.iT3[s[1] & 0xff]
                    ^ transformed_rk[0]
                )
                t1 = (
                    self.iT0[s[1] >> 24]
                    ^ self.iT1[(s[0] >> 16) & 0xff]
                    ^ self.iT2[(s[3] >> 8) & 0xff]
                    ^ self.iT3[s[2] & 0xff]
                    ^ transformed_rk[1]
                )
                t2 = (
                    self.iT0[s[2] >> 24]
                    ^ self.iT1[(s[1] >> 16) & 0xff]
                    ^ self.iT2[(s[0] >> 8) & 0xff]
                    ^ self.iT3[s[3] & 0xff]
                    ^ transformed_rk[2]
                )
                t3 = (
                    self.iT0[s[3] >> 24]
                    ^ self.iT1[(s[2] >> 16) & 0xff]
                    ^ self.iT2[(s[1] >> 8) & 0xff]
                    ^ self.iT3[s[0] & 0xff]
                    ^ transformed_rk[3]
                )
                s = [t0, t1, t2, t3]

            res = bytearray()
            rk = self.round_keys[0:4]

            indices = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3]

            flat_state = b"".join([x.to_bytes(4, "big") for x in s])
            for i in range(16):
                res.append(
                    self.iSBOX[flat_state[indices[i]]]
                    ^ (rk[i // 4] >> (24 - 8 * (i % 4)) & 0xff)
                )

            return bytes(res)


def aes_xts_plain64(K1, K2, sector_size):
    def gma(tweak):
        tweak = int.from_bytes(tweak, "little")
        carry = tweak >> 127
        tweak <<= 1
        if carry:
            tweak ^= 0x87
        tweak &= (2**128) - 1
        tweak = tweak.to_bytes(16, "little")
        return tweak

    def decrypt(offset, ciphertext):
        assert offset % 16 == 0, "unaligned"

        try:
            assert offset % sector_size == 0

            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

            plaintext = b""
            for i in range(0, len(ciphertext), sector_size):
                dec = Cipher(
                    algorithms.AES(K1 + K2),
                    modes.XTS(((i + offset) // 512).to_bytes(16, "little")),
                ).decryptor()
                plaintext += (
                    dec.update(ciphertext[i : i + sector_size]) + dec.finalize()
                )

            return plaintext
        except Exception:
            C1 = AES(K1)
            C2 = AES(K2)

            plaintext = b""

            sector = -1
            T = b""
            for i in range(offset, offset + len(ciphertext), 16):
                c = ciphertext[i - offset : i - offset + 16]

                if i // sector_size != sector:
                    sector = i // sector_size
                    T = C2.encrypt((i // 512).to_bytes(16, "little"))

                    for j in range(0, (i % sector_size) // 16):
                        T = gma(T)

                c = bytes([x ^ y for x, y in zip(c, T)])
                c = C1.decrypt(c)
                c = bytes([x ^ y for x, y in zip(c, T)])
                T = gma(T)

                plaintext += c

            return plaintext

    return decrypt


class CryptoBuf(object):
    _buf_magic = True

    def __init__(self, file, decrypt_function):
        self._file = file
        self._decrypt_function = decrypt_function

        file.seek(0, 2)
        self._size = file.tell()
        file.seek(0)

        self._cache = {}
        self._page_size = 65536

    def read(self, size=-1):
        if size == -1:
            size = self._size - self._file.tell()

        pos = self._file.tell()

        data = b""
        for page in range(
            (pos // self._page_size) * self._page_size,
            ((pos + size + self._page_size - 1) // self._page_size) * self._page_size,
            self._page_size,
        ):
            self._decrypt(page)
            data += self._cache[page]

        self._file.seek(pos + size)

        return data[pos % self._page_size : (pos % self._page_size) + size]

    def _decrypt(self, page):
        if page not in self._cache:
            self._file.seek(page)
            self._cache[page] = self._decrypt_function(
                page, self._file.read(self._page_size)
            )

    def write(self, data):
        raise NotImplementedError()

    def __getattr__(self, name):
        return getattr(self._file, name)


def poly1305(msg, key):
    P = (1 << 130) - 5

    assert len(key) == 32, "invalid key length"

    r_bytes = bytearray(key[0:16])
    s_bytes = key[16:32]

    r_bytes[3] &= 15
    r_bytes[7] &= 15
    r_bytes[11] &= 15
    r_bytes[15] &= 15
    r_bytes[4] &= 252
    r_bytes[8] &= 252
    r_bytes[12] &= 252

    r = int.from_bytes(r_bytes, "little")
    s = int.from_bytes(s_bytes, "little")

    a = 0

    for i in range(0, len(msg), 16):
        block = msg[i : i + 16]
        a = ((a + int.from_bytes(block, "little") + (1 << (8 * len(block)))) * r) % P

    a += s
    a %= 1 << 128

    return a.to_bytes(16, "little")


def rotl(a, b):
    return ((a << b) & 0xffffffff) | (a >> (32 - b))


def chacha_qr(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] ^= x[a]
    x[d] = rotl(x[d], 16)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] ^= x[c]
    x[b] = rotl(x[b], 12)
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] ^= x[a]
    x[d] = rotl(x[d], 8)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] ^= x[c]
    x[b] = rotl(x[b], 7)


def chacha_block(input_state):
    x = []
    for i in range(0, 64, 4):
        x.append(int.from_bytes(input_state[i : i + 4], "little"))
    y = list(x)

    for _ in range(0, 20, 2):
        chacha_qr(x, 0, 4, 8, 12)
        chacha_qr(x, 1, 5, 9, 13)
        chacha_qr(x, 2, 6, 10, 14)
        chacha_qr(x, 3, 7, 11, 15)
        chacha_qr(x, 0, 5, 10, 15)
        chacha_qr(x, 1, 6, 11, 12)
        chacha_qr(x, 2, 7, 8, 13)
        chacha_qr(x, 3, 4, 9, 14)

    x = [(x[i] + y[i]) & 0xffffffff for i in range(16)]
    out = b""
    for i in x:
        out += i.to_bytes(4, "little")

    return out


def chacha20(msg, key, nonce, counter=1):
    assert len(key) == 32, "invalid key length"
    assert len(nonce) in (8, 12), "invalid nonce length"

    ks = b""

    if len(nonce) == 8:
        for i in range(counter, (len(msg) + 63) // 64 + counter):
            ks += chacha_block(
                b"expand 32-byte k" + key + i.to_bytes(8, "little") + nonce
            )
    else:
        for i in range(counter, (len(msg) + 63) // 64 + counter):
            ks += chacha_block(
                b"expand 32-byte k" + key + i.to_bytes(4, "little") + nonce
            )

    return bytes([x ^ k for x, k in zip(msg, ks[: len(msg)])])


def chacha20_poly1305(msg, key, nonce, tag, aad=b""):
    assert len(tag) == 16, "invalid tag length"

    # lower throws asserts already
    poly1305_key = chacha20(bytes(32), key, nonce, counter=0)

    mac_data = b""
    mac_data += aad
    if len(mac_data) % 16 != 0:
        mac_data += bytes(16 - len(mac_data) % 16)
    mac_data += msg
    if len(mac_data) % 16 != 0:
        mac_data += bytes(16 - len(mac_data) % 16)
    mac_data += len(aad).to_bytes(8, "little")
    mac_data += len(msg).to_bytes(8, "little")

    assert poly1305(mac_data, poly1305_key) == tag, "tag mismatch"

    return chacha20(msg, key, nonce)


def hkdf_extract(salt, ikm):
    if salt is None or len(salt) == 0:
        salt = bytes([0] * hashlib.sha256().digest_size)
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length):
    hash_len = hashlib.sha256().digest_size
    assert length <= 255 * hash_len, "invalid length"

    t = b""
    okm = b""
    n = math.ceil(length / hash_len)

    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t

    return okm[:length]


def hkdf_sha256(ikm, length, salt=b"", info=b""):
    prk = hkdf_extract(salt, ikm)
    return hkdf_expand(prk, info, length)


def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(s):
    return [ord(x) >> 5 for x in s] + [0] + [ord(x) & 31 for x in s]


def bech32_verify_checksum(data):
    data = data.lower()
    hrp = "1".join(data.split("1")[:-1])
    data = [
        {
            "q": 0,
            "p": 1,
            "z": 2,
            "r": 3,
            "y": 4,
            "9": 5,
            "x": 6,
            "8": 7,
            "g": 8,
            "f": 9,
            "2": 10,
            "t": 11,
            "v": 12,
            "d": 13,
            "w": 14,
            "0": 15,
            "s": 16,
            "3": 17,
            "j": 18,
            "n": 19,
            "5": 20,
            "4": 21,
            "k": 22,
            "h": 23,
            "c": 24,
            "e": 25,
            "6": 26,
            "m": 27,
            "u": 28,
            "a": 29,
            "7": 30,
            "l": 31,
        }.get(x, 0)
        for x in data.split("1")[-1]
    ]

    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1


def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    return ret


def curve25519(base, scalar):
    P = 2**255 - 19

    assert len(base) == 32, "invalid base point length"
    assert len(scalar) == 32, "invalid scalar length"

    def point_add(point_n, point_m, point_diff):
        (xn, zn) = point_n
        (xm, zm) = point_m
        (x_diff, z_diff) = point_diff
        x = (z_diff << 2) * (xm * xn - zm * zn) ** 2
        z = (x_diff << 2) * (xm * zn - zm * xn) ** 2
        return x % P, z % P

    def point_double(point_n):
        (xn, zn) = point_n
        xn2 = xn**2
        zn2 = zn**2
        x = (xn2 - zn2) ** 2
        xzn = xn * zn
        z = 4 * xzn * (xn2 + 486662 * xzn + zn2)
        return x % P, z % P

    def const_time_swap(a, b, swap):
        """Swap two values in constant time"""
        index = int(swap) * 2
        temp = (a, b, b, a)
        return temp[index : index + 2]

    def _curve25519(base, n):
        """Raise the point base to the power n"""
        zero = (1, 0)
        one = (base, 1)
        mP, m1P = zero, one

        for i in reversed(range(256)):
            bit = bool(n & (1 << i))
            mP, m1P = const_time_swap(mP, m1P, bit)
            mP, m1P = point_double(mP), point_add(mP, m1P, one)
            mP, m1P = const_time_swap(mP, m1P, bit)

        x, z = mP
        inv_z = pow(z, P - 2, P)
        return (x * inv_z) % P

    base = int.from_bytes(base, "little")
    secret = int.from_bytes(scalar, "little") & ~7 & ~(128 << 8 * 31) | (64 << 8 * 31)

    return _curve25519(base, secret).to_bytes(32, "little")


has_argon2 = True
try:
    import argon2 as _argon2
except ImportError:
    has_argon2 = False


def argon2(secret, salt, iterations, memory, parallelism, hash_len, type, version=0x13):
    if not has_argon2:
        raise Exception()

    return _argon2.low_level.hash_secret_raw(
        secret,
        salt,
        iterations,
        memory,
        parallelism,
        hash_len,
        {
            "i": _argon2.low_level.Type.I,
            "d": _argon2.low_level.Type.D,
            "id": _argon2.low_level.Type.ID,
        }.get(type),
        version,
    )


def aes_cbc_pkcs7(key, iv, input_text, decrypt=True):
    assert len(iv) == 16, "invalid IV length"

    f = AES(key).decrypt if decrypt else AES(key).encrypt

    output_text = b""
    input_text = iv + input_text

    if decrypt:
        for i in range(16, len(input_text), 16):
            output_text += bytes([
                x ^ y for x, y in zip(input_text[i - 16 : i], f(input_text[i : i + 16]))
            ])
    else:
        for i in range(16, len(input_text), 16):
            output_text += f(
                bytes([
                    x ^ y
                    for x, y in zip(input_text[i - 16 : i], input_text[i : i + 16])
                ])
            )

    padding = output_text[-1]
    assert padding > 0 and padding <= 16, "invalid padding"

    for i in range(0, padding):
        assert output_text[-1 - i] == padding

    return output_text[:-padding]
