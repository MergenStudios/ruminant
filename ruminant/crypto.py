import os

try:
    if "RUMINANT_NATIVE_MODE" in os.environ:
        raise Exception()

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
        C1 = AES(K1)
        C2 = AES(K2)

        plaintext = b""

        sector = -1
        T = b""
        for i in range(offset, offset + len(ciphertext), 16):
            c = ciphertext[i : i + 16]

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
        self._page_size = 2**20

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
