import io
import struct
import uuid
import tempfile


def _decode(content, encoding="utf-8"):
    try:
        return content.decode(encoding)
    except Exception:
        return content.decode("latin-1")


class Buf(object):
    def __init__(self, source):
        if (
            isinstance(source, io.IOBase)  # file-esque object
            or isinstance(source, tempfile._TemporaryFileWrapper)  # tempfile wrappers are not files???
            or hasattr(source, "_buf_magic")  # dirty hack for CryptoBuf
            or source.__class__.__name__ in ("mmap")  # mmap'ed files are also not files???
        ):
            self._file = source
        else:
            self._file = io.BytesIO(source)

        self._offset = 0

        pos = self.tell()
        self.seek(0, 2)
        self._size = self.tell()
        self.seek(pos)

        self.resetunit()
        self._target = self._size
        self._stack = []
        self._backup = []
        self._bits = 0

    @classmethod
    def of(cls, source):
        if isinstance(source, cls):
            return source
        else:
            return cls(source)

    def available(self):
        """Return the total amount of remaining bytes, ignoring any unit constraints."""
        return max(self._size - self.tell(), 0)

    def isend(self):
        """Return whether no more bytes are available."""
        return self.available() <= 0

    def size(self):
        """Return the size of the buf regardless of the cursor position."""
        return self._size

    def peek(self, length):
        """Read length bytes without changing any internal state."""
        if self._bits != 0:
            raise ValueError("unaligned")

        if self.unit is not None:
            unit = max(self.unit - length, 0)
            assert unit >= 0, f"unit overread by {-unit} byte{'s' if unit != -1 else ''}"

        pos = self.tell()
        data = self._file.read(length)
        self.seek(pos)
        return data

    def skip(self, length):
        """Skip length bytes."""
        if self._bits != 0:
            raise ValueError("unaligned")

        if self.unit is not None:
            self.unit = max(self.unit - length, 0)
            assert self.unit >= 0, f"unit overread by {-self.unit} byte{'s' if self.unit != -1 else ''}"
        self.seek(length, 1)

    def _checkunit(self):
        """Check whether the unit constraint is satisfied."""
        assert self.unit >= 0, f"unit overread by {-self.unit} byte{'s' if self.unit != -1 else ''}"

    def setunit(self, length):
        """Set the unit to the span from the cursor to the cursors + length."""
        self.unit = length
        self._target = self.tell() + length
        self._checkunit()

    def skipunit(self):
        """Skip to the end of the unit."""
        self.seek(self._target)
        self.unit = 0

    def readunit(self):
        """Read all bytes in the unit."""
        return self.read(self.unit)

    def resetunit(self):
        """Reset the unit"""
        self.unit = None

    def read(self, length=None, free=False):
        """Read length bytes, optionally ignore the unit constraint with free."""
        if self._bits != 0:
            raise ValueError("unaligned")

        if length is None:
            self.unit = None
            return self._file.read(self.available())
        else:
            if not free:
                if self.unit is not None:
                    self.unit -= length
                    self._checkunit()

                if self.available() < length:
                    self.unit = self.available() - length
                    self._checkunit()

            return self._file.read(length)

    def pushunit(self):
        """Push the current unit state on the stack."""
        self._stack.append((self.unit, self._target))

    def popunit(self):
        """Pop from the stack into the current unit state."""
        self.unit, t = self._stack.pop()
        if self.unit is not None:
            self.unit = max(t - self._target, 0)
        self._target = t

    def pasunit(self, val):
        """Push and set unit."""
        self.pushunit()
        self.setunit(val)

    def sapunit(self):
        """Skip and pop unit."""
        self.skipunit()
        self.popunit()

    def backup(self):
        """Return the entire internal state."""
        return (
            self.unit,
            self._target,
            self._stack,
            self.tell(),
            self._offset,
            self._size,
            self._bits,
        )

    def restore(self, bak):
        """Restore the entire internal state."""
        (
            self.unit,
            self._target,
            self._stack,
            offset,
            self._offset,
            self._size,
            self._bits,
        ) = bak
        self.seek(offset)

    def rl(self):
        """Read line."""
        line = b""
        while (self.unit is None or (self.unit > 0)) and self.available() > 0:
            c = self.read(1)
            if len(c) == 0:
                break

            if c[0] in (0x0a, 0x0d):
                if self.peek(1) != b"" and self.peek(1)[0] in (0x0a, 0x0d) and self.peek(1) != c:
                    self.skip(1)
                break

            line += c

        return line

    def pl(self):
        """Peek line."""
        with self:
            return self.rl()

    def tell(self):
        """Return the current cursor offset."""
        return self._file.tell() - self._offset

    def seek(self, pos, whence=0):
        """Seek to pos, this will probably break the unit stuff."""
        if whence == 0:
            pos += self._offset

        self._file.seek(pos, whence)

    def sub(self, size):
        """Return context manager to limit the buf to a sub buffer starting from the current cursor with a length of size."""
        assert size <= self.available(), "sub buffer is bigger than host buffer"

        class SubWrapper(object):
            def __enter__(self2):
                self2._offset = self._offset
                self2._size = self._size
                self2._bak = self.backup()
                self._offset += self.tell()
                self._size = size

                self.resetunit()

            def __exit__(self2, *args):
                self.restore(self2._bak)

        return SubWrapper()

    def subunit(self):
        """Return sub buffer with the limits of the current unit."""
        return self.sub(self.unit)

    def cut(self):
        """Return sub buffer with the remaining bytes."""
        return self.sub(self.available())

    def search(self, s, buf_length=1 << 24):
        """Search for and seek to a specific pattern or throw a ValueError if not found."""
        buf = b""
        while True:
            chunk = self.read(min(buf_length, self.unit if self.unit else self.available()))
            buf += chunk

            if (self.unit is not None and self.unit <= 0) or len(chunk) == 0:
                raise ValueError(f"pattern {s.hex()} not found")

            if s not in buf:
                buf = buf[-len(s) :]
            else:
                index = buf.index(s)
                overread = len(buf) - index
                if self.unit is not None:
                    self.unit += overread
                self.seek(-overread, 1)
                return

    def ru8(self):
        """Read an 8-bit unsigned big-endian integer."""
        return int.from_bytes(self.read(1), "big")

    def ru16(self):
        """Read a 16-bit unsigned big-endian integer."""
        return int.from_bytes(self.read(2), "big")

    def ru24(self):
        """Read a 24-bit unsigned big-endian integer."""
        return int.from_bytes(self.read(3), "big")

    def ru32(self):
        """Read a 32-bit unsigned big-endian integer."""
        return int.from_bytes(self.read(4), "big")

    def ru64(self):
        """Read a 64-bit unsigned big-endian integer."""
        return int.from_bytes(self.read(8), "big")

    def ri8(self):
        """Read an 8-bit signed big-endian integer."""
        return int.from_bytes(self.read(1), "big", signed=True)

    def ri16(self):
        """Read a 16-bit signed big-endian integer."""
        return int.from_bytes(self.read(2), "big", signed=True)

    def ri24(self):
        """Read a 24-bit signed big-endian integer."""
        return int.from_bytes(self.read(3), "big", signed=True)

    def ri32(self):
        """Read a 32-bit signed big-endian integer."""
        return int.from_bytes(self.read(4), "big", signed=True)

    def ri64(self):
        """Read a 64-bit signed big-endian integer."""
        return int.from_bytes(self.read(8), "big", signed=True)

    def ru8l(self):
        """Read an 8-bit unsigned little-endian integer."""
        return int.from_bytes(self.read(1), "little")

    def ru16l(self):
        """Read a 16-bit unsigned little-endian integer."""
        return int.from_bytes(self.read(2), "little")

    def ru24l(self):
        """Read a 24-bit unsigned little-endian integer."""
        return int.from_bytes(self.read(3), "little")

    def ru32l(self):
        """Read a 32-bit unsigned little-endian integer."""
        return int.from_bytes(self.read(4), "little")

    def ru64l(self):
        """Read a 64-bit unsigned little-endian integer."""
        return int.from_bytes(self.read(8), "little")

    def ri8l(self):
        """Read an 8-bit signed little-endian integer."""
        return int.from_bytes(self.read(1), "little", signed=True)

    def ri16l(self):
        """Read a 16-bit signed little-endian integer."""
        return int.from_bytes(self.read(2), "little", signed=True)

    def ri24l(self):
        """Read a 24-bit signed little-endian integer."""
        return int.from_bytes(self.read(3), "little", signed=True)

    def ri32l(self):
        """Read a 32-bit signed little-endian integer."""
        return int.from_bytes(self.read(4), "little", signed=True)

    def ri64l(self):
        """Read a 64-bit signed little-endian integer."""
        return int.from_bytes(self.read(8), "little", signed=True)

    def rf16(self):
        """Read a 16-bit big-endian floating point number."""
        return struct.unpack(">e", self.read(2))[0]

    def rf32(self):
        """Read a 32-bit big-endian floating point number."""
        return struct.unpack(">f", self.read(4))[0]

    def rf64(self):
        """Read a 64-bit big-endian floating point number."""
        return struct.unpack(">d", self.read(8))[0]

    def rf16l(self):
        """Read a 16-bit litle-endian floating point number."""
        return struct.unpack("<e", self.read(2))[0]

    def rf32l(self):
        """Read a 32-bit litle-endian floating point number."""
        return struct.unpack("<f", self.read(4))[0]

    def rf64l(self):
        """Read a 64-bit litle-endian floating point number."""
        return struct.unpack("<d", self.read(8))[0]

    def rfp16(self):
        """Read an 8.8 unsigned big-endian fixed point number."""
        return self.ru16() / 256

    def rfp32(self):
        """Read a 16.16 unsigned big-endian fixed point number."""
        return self.ru32() / 65536

    def rsfp16(self):
        """Read an 8.8 signed big-endian fixed point number."""
        return self.ri16() / 256

    def rsfp32(self):
        """Read a 16.16 signed big-endian fixed point number."""
        return self.ri32() / 65536

    def rfp16l(self):
        """Read an 8.8 unsigned little-endian fixed point number."""
        return self.ru16l() / 256

    def rfp32l(self):
        """Read a 16.16 unsigned little-endian fixed point number."""
        return self.ru32l() / 65536

    def rsfp16l(self):
        """Read an 8.8 signed little-endian fixed point number."""
        return self.ri16l() / 256

    def rsfp32l(self):
        """Read a 16.16 signed little-endian fixed point number."""
        return self.ri32l() / 65536

    def pu8(self):
        return int.from_bytes(self.peek(1), "big")

    def pu16(self):
        return int.from_bytes(self.peek(2), "big")

    def pu24(self):
        return int.from_bytes(self.peek(3), "big")

    def pu32(self):
        return int.from_bytes(self.peek(4), "big")

    def pu64(self):
        return int.from_bytes(self.peek(8), "big")

    def pi8(self):
        return int.from_bytes(self.peek(1), "big", signed=True)

    def pi16(self):
        return int.from_bytes(self.peek(2), "big", signed=True)

    def pi24(self):
        return int.from_bytes(self.peek(3), "big", signed=True)

    def pi32(self):
        return int.from_bytes(self.peek(4), "big", signed=True)

    def pi64(self):
        return int.from_bytes(self.peek(8), "big", signed=True)

    def pu8l(self):
        return int.from_bytes(self.peek(1), "little")

    def pu16l(self):
        return int.from_bytes(self.peek(2), "little")

    def pu24l(self):
        return int.from_bytes(self.peek(3), "little")

    def pu32l(self):
        return int.from_bytes(self.peek(4), "little")

    def pu64l(self):
        return int.from_bytes(self.peek(8), "little")

    def pi8l(self):
        return int.from_bytes(self.peek(1), "little", signed=True)

    def pi16l(self):
        return int.from_bytes(self.peek(2), "little", signed=True)

    def pi24l(self):
        return int.from_bytes(self.peek(3), "little", signed=True)

    def pi32l(self):
        return int.from_bytes(self.peek(4), "little", signed=True)

    def pi64l(self):
        return int.from_bytes(self.peek(8), "little", signed=True)

    def pf32(self):
        return struct.unpack(">f", self.peek(4))[0]

    def pf64(self):
        return struct.unpack(">d", self.peek(8))[0]

    def pf32l(self):
        return struct.unpack("<f", self.peek(4))[0]

    def pf64l(self):
        return struct.unpack("<d", self.peek(8))[0]

    def pfp16(self):
        return self.ru16() / 256

    def pfp32(self):
        return self.ru32l() / 65536

    def psfp16(self):
        return self.ri16l() / 256

    def psfp32(self):
        return self.ri32l() / 65536

    def pfp16l(self):
        return self.ru16l() / 256

    def pfp32l(self):
        return self.ru32l() / 65536

    def psfp16l(self):
        return self.ri16l() / 256

    def psfp32l(self):
        return self.ri32l() / 65536

    def rh(self, length):
        return self.read(length).hex()

    def ph(self, length):
        return self.peek(length).hex()

    def rs(self, length, encoding="utf-8", strip=True):
        s = _decode(self.read(length), encoding)
        if strip:
            s = s.rstrip("\x00")
        return s

    def ps(self, length, encoding="utf-8", strip=True):
        s = _decode(self.peek(length), encoding)
        if strip:
            s = s.rstrip("\x00")
        return s

    def rzs(self, encoding="utf-8"):
        s = b""
        while self.pu8():
            s += self.read(1)

        self.skip(1)

        return _decode(s, encoding)

    def rwzs(self):
        s = b""
        while self.pu16():
            s += self.read(2)

        self.skip(2)

        return s.decode("utf-16le")

    def pzs(self, encoding="utf-8"):
        pos = self.tell()

        s = b""
        while self.pu8():
            s += self._file.read(1)

        self.seek(pos)

        return _decode(s, encoding)

    def pwzs(self):
        pos = self.tell()

        s = b""
        while self.pu16():
            s += self._file.read(2)

        self.seek(pos)

        return s.decode("utf-16le")

    def ruuid(self):
        return str(uuid.UUID(bytes=self.read(16)))

    def puuid(self):
        return str(uuid.UUID(bytes=self.peek(16)))

    def rguid(self):
        guid = b""
        guid += self.read(4)[::-1]
        guid += self.read(2)[::-1]
        guid += self.read(2)[::-1]
        guid += self.read(8)

        return str(uuid.UUID(bytes=guid))

    def pguid(self):
        guid = b""

        with self:
            guid += self.read(4)[::-1]
            guid += self.read(2)[::-1]
            guid += self.read(2)[::-1]
            guid += self.read(8)

        return str(uuid.UUID(bytes=guid))

    def ruleb(self):
        c = self.ru8()
        v = c & 0x7f
        shift = 7

        while c & 0x80:
            c = self.ru8()
            v |= (c & 0x7f) << shift
            shift += 7

        return v

    def rubeb(self):
        c = self.ru8()
        v = c & 0x7f

        while c & 0x80:
            c = self.ru8()
            v = (v << 7) | (c & 0x7f)

        return v

    def puleb(self):
        with self.buf:
            return self.ruleb()

    def pubeb(self):
        with self.buf:
            return self.rubeb()

    def rb(self, count):
        i = 0

        c = self.pu8()
        while count:
            if self._bits >= 8:
                self._bits = 0
                self.skip(1)
                c = self.pu8()

            i <<= 1
            i |= (c >> (7 - self._bits)) & 0x01
            self._bits += 1
            count -= 1

        if self._bits >= 8:
            self._bits = 0
            self.skip(1)

        return i

    def rbl(self, count):
        i = 0
        shift = 0

        c = self.pu8()
        while count:
            if self._bits >= 8:
                self._bits = 0
                self.skip(1)
                c = self.pu8()

            i |= ((c >> self._bits) & 0x01) << shift
            shift += 1
            self._bits += 1
            count -= 1

        if self._bits >= 8:
            self._bits = 0
            self.skip(1)

        return i

    def rsb(self, count):
        v = self.rb(count)

        if v >= 2 ** (count - 1):
            v -= 2**count

        return v

    def pb(self, count):
        with self:
            return self.rb(count)

    def pbl(self, count):
        with self:
            return self.rbl(count)

    def psb(self, count):
        with self:
            return self.rsb(count)

    def rue(self):
        bits = 1
        while self.pb(1) == 0:
            bits += 1
            self.rb(1)

        return self.rb(bits) - 1

    def pue(self):
        with self:
            return self.rue()

    def riue(self):
        value = 1

        while self.rb(1) == 0:
            value <<= 1
            if self.rb(1) == 1:
                value += 1

        return value - 1

    def piue(self):
        with self:
            return self.riue()

    def align(self):
        if self._bits != 0:
            self._bits = 0
            self.skip(1)

    def __getattr__(self, name):
        # Delegate everything else to the underlying file
        return getattr(self._file, name)

    def __enter__(self):
        self._backup.append(self.backup())

    def __exit__(self, *args):
        self.restore(self._backup.pop())

    def __iter__(self):
        return iter(self._file)

    def __next__(self):
        return next(self._file)
