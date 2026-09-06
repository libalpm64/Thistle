"""Implements the Poly1305 one-time authenticator from RFC 8439."""

from std.memory import Pointer
from std.collections import InlineArray

# limb masks for a 44 44 and 42 bit split
comptime _M44: UInt64 = 0xFFFFFFFFFFF
comptime _M42: UInt64 = 0x3FFFFFFFFFF


@always_inline
def _le64(ptr: Pointer[mut=False, UInt8, _, address_space=_], offset: Int) -> UInt64:
    return (ptr.unsafe_offset(offset)).unsafe_bitcast[UInt64]().unsafe_load[width=1, alignment=1]()


struct _RPower(Copyable, ImplicitlyCopyable, Movable):
    var r0: UInt64
    var r1: UInt64
    var r2: UInt64
    var s1: UInt64
    var s2: UInt64

    @always_inline
    def __init__(out self, r0: UInt64, r1: UInt64, r2: UInt64):
        self.r0 = r0
        self.r1 = r1
        self.r2 = r2
        self.s1 = r1 * 20
        self.s2 = r2 * 20

    @always_inline
    def __copyinit__(out self, copy: Self):
        self.r0 = copy.r0
        self.r1 = copy.r1
        self.r2 = copy.r2
        self.s1 = copy.s1
        self.s2 = copy.s2

    @always_inline
    def __moveinit__(out self, deinit take: Self):
        self.r0 = take.r0
        self.r1 = take.r1
        self.r2 = take.r2
        self.s1 = take.s1
        self.s2 = take.s2

    @always_inline
    def wipe(mut self):
        Pointer(to=self.r0).unsafe_store[volatile=True](0, UInt64(0))
        Pointer(to=self.r1).unsafe_store[volatile=True](0, UInt64(0))
        Pointer(to=self.r2).unsafe_store[volatile=True](0, UInt64(0))
        Pointer(to=self.s1).unsafe_store[volatile=True](0, UInt64(0))
        Pointer(to=self.s2).unsafe_store[volatile=True](0, UInt64(0))


@always_inline
def _mul_acc(
    h0: UInt64, h1: UInt64, h2: UInt64, r: _RPower,
    mut d0: UInt128, mut d1: UInt128, mut d2: UInt128
):
    d0 += UInt128(h0) * UInt128(r.r0) + UInt128(h1) * UInt128(r.s2) + UInt128(h2) * UInt128(r.s1)
    d1 += UInt128(h0) * UInt128(r.r1) + UInt128(h1) * UInt128(r.r0) + UInt128(h2) * UInt128(r.s2)
    d2 += UInt128(h0) * UInt128(r.r2) + UInt128(h1) * UInt128(r.r1) + UInt128(h2) * UInt128(r.r0)


@always_inline
def _reduce(mut h0: UInt64, mut h1: UInt64, mut h2: UInt64, d0: UInt128, d1: UInt128, d2: UInt128
):
    var c = d0 >> 44
    h0 = d0.cast[DType.uint64]() & _M44
    var e1 = d1 + c
    c = e1 >> 44
    h1 = e1.cast[DType.uint64]() & _M44
    var e2 = d2 + c
    c = e2 >> 42
    h2 = e2.cast[DType.uint64]() & _M42
    h0 += c.cast[DType.uint64]() * 5
    var c64 = h0 >> 44
    h0 &= _M44
    h1 += c64


@always_inline
def _limbs_at(ptr: Pointer[mut=False, UInt8, _, address_space=_], offset: Int, hibit: UInt64
) -> SIMD[DType.uint64, 4]:
    var t0 = _le64(ptr, offset)
    var t1 = _le64(ptr, offset + 8)
    return SIMD[DType.uint64, 4](
        t0 & _M44,
        ((t0 >> 44) | (t1 << 20)) & _M44,
        ((t1 >> 24) & _M42) | hibit,
        0
    )


struct Poly1305:
    """Poly1305 that keeps r mod 2 to the 130 minus 5 in three limbs and batches with Horner"""
    var r: _RPower
    var r2: _RPower
    var r3: _RPower
    var r4: _RPower
    var r5: _RPower
    var r6: _RPower
    var r7: _RPower
    var r8: _RPower
    var pad0: UInt64
    var pad1: UInt64
    var h0: UInt64
    var h1: UInt64
    var h2: UInt64
    var buf: InlineArray[UInt8, 16]
    var buf_len: Int
    var powers4_ready: Bool
    var powers8_ready: Bool
    var finalized: Bool

    def __init__(out self, key: Span[UInt8, ...]) raises:
        if len(key) != 32:
            raise Error("Poly1305 key must be 32 bytes")
        var kp = key.unsafe_ptr()
        var t0 = _le64(kp, 0)
        var t1 = _le64(kp, 8)
        self.r = _RPower(
            t0 & 0xFFC0FFFFFFF,
            ((t0 >> 44) | (t1 << 20)) & 0xFFFFFC0FFFF,
            (t1 >> 24) & 0x00FFFFFFC0F
        )
        self.pad0 = _le64(kp, 16)
        self.pad1 = _le64(kp, 24)
        self.h0 = 0
        self.h1 = 0
        self.h2 = 0
        self.buf = InlineArray[UInt8, 16](fill=0)
        self.buf_len = 0
        self.r2 = self.r
        self.r3 = self.r
        self.r4 = self.r
        self.r5 = self.r
        self.r6 = self.r
        self.r7 = self.r
        self.r8 = self.r
        self.powers4_ready = False
        self.powers8_ready = False
        self.finalized = False

    def __deinit__(deinit self):
        self.wipe()

    @no_inline
    def _make_powers4(mut self):
        self.r2 = Poly1305._rmul(self.r, self.r)
        self.r3 = Poly1305._rmul(self.r2, self.r)
        self.r4 = Poly1305._rmul(self.r2, self.r2)
        self.powers4_ready = True

    @no_inline
    def _make_powers8(mut self):
        if not self.powers4_ready:
            self._make_powers4()
        self.r5 = Poly1305._rmul(self.r4, self.r)
        self.r6 = Poly1305._rmul(self.r4, self.r2)
        self.r7 = Poly1305._rmul(self.r4, self.r3)
        self.r8 = Poly1305._rmul(self.r4, self.r4)
        self.powers8_ready = True

    @staticmethod
    def _rmul(a: _RPower, b: _RPower) -> _RPower:
        var d0 = UInt128(0)
        var d1 = UInt128(0)
        var d2 = UInt128(0)
        _mul_acc(a.r0, a.r1, a.r2, b, d0, d1, d2)
        var x0: UInt64 = 0
        var x1: UInt64 = 0
        var x2: UInt64 = 0
        _reduce(x0, x1, x2, d0, d1, d2)
        var c = x1 >> 44
        x1 &= _M44
        x2 += c
        c = x2 >> 42
        x2 &= _M42
        x0 += c * 5
        c = x0 >> 44
        x0 &= _M44
        x1 += c
        return _RPower(x0, x1, x2)

    @always_inline
    def _block(mut self, t0: UInt64, t1: UInt64, hibit: UInt64):
        self.h0 += t0 & _M44
        self.h1 += ((t0 >> 44) | (t1 << 20)) & _M44
        self.h2 += ((t1 >> 24) & _M42) | hibit
        var d0 = UInt128(0)
        var d1 = UInt128(0)
        var d2 = UInt128(0)
        _mul_acc(self.h0, self.h1, self.h2, self.r, d0, d1, d2)
        _reduce(self.h0, self.h1, self.h2, d0, d1, d2)

    @no_inline
    def _blocks8(mut self, ptr: Pointer[mut=False, UInt8, _, address_space=_], count8: Int
    ):
        var h0 = self.h0
        var h1 = self.h1
        var h2 = self.h2
        var off = 0
        for _ in range(count8):
            var m0 = _limbs_at(ptr, off, UInt64(1) << 40)
            var m1 = _limbs_at(ptr, off + 16, UInt64(1) << 40)
            var m2 = _limbs_at(ptr, off + 32, UInt64(1) << 40)
            var m3 = _limbs_at(ptr, off + 48, UInt64(1) << 40)
            var m4 = _limbs_at(ptr, off + 64, UInt64(1) << 40)
            var m5 = _limbs_at(ptr, off + 80, UInt64(1) << 40)
            var m6 = _limbs_at(ptr, off + 96, UInt64(1) << 40)
            var m7 = _limbs_at(ptr, off + 112, UInt64(1) << 40)
            var d0 = UInt128(0)
            var d1 = UInt128(0)
            var d2 = UInt128(0)
            _mul_acc(h0 + m0[0], h1 + m0[1], h2 + m0[2], self.r8, d0, d1, d2)
            _mul_acc(m1[0], m1[1], m1[2], self.r7, d0, d1, d2)
            _mul_acc(m2[0], m2[1], m2[2], self.r6, d0, d1, d2)
            _mul_acc(m3[0], m3[1], m3[2], self.r5, d0, d1, d2)
            _mul_acc(m4[0], m4[1], m4[2], self.r4, d0, d1, d2)
            _mul_acc(m5[0], m5[1], m5[2], self.r3, d0, d1, d2)
            _mul_acc(m6[0], m6[1], m6[2], self.r2, d0, d1, d2)
            _mul_acc(m7[0], m7[1], m7[2], self.r, d0, d1, d2)
            _reduce(h0, h1, h2, d0, d1, d2)
            off += 128
        self.h0 = h0
        self.h1 = h1
        self.h2 = h2

    @no_inline
    def _blocks4(mut self, ptr: Pointer[mut=False, UInt8, _, address_space=_], count4: Int
    ):
        var h0 = self.h0
        var h1 = self.h1
        var h2 = self.h2
        var off = 0
        for _ in range(count4):
            var m0 = _limbs_at(ptr, off, UInt64(1) << 40)
            var m1 = _limbs_at(ptr, off + 16, UInt64(1) << 40)
            var m2 = _limbs_at(ptr, off + 32, UInt64(1) << 40)
            var m3 = _limbs_at(ptr, off + 48, UInt64(1) << 40)
            var d0 = UInt128(0)
            var d1 = UInt128(0)
            var d2 = UInt128(0)
            _mul_acc(h0 + m0[0], h1 + m0[1], h2 + m0[2], self.r4, d0, d1, d2)
            _mul_acc(m1[0], m1[1], m1[2], self.r3, d0, d1, d2)
            _mul_acc(m2[0], m2[1], m2[2], self.r2, d0, d1, d2)
            _mul_acc(m3[0], m3[1], m3[2], self.r, d0, d1, d2)
            _reduce(h0, h1, h2, d0, d1, d2)
            off += 64
        self.h0 = h0
        self.h1 = h1
        self.h2 = h2

    def update(mut self, data: Span[UInt8, ...]):
        var n = len(data)
        if n == 0:
            return
        var ptr = data.unsafe_ptr()
        var i = 0

        if self.buf_len > 0:
            while self.buf_len < 16 and i < n:
                self.buf[self.buf_len] = ptr[unsafe_offset=i]
                self.buf_len += 1
                i += 1
            if self.buf_len == 16:
                var bp = self.buf.unsafe_ptr()
                self._block(_le64(bp, 0), _le64(bp, 8), UInt64(1) << 40)
                self.buf_len = 0

        var octs = (n - i) >> 7
        if octs > 0:
            if not self.powers8_ready:
                self._make_powers8()
            self._blocks8(ptr.unsafe_offset(i), octs)
            i += octs << 7

        var quads = (n - i) >> 6
        if quads > 0 and (self.powers4_ready or quads > 1):
            if not self.powers4_ready:
                self._make_powers4()
            self._blocks4(ptr.unsafe_offset(i), quads)
            i += quads << 6

        while i + 16 <= n:
            self._block(_le64(ptr, i), _le64(ptr, i + 8), UInt64(1) << 40)
            i += 16

        while i < n:
            self.buf[self.buf_len] = ptr[unsafe_offset=i]
            self.buf_len += 1
            i += 1

    def _finalize_into_unchecked(
        mut self, output: Pointer[mut=True, UInt8, _, address_space=_]
    ):
        if self.buf_len > 0:
            self.buf[self.buf_len] = 1
            for j in range(self.buf_len + 1, 16):
                self.buf[j] = 0
            var bp = self.buf.unsafe_ptr()
            self._block(_le64(bp, 0), _le64(bp, 8), 0)

        var h0 = self.h0
        var h1 = self.h1
        var h2 = self.h2
        var c = h1 >> 44
        h1 &= _M44
        h2 += c
        c = h2 >> 42
        h2 &= _M42
        h0 += c * 5
        c = h0 >> 44
        h0 &= _M44
        h1 += c
        c = h1 >> 44
        h1 &= _M44
        h2 += c
        c = h2 >> 42
        h2 &= _M42
        h0 += c * 5
        c = h0 >> 44
        h0 &= _M44
        h1 += c

        var g0 = h0 + 5
        c = g0 >> 44
        g0 &= _M44
        var g1 = h1 + c
        c = g1 >> 44
        g1 &= _M44
        var g2 = (h2 + c) - (UInt64(1) << 42)

        var mask = UInt64(0) - (g2 >> 63)
        g0 = (g0 & ~mask) | (h0 & mask)
        g1 = (g1 & ~mask) | (h1 & mask)
        g2 = (g2 & ~mask) | (h2 & mask)

        var t0 = self.pad0
        var t1 = self.pad1
        var f0 = UInt128(g0) + UInt128(t0 & _M44)
        var f1 = UInt128(g1) + UInt128(((t0 >> 44) | (t1 << 20)) & _M44) + (f0 >> 44)
        var f2 = UInt128(g2) + UInt128((t1 >> 24) & _M42) + (f1 >> 44)
        h0 = f0.cast[DType.uint64]() & _M44
        h1 = f1.cast[DType.uint64]() & _M44
        h2 = f2.cast[DType.uint64]() & _M42

        var o0 = h0 | (h1 << 44)
        var o1 = (h1 >> 20) | (h2 << 24)
        output.unsafe_bitcast[UInt64]().unsafe_store[alignment=1](0, o0)
        (output.unsafe_offset(8)).unsafe_bitcast[UInt64]().unsafe_store[alignment=1](0, o1)
        self.wipe()

    def finalize_into(
        mut self, output: Span[mut=True, UInt8, ...]
    ) raises:
        if self.finalized:
            raise Error("Poly1305 context is already finalized or wiped")
        if len(output) < 16:
            raise Error("Poly1305 output needs at least 16 writable bytes")
        self._finalize_into_unchecked(output.unsafe_ptr())

    def wipe(mut self):
        self.r.wipe()
        self.r2.wipe()
        self.r3.wipe()
        self.r4.wipe()
        self.r5.wipe()
        self.r6.wipe()
        self.r7.wipe()
        self.r8.wipe()
        Pointer(to=self.h0).unsafe_store[volatile=True](0, UInt64(0))
        Pointer(to=self.h1).unsafe_store[volatile=True](0, UInt64(0))
        Pointer(to=self.h2).unsafe_store[volatile=True](0, UInt64(0))
        Pointer(to=self.pad0).unsafe_store[volatile=True](0, UInt64(0))
        Pointer(to=self.pad1).unsafe_store[volatile=True](0, UInt64(0))
        var buf_ptr = self.buf.unsafe_ptr()
        for i in range(16):
            buf_ptr.unsafe_store[volatile=True](i, UInt8(0))
        self.buf_len = 0
        self.powers4_ready = False
        self.powers8_ready = False
        self.finalized = True


def poly1305_mac(
    key: Span[UInt8, ...],
    message: Span[UInt8, ...],
    output: Span[mut=True, UInt8, ...]
) raises:
    """one shot Poly1305 that clamps r then folds each block in and adds s at the end"""
    if len(output) < 16:
        raise Error("Poly1305 output needs at least 16 writable bytes")
    var p = Poly1305(key)
    p.update(message)
    p.finalize_into(output)
