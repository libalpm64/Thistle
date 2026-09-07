"""PBKDF2 (RFC 8018, sec. 5.2) and HMAC (RFC 2104) with SHA-2 (FIPS 180-4)."""
from std.collections import List
from std.memory import unsafe_memcpy, Pointer
from std.builtin.simd import SIMD
from std.builtin.dtype import DType
from .utils import StackBuffer
from .sha2 import (
    SHA384_IV,
    SHA256Context,
    SHA512Context,
    sha384_hash,
    sha256_hash,
    sha256_update,
    sha256_final_to_buffer,
    sha512_update,
    sha512_final_to_buffer,
    sha512_final_with_len
)

comptime PBKDF2_SHA256_MAX_DKLEN: Int = 0xFFFFFFFF * 32
comptime PBKDF2_SHA512_MAX_DKLEN: Int = 0xFFFFFFFF * 64


@always_inline
def _secure_zero(ptr: Pointer[mut=True, UInt8, _, address_space=_], count: Int):
    # Volatile stores preserve password and pad wiping against dead-store elimination.
    for i in range(count):
        ptr.unsafe_store[volatile=True](i, UInt8(0))


@always_inline
def _xor_block[WIDTH: Int](dst: Pointer[mut=True, UInt8, _, address_space=_], src: Pointer[mut=True, UInt8, _, address_space=_]
):
    # XOR each U value into the PBKDF2 block accumulator without early exits.
    var d = dst.unsafe_bitcast[UInt64]().unsafe_load[width=WIDTH, alignment=1]()
    var s = src.unsafe_bitcast[UInt64]().unsafe_load[width=WIDTH, alignment=1]()
    dst.unsafe_bitcast[UInt64]().unsafe_store[width=WIDTH, alignment=1](0, d ^ s)


trait HMACer(Movable):
    """HMAC backend for the shared PBKDF2 loop, including a salt-and-counter first round."""
    comptime BLOCK: Int
    comptime HASH: Int
    def hmac(mut self, data: Span[UInt8, ...]): ...
    def hmac_with_counter(mut self, data: Span[UInt8, ...], counter: UInt32): ...
    def _hmac_fixed_unchecked(mut self, data: Span[UInt8, ...]): ...
    def u_block_ptr(mut self) -> Pointer[UInt8, MutUntrackedOrigin]: ...


@always_inline
def _pbkdf2_derive[H: HMACer](mut h: H, salt: Span[UInt8, ...], iterations: Int, dklen: Int) raises -> List[UInt8]:
    """Derive blocks T_i = U_1 XOR ... XOR U_c, where U_1 = PRF(P, S || INT32_BE(i)) and U_j =
    PRF(P, U_{j-1}) (RFC 8018, sec. 5.2).
    """
    if iterations < 1:
        raise Error("PBKDF2 iterations must be positive")
    comptime hLen = H.HASH
    if dklen < 1 or dklen > 0xFFFFFFFF * hLen:
        raise Error("PBKDF2 dkLen exceeds the RFC 8018 limit")
    var num_blocks = dklen // hLen
    if dklen % hLen != 0:
        num_blocks += 1
    var derived_key = List[UInt8](capacity=dklen)
    var t_block = InlineArray[UInt8, 64](fill=0)
    var input_block = InlineArray[UInt8, 64](fill=0)
    for block_idx in range(1, num_blocks + 1):
        h.hmac_with_counter(salt, UInt32(block_idx))
        unsafe_memcpy(dest=t_block.unsafe_ptr(), src=h.u_block_ptr(), count=hLen)
        for _ in range(1, iterations):
            unsafe_memcpy(dest=input_block.unsafe_ptr(), src=h.u_block_ptr(), count=hLen)
            h._hmac_fixed_unchecked(
                Span[UInt8, ...](unsafe_ptr=input_block.unsafe_ptr(), length=hLen)
            )
            comptime if hLen == 32:
                _xor_block[4](t_block.unsafe_ptr(), h.u_block_ptr())
            else:
                _xor_block[8](t_block.unsafe_ptr(), h.u_block_ptr())
        var remaining = dklen - len(derived_key)
        var to_copy = hLen if remaining > hLen else remaining
        for b in range(to_copy):
            derived_key.append(t_block[b])
    _secure_zero(t_block.unsafe_ptr(), 64)
    _secure_zero(input_block.unsafe_ptr(), 64)
    return derived_key^


struct PBKDF2SHA256(HMACer):
    """Cache HMAC-SHA-256 pad states for PBKDF2 derivations with one password (RFC 2104, sec. 4)."""
    comptime BLOCK = 64
    comptime HASH = 32
    var ipad: StackBuffer[UInt8, 64]
    var opad: StackBuffer[UInt8, 64]
    var inner_hash: StackBuffer[UInt8, 32]
    var u_block: StackBuffer[UInt8, 32]
    var counter_bytes: StackBuffer[UInt8, 4]
    var inner_ctx: SHA256Context
    var outer_ctx: SHA256Context
    var inner_state: SIMD[DType.uint32, 8]
    var outer_state: SIMD[DType.uint32, 8]
    def u_block_ptr(mut self) -> Pointer[UInt8, MutUntrackedOrigin]:
        return self.u_block.ptr().unsafe_origin_cast[MutUntrackedOrigin]()

    def __init__(out self, password: Span[UInt8, ...]):
        self.ipad = StackBuffer[UInt8, 64](fill=0)
        self.opad = StackBuffer[UInt8, 64](fill=0)
        self.inner_hash = StackBuffer[UInt8, 32](fill=0)
        self.u_block = StackBuffer[UInt8, 32](fill=0)
        self.counter_bytes = StackBuffer[UInt8, 4](fill=0)
        self.inner_ctx = SHA256Context()
        self.outer_ctx = SHA256Context()

        var k = StackBuffer[UInt8, 64](fill=0)

        if len(password) > 64:
            var ctx = SHA256Context()
            sha256_update(ctx, password)
            sha256_final_to_buffer(ctx, k.ptr())
        else:
            for i in range(len(password)):
                k[i] = password[i]

        for i in range(64):
            self.ipad[i] = k[i] ^ 0x36
            self.opad[i] = k[i] ^ 0x5C
        _secure_zero(k.ptr(), 64)
        sha256_update(self.inner_ctx, Span[UInt8, ...](unsafe_ptr=self.ipad.ptr(), length=64))
        sha256_update(self.outer_ctx, Span[UInt8, ...](unsafe_ptr=self.opad.ptr(), length=64))
        self.inner_state = self.inner_ctx.state
        self.outer_state = self.outer_ctx.state

    def __deinit__(deinit self):
        _secure_zero(Pointer(to=self.inner_state).unsafe_bitcast[UInt8](), 32)
        _secure_zero(Pointer(to=self.outer_state).unsafe_bitcast[UInt8](), 32)
        _secure_zero(self.ipad.ptr(), 64)
        _secure_zero(self.opad.ptr(), 64)
        _secure_zero(self.inner_hash.ptr(), 32)
        _secure_zero(self.u_block.ptr(), 32)
        _secure_zero(self.counter_bytes.ptr(), 4)

    @always_inline
    def hmac(mut self, data: Span[UInt8, ...]):
        """Compute HMAC-SHA-256 from copies of the cached inner and outer states (RFC 2104, sec.
        2).
        """
        self.inner_ctx.reset(self.inner_state)
        self.inner_ctx.count = 512
        sha256_update(self.inner_ctx, data)
        sha256_final_to_buffer(self.inner_ctx, self.inner_hash.ptr())

        self.outer_ctx.reset(self.outer_state)
        self.outer_ctx.count = 512
        sha256_update(self.outer_ctx, Span[UInt8, ...](unsafe_ptr=self.inner_hash.ptr(), length=32))
        sha256_final_to_buffer(self.outer_ctx, self.u_block.ptr())

    @always_inline
    def _hmac_fixed_unchecked(mut self, data: Span[UInt8, ...]):
        # Unchecked PBKDF2 round: data must contain exactly 32 bytes.
        self.inner_ctx.state = self.inner_state
        self.inner_ctx.count = 512
        for i in range(32):
            self.inner_ctx.buffer[i] = data[i]
        self.inner_ctx.buffer_len = 32
        sha256_final_to_buffer(self.inner_ctx, self.inner_hash.ptr())

        self.outer_ctx.state = self.outer_state
        self.outer_ctx.count = 512
        for i in range(32):
            self.outer_ctx.buffer[i] = self.inner_hash[i]
        self.outer_ctx.buffer_len = 32
        sha256_final_to_buffer(self.outer_ctx, self.u_block.ptr())

    @always_inline
    def hmac_with_counter(mut self, data: Span[UInt8, ...], counter: UInt32):
        """Compute U_1 from the salt followed by a 32-bit big-endian block counter (RFC 8018,
        sec. 5.2).
        """
        self.counter_bytes[0] = UInt8((counter >> 24) & 0xFF)
        self.counter_bytes[1] = UInt8((counter >> 16) & 0xFF)
        self.counter_bytes[2] = UInt8((counter >> 8) & 0xFF)
        self.counter_bytes[3] = UInt8(counter & 0xFF)

        self.inner_ctx.reset(self.inner_state)
        self.inner_ctx.count = 512
        sha256_update(self.inner_ctx, data)
        sha256_update(self.inner_ctx, Span[UInt8, ...](unsafe_ptr=self.counter_bytes.ptr(), length=4))
        sha256_final_to_buffer(self.inner_ctx, self.inner_hash.ptr())

        self.outer_ctx.reset(self.outer_state)
        self.outer_ctx.count = 512
        sha256_update(self.outer_ctx, Span[UInt8, ...](unsafe_ptr=self.inner_hash.ptr(), length=32))
        sha256_final_to_buffer(self.outer_ctx, self.u_block.ptr())

    @always_inline
    def derive(mut self, salt: Span[UInt8, ...], iterations: Int, dklen: Int) raises -> List[UInt8]:
        """Derive dklen bytes using the cached password state and the requested iteration
        count.
        """
        return _pbkdf2_derive(self, salt, iterations, dklen)


def pbkdf2_hmac_sha256(
    password: Span[UInt8, ...], salt: Span[UInt8, ...], iterations: Int, dkLen: Int
) raises -> List[UInt8]:
    """Derive dkLen bytes with PBKDF2-HMAC-SHA-256 (RFC 8018, sec. 5.2)."""
    if iterations < 1:
        raise Error("PBKDF2 iterations must be at least 1")
    if dkLen < 1:
        raise Error("PBKDF2 dkLen must be at least 1")
    if dkLen > PBKDF2_SHA256_MAX_DKLEN:
        raise Error("PBKDF2-SHA256 dkLen exceeds the RFC 8018 limit")
    var ctx = PBKDF2SHA256(password)
    return ctx.derive(salt, iterations, dkLen)


struct PBKDF2SHA512(HMACer):
    """Cache HMAC-SHA-512 pad states for PBKDF2 derivations with one password (RFC 2104, sec. 4)."""
    comptime BLOCK = 128
    comptime HASH = 64
    var ipad: StackBuffer[UInt8, 128]
    var opad: StackBuffer[UInt8, 128]
    var inner_hash: StackBuffer[UInt8, 64]
    var u_block: StackBuffer[UInt8, 64]
    var counter_bytes: StackBuffer[UInt8, 4]
    var inner_ctx: SHA512Context
    var outer_ctx: SHA512Context
    var inner_state: SIMD[DType.uint64, 8]
    var outer_state: SIMD[DType.uint64, 8]
    def u_block_ptr(mut self) -> Pointer[UInt8, MutUntrackedOrigin]:
        return self.u_block.ptr().unsafe_origin_cast[MutUntrackedOrigin]()

    def __init__(out self, password: Span[UInt8, ...]):
        self.ipad = StackBuffer[UInt8, 128](fill=0)
        self.opad = StackBuffer[UInt8, 128](fill=0)
        self.inner_hash = StackBuffer[UInt8, 64](fill=0)
        self.u_block = StackBuffer[UInt8, 64](fill=0)
        self.counter_bytes = StackBuffer[UInt8, 4](fill=0)
        self.inner_ctx = SHA512Context()
        self.outer_ctx = SHA512Context()

        var k = StackBuffer[UInt8, 128](fill=0)

        if len(password) > 128:
            var ctx = SHA512Context()
            sha512_update(ctx, password)
            sha512_final_to_buffer(ctx, k.ptr())
        else:
            for i in range(len(password)):
                k[i] = password[i]

        for i in range(128):
            self.ipad[i] = k[i] ^ 0x36
            self.opad[i] = k[i] ^ 0x5C
        _secure_zero(k.ptr(), 128)
        sha512_update(self.inner_ctx, Span[UInt8, ...](unsafe_ptr=self.ipad.ptr(), length=128))
        sha512_update(self.outer_ctx, Span[UInt8, ...](unsafe_ptr=self.opad.ptr(), length=128))
        self.inner_state = self.inner_ctx.state
        self.outer_state = self.outer_ctx.state

    def __deinit__(deinit self):
        _secure_zero(Pointer(to=self.inner_state).unsafe_bitcast[UInt8](), 64)
        _secure_zero(Pointer(to=self.outer_state).unsafe_bitcast[UInt8](), 64)
        _secure_zero(self.ipad.ptr(), 128)
        _secure_zero(self.opad.ptr(), 128)
        _secure_zero(self.inner_hash.ptr(), 64)
        _secure_zero(self.u_block.ptr(), 64)
        _secure_zero(self.counter_bytes.ptr(), 4)

    @always_inline
    def hmac(mut self, data: Span[UInt8, ...]):
        """Compute HMAC-SHA-512 from copies of the cached inner and outer states (RFC 2104, sec.
        2).
        """
        self.inner_ctx.reset(self.inner_state)
        self.inner_ctx.count_low = 1024
        sha512_update(self.inner_ctx, data)
        sha512_final_to_buffer(self.inner_ctx, self.inner_hash.ptr())

        self.outer_ctx.reset(self.outer_state)
        self.outer_ctx.count_low = 1024
        sha512_update(self.outer_ctx, Span[UInt8, ...](unsafe_ptr=self.inner_hash.ptr(), length=64))
        sha512_final_to_buffer(self.outer_ctx, self.u_block.ptr())

    @always_inline
    def _hmac_fixed_unchecked(mut self, data: Span[UInt8, ...]):
        # Unchecked PBKDF2 round: data must contain exactly 64 bytes.
        self.inner_ctx.state = self.inner_state
        self.inner_ctx.count_high = 0
        self.inner_ctx.count_low = 1024
        for i in range(64):
            self.inner_ctx.buffer[i] = data[i]
        self.inner_ctx.buffer_len = 64
        sha512_final_to_buffer(self.inner_ctx, self.inner_hash.ptr())

        self.outer_ctx.state = self.outer_state
        self.outer_ctx.count_high = 0
        self.outer_ctx.count_low = 1024
        for i in range(64):
            self.outer_ctx.buffer[i] = self.inner_hash[i]
        self.outer_ctx.buffer_len = 64
        sha512_final_to_buffer(self.outer_ctx, self.u_block.ptr())

    @always_inline
    def hmac_with_counter(mut self, data: Span[UInt8, ...], counter: UInt32):
        """Compute U_1 from the salt followed by a 32-bit big-endian block counter (RFC 8018,
        sec. 5.2).
        """
        self.counter_bytes[0] = UInt8((counter >> 24) & 0xFF)
        self.counter_bytes[1] = UInt8((counter >> 16) & 0xFF)
        self.counter_bytes[2] = UInt8((counter >> 8) & 0xFF)
        self.counter_bytes[3] = UInt8(counter & 0xFF)

        self.inner_ctx.reset(self.inner_state)
        self.inner_ctx.count_low = 1024
        sha512_update(self.inner_ctx, data)
        sha512_update(self.inner_ctx, Span[UInt8, ...](unsafe_ptr=self.counter_bytes.ptr(), length=4))
        sha512_final_to_buffer(self.inner_ctx, self.inner_hash.ptr())

        self.outer_ctx.reset(self.outer_state)
        self.outer_ctx.count_low = 1024
        sha512_update(self.outer_ctx, Span[UInt8, ...](unsafe_ptr=self.inner_hash.ptr(), length=64))
        sha512_final_to_buffer(self.outer_ctx, self.u_block.ptr())

    @always_inline
    def derive(mut self, salt: Span[UInt8, ...], iterations: Int, dklen: Int) raises -> List[UInt8]:
        """Derive dklen bytes using the cached password state and the requested iteration
        count.
        """
        return _pbkdf2_derive(self, salt, iterations, dklen)


def pbkdf2_hmac_sha512(
    password: Span[UInt8, ...], salt: Span[UInt8, ...], iterations: Int, dkLen: Int
) raises -> List[UInt8]:
    """Derive dkLen bytes with PBKDF2-HMAC-SHA-512 (RFC 8018, sec. 5.2)."""
    if iterations < 1:
        raise Error("PBKDF2 iterations must be at least 1")
    if dkLen < 1:
        raise Error("PBKDF2 dkLen must be at least 1")
    if dkLen > PBKDF2_SHA512_MAX_DKLEN:
        raise Error("PBKDF2-SHA512 dkLen exceeds the RFC 8018 limit")
    var ctx = PBKDF2SHA512(password)
    return ctx.derive(salt, iterations, dkLen)


trait RFC6979HMAC(Movable):
    """HMAC backend for deterministic nonce generation (RFC 6979, sec. 3.2)."""
    def __init__(out self, key: Span[UInt8, ...]): ...
    def hmac_into(mut self, data: Span[UInt8, ...], output: Pointer[mut=True, UInt8, _, address_space=_]): ...


struct HMACSHA256State(RFC6979HMAC):
    """Cache keyed SHA-256 inner and outer states for repeated HMAC operations (RFC 2104, sec.
    4).
    """
    var inner_state: SIMD[DType.uint32, 8]
    var outer_state: SIMD[DType.uint32, 8]

    def __init__(out self, key: Span[UInt8, ...]):
        var k = StackBuffer[UInt8, 64](fill=0)
        if len(key) > 64:
            var kh = sha256_hash(key)
            unsafe_memcpy(dest=k.ptr(), src=kh.unsafe_ptr(), count=32)
            var khp = kh.unsafe_ptr()
            for i in range(32):
                khp.unsafe_store[volatile=True](i, UInt8(0))
        else:
            for i in range(len(key)):
                k[i] = key[i]
        var ipad = StackBuffer[UInt8, 64](fill=0)
        var opad = StackBuffer[UInt8, 64](fill=0)
        for i in range(64):
            ipad[i] = k[i] ^ 0x36
            opad[i] = k[i] ^ 0x5C
        var inner = SHA256Context()
        sha256_update(inner, Span[UInt8, ...](unsafe_ptr=ipad.ptr(), length=64))
        self.inner_state = inner.state
        var outer = SHA256Context()
        sha256_update(outer, Span[UInt8, ...](unsafe_ptr=opad.ptr(), length=64))
        self.outer_state = outer.state
        _secure_zero(k.ptr(), 64)
        _secure_zero(ipad.ptr(), 64)
        _secure_zero(opad.ptr(), 64)

    def __deinit__(deinit self):
        var ip = Pointer(to=self.inner_state).unsafe_bitcast[UInt32]()
        var op = Pointer(to=self.outer_state).unsafe_bitcast[UInt32]()
        for i in range(8):
            ip.unsafe_store[volatile=True](i, UInt32(0))
            op.unsafe_store[volatile=True](i, UInt32(0))

    @always_inline
    def hmac_into(mut self, data: Span[UInt8, ...], output: Pointer[mut=True, UInt8, _, address_space=_]):
        """Write a 32-byte HMAC-SHA-256 tag without consuming the cached keyed states."""
        var inner = SHA256Context(self.inner_state)
        inner.count = 512
        sha256_update(inner, data)
        var digest = StackBuffer[UInt8, 32](fill=0)
        sha256_final_to_buffer(inner, digest.ptr())
        var outer = SHA256Context(self.outer_state)
        outer.count = 512
        sha256_update(outer, Span[UInt8, ...](unsafe_ptr=digest.ptr(), length=32))
        sha256_final_to_buffer(outer, output)
        _secure_zero(digest.ptr(), 32)


struct HMACSHA384State(RFC6979HMAC):
    """Cache keyed SHA-384 inner and outer states for repeated HMAC operations (RFC 2104, sec.
    4).
    """
    var inner_state: SIMD[DType.uint64, 8]
    var outer_state: SIMD[DType.uint64, 8]

    def __init__(out self, key: Span[UInt8, ...]):
        var k = StackBuffer[UInt8, 128](fill=0)
        if len(key) > 128:
            var kh = sha384_hash(key)
            unsafe_memcpy(dest=k.ptr(), src=kh.unsafe_ptr(), count=48)
            var khp = kh.unsafe_ptr()
            for i in range(48):
                khp.unsafe_store[volatile=True](i, UInt8(0))
        else:
            for i in range(len(key)):
                k[i] = key[i]
        var ipad = StackBuffer[UInt8, 128](fill=0)
        var opad = StackBuffer[UInt8, 128](fill=0)
        for i in range(128):
            ipad[i] = k[i] ^ 0x36
            opad[i] = k[i] ^ 0x5C
        var inner = SHA512Context(SHA384_IV)
        sha512_update(inner, Span[UInt8, ...](unsafe_ptr=ipad.ptr(), length=128))
        self.inner_state = inner.state
        var outer = SHA512Context(SHA384_IV)
        sha512_update(outer, Span[UInt8, ...](unsafe_ptr=opad.ptr(), length=128))
        self.outer_state = outer.state
        _secure_zero(k.ptr(), 128)
        _secure_zero(ipad.ptr(), 128)
        _secure_zero(opad.ptr(), 128)

    def __deinit__(deinit self):
        var ip = Pointer(to=self.inner_state).unsafe_bitcast[UInt64]()
        var op = Pointer(to=self.outer_state).unsafe_bitcast[UInt64]()
        for i in range(8):
            ip.unsafe_store[volatile=True](i, UInt64(0))
            op.unsafe_store[volatile=True](i, UInt64(0))

    @always_inline
    def hmac_into(mut self, data: Span[UInt8, ...], output: Pointer[mut=True, UInt8, _, address_space=_]):
        """Write a 48-byte HMAC-SHA-384 tag without consuming the cached keyed states."""
        var inner = SHA512Context(self.inner_state)
        inner.count_low = 1024
        var digest = StackBuffer[UInt8, 64](fill=0)
        sha512_update(inner, data)
        sha512_final_to_buffer(inner, digest.ptr())
        var outer = SHA512Context(self.outer_state)
        outer.count_low = 1024
        sha512_update(outer, Span[UInt8, ...](unsafe_ptr=digest.ptr(), length=48))
        sha512_final_to_buffer(outer, digest.ptr())
        for i in range(48):
            output.unsafe_store(i, digest[i])
        _secure_zero(digest.ptr(), 64)


def hmac_sha256(key: Span[UInt8, ...], data: Span[UInt8, ...]) -> List[UInt8]:
    """Return the 32-byte HMAC-SHA-256 tag for key and data (RFC 2104, sec. 2)."""
    var ctx = PBKDF2SHA256(key)
    ctx.hmac(data)
    var result = List[UInt8](capacity=32)
    for i in range(32):
        result.append(ctx.u_block[i])
    return result^


def hmac_sha512(key: Span[UInt8, ...], data: Span[UInt8, ...]) -> List[UInt8]:
    """Return the 64-byte HMAC-SHA-512 tag for key and data (RFC 2104, sec. 2)."""
    var ctx = PBKDF2SHA512(key)
    ctx.hmac(data)
    var result = List[UInt8](capacity=64)
    for i in range(64):
        result.append(ctx.u_block[i])
    return result^


def hmac_sha384(key: Span[UInt8, ...], data: Span[UInt8, ...]) -> List[UInt8]:
    """Return the 48-byte HMAC-SHA-384 tag for key and data (RFC 2104, sec. 2)."""
    var k = StackBuffer[UInt8, 128](fill=0)
    if len(key) > 128:
        var kh = sha384_hash(key)
        unsafe_memcpy(dest=k.ptr(), src=kh.unsafe_ptr(), count=48)
        var khp = kh.unsafe_ptr()
        for i in range(48):
            khp.unsafe_store[volatile=True](i, UInt8(0))
    else:
        for i in range(len(key)):
            k[i] = key[i]

    var ipad = StackBuffer[UInt8, 128](fill=0)
    var opad = StackBuffer[UInt8, 128](fill=0)
    for i in range(128):
        ipad[i] = k[i] ^ 0x36
        opad[i] = k[i] ^ 0x5C

    var inner = SHA512Context(SHA384_IV)
    sha512_update(inner, Span[UInt8, ...](unsafe_ptr=ipad.ptr(), length=128))
    sha512_update(inner, data)
    var inner_hash = sha512_final_with_len(inner, 48)

    var outer = SHA512Context(SHA384_IV)
    sha512_update(outer, Span[UInt8, ...](unsafe_ptr=opad.ptr(), length=128))
    sha512_update(outer, Span[UInt8, ...](inner_hash))
    var result = sha512_final_with_len(outer, 48)

    var kp = k.ptr()
    var ip = ipad.ptr()
    var op = opad.ptr()
    for i in range(128):
        kp.unsafe_store[volatile=True](i, UInt8(0))
        ip.unsafe_store[volatile=True](i, UInt8(0))
        op.unsafe_store[volatile=True](i, UInt8(0))
    var ihp = inner_hash.unsafe_ptr()
    for i in range(48):
        ihp.unsafe_store[volatile=True](i, UInt8(0))
    inner.wipe()
    outer.wipe()
    return result^
