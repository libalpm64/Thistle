"""PBKDF2 (RFC 8018, sec. 5.2) and HMAC (RFC 2104) with SHA-2 (FIPS 180-4)."""
from std.collections import List
from std.memory import unsafe_memcpy, Pointer
from std.builtin.simd import SIMD
from std.builtin.dtype import DType
from std.bit import byte_swap
from .utils import StackBuffer, volatile_wipe
from .sha2 import (
    SHA384_IV,
    SHA256Context,
    SHA512Context,
    sha384_hash,
    sha256_hash,
    sha256_update,
    sha256_final_to_buffer,
    sha256_transform_blocks,
    sha512_update,
    sha512_final_to_buffer,
    sha512_transform_blocks,
)

comptime PBKDF2_SHA256_MAX_DKLEN: Int = 0xFFFFFFFF * 32
comptime PBKDF2_SHA512_MAX_DKLEN: Int = 0xFFFFFFFF * 64


@always_inline
def _xor_block[WIDTH: Int](
    dst: Pointer[mut=True, UInt8, _, address_space=_],
    src: Pointer[mut=True, UInt8, _, address_space=_],
):
    # XOR each U value into the PBKDF2 block accumulator without early exits.
    var dst_words = dst.unsafe_bitcast[UInt64]().unsafe_load[width=WIDTH, alignment=1]()
    var src_words = src.unsafe_bitcast[UInt64]().unsafe_load[width=WIDTH, alignment=1]()
    dst.unsafe_bitcast[UInt64]().unsafe_store[width=WIDTH, alignment=1](0, dst_words ^ src_words)


trait HMACer(Movable):
    """HMAC backend for the shared PBKDF2 loop, including a salt-and-counter first round."""

    comptime BLOCK: Int
    comptime HASH: Int

    def hmac(mut self, data: Span[UInt8, ...]): ...
    def hmac_with_counter(mut self, data: Span[UInt8, ...], counter: UInt32): ...
    def _hmac_fixed_unchecked(mut self, data: Span[UInt8, ...]): ...
    def u_block_ptr(mut self) -> Pointer[UInt8, MutUntrackedOrigin]: ...


@always_inline
def _pbkdf2_derive[H: HMACer](
    mut hmac: H, salt: Span[UInt8, ...], iterations: Int, dklen: Int
) raises -> List[UInt8]:
    """Derive blocks T_i = U_1 XOR ... XOR U_c, where U_1 = PRF(P, S || INT32_BE(i)) and U_j =
    PRF(P, U_{j-1}) (RFC 8018, sec. 5.2).
    """
    if iterations < 1:
        raise Error("PBKDF2 iterations must be positive")
    comptime hash_len = H.HASH
    if dklen < 1 or dklen > 0xFFFFFFFF * hash_len:
        raise Error("PBKDF2 dkLen exceeds the RFC 8018 limit")
    var num_blocks = dklen // hash_len
    if dklen % hash_len != 0:
        num_blocks += 1
    var derived_key = List[UInt8](capacity=dklen)
    var t_block = InlineArray[UInt8, 64](fill=0)
    var input_block = InlineArray[UInt8, 64](fill=0)
    for block_idx in range(1, num_blocks + 1):
        hmac.hmac_with_counter(salt, UInt32(block_idx))
        unsafe_memcpy(dest=t_block.unsafe_ptr(), src=hmac.u_block_ptr(), count=hash_len)
        for _ in range(1, iterations):
            unsafe_memcpy(dest=input_block.unsafe_ptr(), src=hmac.u_block_ptr(), count=hash_len)
            hmac._hmac_fixed_unchecked(
                Span[UInt8, ...](unsafe_ptr=input_block.unsafe_ptr(), length=hash_len)
            )
            comptime if hash_len == 32:
                _xor_block[4](t_block.unsafe_ptr(), hmac.u_block_ptr())
            else:
                _xor_block[8](t_block.unsafe_ptr(), hmac.u_block_ptr())
        var remaining = dklen - len(derived_key)
        var to_copy = hash_len if remaining > hash_len else remaining
        for b in range(to_copy):
            derived_key.append(t_block[b])
    volatile_wipe(t_block.unsafe_ptr(), 64)
    volatile_wipe(input_block.unsafe_ptr(), 64)
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
    var fixed_block: StackBuffer[UInt8, 64]
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
        self.fixed_block = StackBuffer[UInt8, 64](fill=0)
        self.fixed_block[32] = 0x80
        self.fixed_block[62] = 0x03
        self.fixed_block[63] = 0x00
        self.inner_ctx = SHA256Context()
        self.outer_ctx = SHA256Context()

        var key_block = StackBuffer[UInt8, 64](fill=0)

        if len(password) > 64:
            var hash_ctx = SHA256Context()
            sha256_update(hash_ctx, password)
            sha256_final_to_buffer(hash_ctx, key_block.ptr())
        else:
            for i in range(len(password)):
                key_block[i] = password[i]

        for i in range(64):
            self.ipad[i] = key_block[i] ^ 0x36
            self.opad[i] = key_block[i] ^ 0x5C
        volatile_wipe(key_block.ptr(), 64)
        sha256_update(self.inner_ctx, Span[UInt8, ...](unsafe_ptr=self.ipad.ptr(), length=64))
        sha256_update(self.outer_ctx, Span[UInt8, ...](unsafe_ptr=self.opad.ptr(), length=64))
        self.inner_state = self.inner_ctx.state
        self.outer_state = self.outer_ctx.state

    def __deinit__(deinit self):
        volatile_wipe(Pointer(to=self.inner_state).unsafe_bitcast[UInt8](), 32)
        volatile_wipe(Pointer(to=self.outer_state).unsafe_bitcast[UInt8](), 32)
        volatile_wipe(self.ipad.ptr(), 64)
        volatile_wipe(self.opad.ptr(), 64)
        volatile_wipe(self.inner_hash.ptr(), 32)
        volatile_wipe(self.u_block.ptr(), 32)
        volatile_wipe(self.counter_bytes.ptr(), 4)
        volatile_wipe(self.fixed_block.ptr(), 64)

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
        # PBKDF2 rounds after U1 always HMAC exactly 32 bytes. Both the
        # inner and outer hashes therefore compress one fixed-shape block
        # after their cached 64-byte pad state: 32 data bytes, 0x80, zeros,
        # and the 96-byte (768-bit) total length.
        var block = self.fixed_block.ptr()
        var src = data.unsafe_ptr()
        block.unsafe_store[width=32](0, src.unsafe_load[width=32](0))

        var inner = self.inner_state
        sha256_transform_blocks(inner, block, 1)
        for i in range(8):
            block.unsafe_offset(i * 4).unsafe_bitcast[UInt32]().unsafe_store[
                alignment=1
            ](0, byte_swap(inner[i]))

        var outer = self.outer_state
        sha256_transform_blocks(outer, block, 1)
        for i in range(8):
            self.u_block.ptr().unsafe_offset(i * 4).unsafe_bitcast[UInt32]().unsafe_store[
                alignment=1
            ](0, byte_swap(outer[i]))

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
        sha256_update(
            self.inner_ctx, Span[UInt8, ...](unsafe_ptr=self.counter_bytes.ptr(), length=4)
        )
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
    var fixed_block: StackBuffer[UInt8, 128]
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
        self.fixed_block = StackBuffer[UInt8, 128](fill=0)
        self.fixed_block[64] = 0x80
        self.fixed_block[126] = 0x06
        self.fixed_block[127] = 0x00
        self.inner_ctx = SHA512Context()
        self.outer_ctx = SHA512Context()

        var key_block = StackBuffer[UInt8, 128](fill=0)

        if len(password) > 128:
            var hash_ctx = SHA512Context()
            sha512_update(hash_ctx, password)
            sha512_final_to_buffer(hash_ctx, key_block.ptr())
        else:
            for i in range(len(password)):
                key_block[i] = password[i]

        for i in range(128):
            self.ipad[i] = key_block[i] ^ 0x36
            self.opad[i] = key_block[i] ^ 0x5C
        volatile_wipe(key_block.ptr(), 128)
        sha512_update(self.inner_ctx, Span[UInt8, ...](unsafe_ptr=self.ipad.ptr(), length=128))
        sha512_update(self.outer_ctx, Span[UInt8, ...](unsafe_ptr=self.opad.ptr(), length=128))
        self.inner_state = self.inner_ctx.state
        self.outer_state = self.outer_ctx.state

    def __deinit__(deinit self):
        volatile_wipe(Pointer(to=self.inner_state).unsafe_bitcast[UInt8](), 64)
        volatile_wipe(Pointer(to=self.outer_state).unsafe_bitcast[UInt8](), 64)
        volatile_wipe(self.ipad.ptr(), 128)
        volatile_wipe(self.opad.ptr(), 128)
        volatile_wipe(self.inner_hash.ptr(), 64)
        volatile_wipe(self.u_block.ptr(), 64)
        volatile_wipe(self.counter_bytes.ptr(), 4)
        volatile_wipe(self.fixed_block.ptr(), 128)

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
        # PBKDF2 rounds after U1 always HMAC exactly 64 bytes. Both the
        # inner and outer hashes therefore compress one fixed-shape block
        # after their cached 128-byte pad state: 64 data bytes, 0x80, zeros,
        # and the 192-byte (1536-bit) total length.
        var block = self.fixed_block.ptr()
        block.unsafe_store[width=64](
            0, data.unsafe_ptr().unsafe_load[width=64](0)
        )

        var inner = self.inner_state
        sha512_transform_blocks(inner, block, 1)
        for i in range(8):
            block.unsafe_offset(i * 8).unsafe_bitcast[UInt64]().unsafe_store[
                alignment=1
            ](0, byte_swap(inner[i]))

        var outer = self.outer_state
        sha512_transform_blocks(outer, block, 1)
        for i in range(8):
            self.u_block.ptr().unsafe_offset(i * 8).unsafe_bitcast[UInt64]().unsafe_store[
                alignment=1
            ](0, byte_swap(outer[i]))

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
        sha512_update(
            self.inner_ctx, Span[UInt8, ...](unsafe_ptr=self.counter_bytes.ptr(), length=4)
        )
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

    def hmac_into(
        mut self, data: Span[UInt8, ...], output: Pointer[mut=True, UInt8, _, address_space=_]
    ): ...


struct HMACSHA256State(RFC6979HMAC):
    """Cache keyed SHA-256 inner and outer states for repeated HMAC operations (RFC 2104, sec.
    4).
    """

    var inner_state: SIMD[DType.uint32, 8]
    var outer_state: SIMD[DType.uint32, 8]

    def __init__(out self, key: Span[UInt8, ...]):
        var key_block = StackBuffer[UInt8, 64](fill=0)
        if len(key) > 64:
            var key_hash = sha256_hash(key)
            unsafe_memcpy(dest=key_block.ptr(), src=key_hash.unsafe_ptr(), count=32)
            var key_hash_ptr = key_hash.unsafe_ptr()
            for i in range(32):
                key_hash_ptr.unsafe_store[volatile=True](i, UInt8(0))
        else:
            for i in range(len(key)):
                key_block[i] = key[i]
        var ipad = StackBuffer[UInt8, 64](fill=0)
        var opad = StackBuffer[UInt8, 64](fill=0)
        for i in range(64):
            ipad[i] = key_block[i] ^ 0x36
            opad[i] = key_block[i] ^ 0x5C
        var inner = SHA256Context()
        sha256_update(inner, Span[UInt8, ...](unsafe_ptr=ipad.ptr(), length=64))
        self.inner_state = inner.state
        var outer = SHA256Context()
        sha256_update(outer, Span[UInt8, ...](unsafe_ptr=opad.ptr(), length=64))
        self.outer_state = outer.state
        volatile_wipe(key_block.ptr(), 64)
        volatile_wipe(ipad.ptr(), 64)
        volatile_wipe(opad.ptr(), 64)

    def __deinit__(deinit self):
        var inner_ptr = Pointer(to=self.inner_state).unsafe_bitcast[UInt32]()
        var outer_ptr = Pointer(to=self.outer_state).unsafe_bitcast[UInt32]()
        for i in range(8):
            inner_ptr.unsafe_store[volatile=True](i, UInt32(0))
            outer_ptr.unsafe_store[volatile=True](i, UInt32(0))

    @always_inline
    def hmac_into(
        mut self, data: Span[UInt8, ...], output: Pointer[mut=True, UInt8, _, address_space=_]
    ):
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
        volatile_wipe(digest.ptr(), 32)


struct HMACSHA384State(RFC6979HMAC):
    """Cache keyed SHA-384 inner and outer states for repeated HMAC operations (RFC 2104, sec.
    4).
    """

    var inner_state: SIMD[DType.uint64, 8]
    var outer_state: SIMD[DType.uint64, 8]

    def __init__(out self, key: Span[UInt8, ...]):
        var key_block = StackBuffer[UInt8, 128](fill=0)
        if len(key) > 128:
            var key_hash = sha384_hash(key)
            unsafe_memcpy(dest=key_block.ptr(), src=key_hash.unsafe_ptr(), count=48)
            var key_hash_ptr = key_hash.unsafe_ptr()
            for i in range(48):
                key_hash_ptr.unsafe_store[volatile=True](i, UInt8(0))
        else:
            for i in range(len(key)):
                key_block[i] = key[i]
        var ipad = StackBuffer[UInt8, 128](fill=0)
        var opad = StackBuffer[UInt8, 128](fill=0)
        for i in range(128):
            ipad[i] = key_block[i] ^ 0x36
            opad[i] = key_block[i] ^ 0x5C
        var inner = SHA512Context(SHA384_IV)
        sha512_update(inner, Span[UInt8, ...](unsafe_ptr=ipad.ptr(), length=128))
        self.inner_state = inner.state
        var outer = SHA512Context(SHA384_IV)
        sha512_update(outer, Span[UInt8, ...](unsafe_ptr=opad.ptr(), length=128))
        self.outer_state = outer.state
        volatile_wipe(key_block.ptr(), 128)
        volatile_wipe(ipad.ptr(), 128)
        volatile_wipe(opad.ptr(), 128)

    def __deinit__(deinit self):
        var inner_ptr = Pointer(to=self.inner_state).unsafe_bitcast[UInt64]()
        var outer_ptr = Pointer(to=self.outer_state).unsafe_bitcast[UInt64]()
        for i in range(8):
            inner_ptr.unsafe_store[volatile=True](i, UInt64(0))
            outer_ptr.unsafe_store[volatile=True](i, UInt64(0))

    @always_inline
    def hmac_into(
        mut self, data: Span[UInt8, ...], output: Pointer[mut=True, UInt8, _, address_space=_]
    ):
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
        volatile_wipe(digest.ptr(), 64)


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
    var ctx = HMACSHA384State(key)
    var result = List[UInt8](unsafe_uninit_length=48)
    ctx.hmac_into(data, result.unsafe_ptr())
    return result^
