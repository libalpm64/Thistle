from std.bit import byte_swap


struct StackInlineArray[ElementType: Copyable, size: Int](Copyable):
    var _data: InlineArray[Self.ElementType, Self.size]

    @always_inline
    def __init__(out self, *, uninitialized: Bool):
        self._data = InlineArray[Self.ElementType, Self.size](
            uninitialized=True
        )

    @always_inline
    def __init__(out self, var *elems: Self.ElementType, __list_literal__: NoneType):
        debug_assert(
            len(elems) == Self.size, "No. of elems must match array size"
        )
        self = Self(storage=elems^)

    @always_inline
    def __init__[
        origin: MutOrigin,
    ](
        out self,
        *,
        var storage: VariadicList[
            elt_is_mutable=True, origin=origin, Self.ElementType, is_owned=True
        ],
    ):
        debug_assert(
            len(storage) == Self.size,
            "Expected variadic list of length ",
            Self.size,
            ", received ",
            len(storage),
        )
        self = {uninitialized=True}

        var ptr = self.unsafe_ptr()

        comptime for i in range(Self.size):
            ptr.init_pointee_move_from(
                UnsafePointer(to=storage[i]).unsafe_mut_cast[True]()
            )
            ptr += 1

        storage^._annihilate()

    @always_inline
    def unsafe_ptr[
        origin: Origin, address_space: AddressSpace, //
    ](ref[origin, address_space] self) -> UnsafePointer[
        Self.ElementType,
        origin,
        address_space=address_space
    ]:
        return (
            self._data.unsafe_ptr()
            .unsafe_mut_cast[origin.mut]()
            .unsafe_origin_cast[origin]()
            .address_space_cast[address_space]()
        )

    @always_inline
    def unsafe_get[I: Indexer](ref self, idx: I) -> ref[self._data] Self.ElementType:
        var i = index(idx)
        debug_assert(
            0 <= i < Self.size,
            " InlineArray.unsafe_get() index out of bounds: ",
            i,
            " should be greater than or equal to 0 and less than ",
            Self.size,
        )
        return self._data.unsafe_get(i)

    @always_inline
    def __getitem_param__[
        idx: Some[Indexer]
    ](ref self) -> ref[self._data] Self.ElementType:
        comptime i = index(idx)
        comptime assert 0 <= i < Self.size, "Index must be within bounds."
        return self.unsafe_get(i)

    @always_inline
    def __getitem_param__[
        idx: Int
    ](ref self) -> ref[self._data] Self.ElementType:
        comptime i = index(idx)
        comptime assert 0 <= i < Self.size, "Index must be within bounds."
        return self.unsafe_get(i)

    @always_inline
    def __getitem__(ref self, idx: Int) -> ref[self._data] Self.ElementType:
        debug_assert(
            0 <= idx < Self.size,
            "Index out of bounds: ", idx, " should be in [0, ", Self.size, ")",
        )
        return self.unsafe_get(idx)

    @always_inline
    def unsafe_set[
        _T: Copyable & ImplicitlyDestructible
    ](mut self: StackInlineArray[_T, ...], idx: Int, var value: _T):
        debug_assert(
            0 <= idx < Self.size,
            "The index provided must be within the range [0, len(List) -1] when using List.unsafe_set()",
        )
        (self._data.unsafe_ptr() + idx).destroy_pointee()
        (self._data.unsafe_ptr() + idx).init_pointee_move(value^)


struct StackBuffer[T: Copyable & ImplicitlyDestructible, N: Int](Movable):
    var _data: InlineArray[Self.T, Self.N]
    var _len: Int

    @always_inline
    def __init__(out self):
        comptime assert Self.T.__del__is_trivial, "StackBuffer requires trivially destructible types (UInt8, UInt32, UInt64, etc)"
        self._data = InlineArray[Self.T, Self.N](uninitialized=True)
        self._len = 0

    @always_inline
    def __init__(out self, *, var fill: Self.T):
        self._data = InlineArray[Self.T, Self.N](fill=fill^)
        self._len = 0

    @always_inline
    def __init__(out self, *, deinit take: Self):
        self._data = take._data^
        self._len = take._len

    @always_inline
    def len(self) -> Int:
        return self._len

    @always_inline
    def capacity(self) -> Int:
        return Self.N

    @always_inline
    def remaining(self) -> Int:
        return Self.N - self._len

    @always_inline
    def push(mut self, var val: Self.T):
        debug_assert(self._len < Self.N, "StackBuffer overflow")
        self._data[self._len] = val^
        self._len += 1

    @always_inline
    def push_unchecked(mut self, var val: Self.T):
        self._data[self._len] = val^
        self._len += 1

    @always_inline
    def pop(mut self) -> Self.T:
        debug_assert(self._len > 0, "StackBuffer underflow")
        self._len -= 1
        return self._data[self._len].copy()

    @always_inline
    def top(ref self) -> ref[self._data] Self.T:
        debug_assert(self._len > 0, "StackBuffer empty")
        return self._data[self._len - 1]

    @always_inline
    def clear(mut self):
        self._len = 0

    @always_inline
    def set_len_unchecked(mut self, new_len: Int):
        debug_assert(0 <= new_len <= Self.N, "StackBuffer set_len_unchecked out of bounds")
        self._len = new_len

    @always_inline
    def reset(mut self):
        self.clear()

    @always_inline
    def __getitem__(ref self, i: Int) -> ref[self._data] Self.T:
        debug_assert(0 <= i < Self.N, "StackBuffer index out of bounds")
        return self._data[i]

    @always_inline
    def __setitem__(mut self, i: Int, var val: Self.T):
        debug_assert(0 <= i < Self.N, "StackBuffer index out of bounds")
        self._data[i] = val^

    @always_inline
    def ptr(mut self) -> UnsafePointer[Self.T, MutAnyOrigin]:
        return self._data.unsafe_ptr().unsafe_origin_cast[MutAnyOrigin]()


@always_inline
def load_32be(ptr: UnsafePointer[UInt8, ImmutAnyOrigin], offset: Int) -> UInt32:
    return byte_swap((ptr + offset).bitcast[UInt32]().load[width=1, alignment=1]())


@always_inline
def load_64be(ptr: UnsafePointer[UInt8, ImmutAnyOrigin], offset: Int) -> UInt64:
    return byte_swap((ptr + offset).bitcast[UInt64]().load[width=1, alignment=1]())


@always_inline
def store_64be(p: UnsafePointer[UInt8, MutAnyOrigin], off: Int, v: UInt64):
    for i in range(8):
        p[off + i] = UInt8((v >> UInt64(56 - 8 * i)) & 0xFF)


@always_inline
def transpose8x8(x0: UInt64) -> UInt64:
    # Transpose an 8x8 bit matrix: bit j of output byte i = bit i of input byte j.
    # (Hacker's Delight, chapter 7, rearranging bits and bytes.)
    var x = x0
    var t = (x ^ (x >> 7)) & 0x00AA00AA00AA00AA
    x ^= t ^ (t << 7)
    t = (x ^ (x >> 14)) & 0x0000CCCC0000CCCC
    x ^= t ^ (t << 14)
    t = (x ^ (x >> 28)) & 0x00000000F0F0F0F0
    x ^= t ^ (t << 28)
    return x


@always_inline
def u64_nonzero_choice(x: UInt64) -> UInt64:
    return ((x | (UInt64(0) - x)) >> UInt64(63)) & UInt64(1)


@always_inline
def u64_zero_choice(x: UInt64) -> UInt64:
    return u64_nonzero_choice(x) ^ UInt64(1)


def zero_stack_u8(mut data: StackBuffer[UInt8, ...]):
    var ptr = data.ptr()
    for i in range(data.len()):
        ptr.store[volatile=True](i, UInt8(0))
    data.clear()


@always_inline
def nibble_to_hex_char(nibble: UInt8) -> UInt8:
    """Convert a nibble (0-15) to its hex character ASCII value."""
    if nibble < 10:
        return nibble + 0x30
    else:
        return nibble - 10 + 0x61


@always_inline
def bytes_to_hex_simd(data: UnsafePointer[UInt8, ImmutAnyOrigin], len: Int) -> String:
    var result = String(capacity=len * 2)
    for i in range(len):
        var b = data[i]
        result += chr(Int(nibble_to_hex_char((b >> 4) & 0x0F)))
        result += chr(Int(nibble_to_hex_char(b & 0x0F)))
    return result


def bytes_to_hex(data: List[UInt8]) -> String:
    """Convert a byte list to a hexadecimal string."""
    return bytes_to_hex_simd(data.unsafe_ptr(), len(data))


def bytes_to_hex(data: Span[UInt8, ...]) -> String:
    """Convert a byte span to a hexadecimal string."""
    return bytes_to_hex_simd(data.unsafe_ptr(), len(data))


def bytes_to_hex(data: SIMD[DType.uint8, 16]) -> String:
    """Convert a 16-byte SIMD vector to a hexadecimal string."""
    var result = String(capacity=32)
    for i in range(16):
        var b = data[i]
        result += chr(Int(nibble_to_hex_char((b >> 4) & 0x0F)))
        result += chr(Int(nibble_to_hex_char(b & 0x0F)))
    return result


def string_to_bytes(s: String) -> List[UInt8]:
    """Convert a string to a list of bytes."""
    var bytes = s.as_bytes()
    var data = List[UInt8](capacity=len(bytes))
    for i in range(len(bytes)):
        data.append(bytes[i])
    return data^
