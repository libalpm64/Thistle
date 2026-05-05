from std.builtin.rebind import downcast
from std.builtin.constrained import _constrained_conforms_to
from std.memory import stack_allocation

struct StackInlineArray[ElementType: Copyable, size: Int](Copyable):
    var _ptr: UnsafePointer[Self.ElementType, MutExternalOrigin]

    @always_inline
    fn __init__(out self, *, uninitialized: Bool):
        self._ptr = stack_allocation[Self.size, Self.ElementType]()

    @always_inline
    fn __init__(out self, var *elems: Self.ElementType, __list_literal__: ()):
        debug_assert(
            len(elems) == Self.size, "No. of elems must match array size"
        )
        self = Self(storage=elems^)

    @always_inline
    fn __init__[
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

        storage^._anihilate()

    @always_inline
    fn unsafe_ptr[
        origin: Origin, address_space: AddressSpace, //
    ](ref[origin, address_space] self) -> UnsafePointer[
        Self.ElementType,
        origin,
        address_space=address_space
    ]:
        return (
            self._ptr
            .unsafe_mut_cast[origin.mut]()
            .unsafe_origin_cast[origin]()
            .address_space_cast[address_space]()
        )

    @always_inline
    fn unsafe_get[I: Indexer](ref self, idx: I) -> ref[MutExternalOrigin] Self.ElementType:
        var i = index(idx)
        debug_assert(
            0 <= i < Self.size,
            " InlineArray.unsafe_get() index out of bounds: ",
            i,
            " should be greater than or equal to 0 and less than ",
            Self.size,
        )
        return self._ptr[i]

    @always_inline
    fn __getitem_param__[
        idx: Some[Indexer]
    ](ref self) -> ref[MutExternalOrigin] Self.ElementType:
        comptime i = index(idx)
        comptime assert 0 <= i < Self.size, "Index must be within bounds."
        return self.unsafe_get(i)

    @always_inline
    fn __getitem_param__[
        idx: Int
    ](ref self) -> ref[MutExternalOrigin] Self.ElementType:
        comptime i = index(idx)
        comptime assert 0 <= i < Self.size, "Index must be within bounds."
        return self.unsafe_get(i)

    @always_inline
    fn __getitem__(ref self, idx: Int) -> ref[MutExternalOrigin] Self.ElementType:
        debug_assert(
            0 <= idx < Self.size,
            "Index out of bounds: ", idx, " should be in [0, ", Self.size, ")",
        )
        return self.unsafe_get(idx)

    @always_inline
    fn unsafe_set[
        _T: Copyable & ImplicitlyDestructible
    ](mut self: StackInlineArray[_T, ...], idx: Int, var value: _T):
        debug_assert(
            0 <= idx < Self.size,
            "The index provided must be within the range [0, len(List) -1] when using List.unsafe_set()",
        )
        (self._ptr + idx).destroy_pointee()
        (self._ptr + idx).init_pointee_move(value^)

    fn __del__(deinit self):
        _constrained_conforms_to[
            conforms_to(Self.ElementType, ImplicitlyDestructible),
            Parent=Self,
            Element = Self.ElementType,
            ParentConformsTo="ImplicitlyDestructible",
        ]()
        comptime TDestructible = downcast[
            Self.ElementType, ImplicitlyDestructible
        ]

        comptime if not TDestructible.__del__is_trivial:
            comptime for idx in range(Self.size):
                var ptr = self.unsafe_ptr() + idx
                ptr.bitcast[TDestructible]().destroy_pointee()


struct StackBuffer[T: Copyable & ImplicitlyDestructible, N: Int](Movable):
    var _data: InlineArray[Self.T, Self.N]
    var _len: Int

    fn __init__(out self):
        comptime assert Self.T.__del__is_trivial, "StackBuffer requires trivially destructible types (UInt8, UInt32, UInt64, etc)"
        self._data = InlineArray[Self.T, Self.N](uninitialized=True)
        self._len = 0

    fn __init__(out self, *, var fill: Self.T):
        self._data = InlineArray[Self.T, Self.N](fill=fill^)
        self._len = 0

    fn __init__(out self, *, deinit take: Self):
        self._data = take._data^
        self._len = take._len

    fn len(self) -> Int:
        return self._len

    fn capacity(self) -> Int:
        return Self.N

    fn remaining(self) -> Int:
        return Self.N - self._len

    fn push(mut self, var val: Self.T):
        debug_assert(self._len < Self.N, "StackBuffer overflow")
        self._data[self._len] = val^
        self._len += 1

    fn push_unchecked(mut self, var val: Self.T):
        self._data[self._len] = val^
        self._len += 1

    fn pop(mut self) -> Self.T:
        debug_assert(self._len > 0, "StackBuffer underflow")
        self._len -= 1
        return self._data[self._len].copy()

    fn top(ref self) -> ref[self._data] Self.T:
        debug_assert(self._len > 0, "StackBuffer empty")
        return self._data[self._len - 1]

    fn clear(mut self):
        self._len = 0

    fn reset(mut self):
        self.clear()

    fn __getitem__(ref self, i: Int) -> ref[self._data] Self.T:
        debug_assert(0 <= i < self._len, "StackBuffer index out of bounds")
        return self._data[i]

    fn __setitem__(mut self, i: Int, var val: Self.T):
        debug_assert(0 <= i < self._len, "StackBuffer index out of bounds")
        self._data[i] = val^

    fn ptr(mut self) -> UnsafePointer[Self.T, MutExternalOrigin]:
        return self._data.unsafe_ptr().unsafe_origin_cast[MutExternalOrigin]()

    fn const_ptr(ref self) -> UnsafePointer[Self.T, ImmutExternalOrigin]:
        return self._data.unsafe_ptr().unsafe_origin_cast[ImmutExternalOrigin]()
