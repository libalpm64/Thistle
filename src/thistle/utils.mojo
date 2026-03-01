from builtin.rebind import downcast
from builtin.constrained import _constrained_conforms_to
from memory import stack_allocation

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
        //,
    ](
        out self,
        *,
        var storage: VariadicListMem[
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

        # Move each element into the array storage.
        @parameter
        for i in range(Self.size):
            # Safety: We own the elements in the variadic list.
            ptr.init_pointee_move_from(
                UnsafePointer(to=storage[i]).unsafe_mut_cast[True]()
            )
            ptr += 1

        # Do not destroy the elements when their backing storage goes away.
        # FIXME: Why doesn't consume_elements work here?
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
    fn __getitem__[
        idx: Some[Indexer]
    ](ref self) -> ref[MutExternalOrigin] Self.ElementType:
        comptime i = index(idx)
        constrained[0 <= i < Self.size, "Index must be within bounds."]()
        return self.unsafe_get(i)


    # FIXME: temporary workaround
    @always_inline
    fn __getitem__[
        idx: Int
    ](ref self) -> ref[MutExternalOrigin] Self.ElementType:
        comptime i = index(idx)
        constrained[0 <= i < Self.size, "Index must be within bounds."]()
        return self.unsafe_get(i)

    @always_inline
    fn unsafe_set[
        _T: Copyable & ImplicitlyDestructible
    ](mut self: StackInlineArray[_T], idx: Int, var value: _T):
        debug_assert(
            0 <= idx < Self.size,
            (
                "The index provided must be within the range [0, len(List) -1]"
                " when using List.unsafe_set()"
            ),
        )
        (self._ptr + idx).destroy_pointee()
        (self._ptr + idx).init_pointee_move(value^)

    fn __del__(deinit self):
        """Deallocates the array and destroys its elements."""

        _constrained_conforms_to[
            conforms_to(Self.ElementType, ImplicitlyDestructible),
            Parent=Self,
            Element = Self.ElementType,
            ParentConformsTo="ImplicitlyDestructible",
        ]()
        comptime TDestructible = downcast[
            Self.ElementType, ImplicitlyDestructible
        ]

        @parameter
        if not TDestructible.__del__is_trivial:
            @parameter
            for idx in range(Self.size):
                var ptr = self.unsafe_ptr() + idx
                ptr.bitcast[TDestructible]().destroy_pointee()


