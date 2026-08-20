from std.collections import List
from std.memory import UnsafePointer
from std.sys import CompilationTarget, inlined_assembly


@always_inline
def _getrandom_linux_x86(buf: UnsafePointer[mut=True, UInt8, _, address_space=_], length: Int) -> Int:
    # Linux x86-64: getrandom(buf, len, flags=0), syscall 318.
    # rax is both syscall-number input and return-value output.
    return Int(
        inlined_assembly[
            "syscall",
            Int64,
            constraints="={rax},0,{rdi},{rsi},{rdx},~{rcx},~{r11},~{memory}",
            has_side_effect=True,
        ](Int64(318), Int64(Int(buf)), Int64(length), Int64(0))
    )


@always_inline
def _getrandom_linux_arm(buf: UnsafePointer[mut=True, UInt8, _, address_space=_], length: Int) -> Int:
    # Linux aarch64: getrandom(buf, len, flags=0), syscall 278.
    # inputs go via scratch registers to avoid asm constraint conflicts
    return Int(
        inlined_assembly[
            """
            mov x0, x9
            mov x1, x10
            mov x2, #0
            mov x8, #278
            svc #0
            """,
            Int64,
            constraints="=&{x0},{x9},{x10},~{x1},~{x2},~{x8},~{memory}",
            has_side_effect=True,
        ](Int64(Int(buf)), Int64(length))
    )


@always_inline
def _getentropy_macos_arm(buf: UnsafePointer[mut=True, UInt8, _, address_space=_], length: Int) -> Int:
    # Darwin arm64: getentropy(buf, size), syscall 500.
    # x16 = syscall number, x0 = buffer, x1 = size.
    # Errors set carry and return errno in x0; convert that to -errno.
    # getentropy returns 0 on success and accepts at most 256 bytes per call.
    return Int(
        inlined_assembly[
            """
            mov x0, x9
            mov x1, x10
            mov x16, #500
            svc #0x80
            b.cc 1f
            neg x0, x0
        1:
            """,
            Int64,
            constraints="=&{x0},{x9},{x10},~{x1},~{x16},~{cc},~{memory}",
            has_side_effect=True,
        ](Int64(Int(buf)), Int64(length))
    )


def _fill_linux_x86(buf: UnsafePointer[mut=True, UInt8, _, address_space=_], length: Int) raises:
    var offset = 0
    while offset < length:
        var ret = _getrandom_linux_x86(buf + offset, length - offset)
        if ret < 0:
            if ret == -4:  # EINTR
                continue
            raise Error("getrandom syscall failed")
        if ret == 0:
            raise Error("getrandom returned zero bytes")
        offset += ret


def _fill_linux_arm(buf: UnsafePointer[mut=True, UInt8, _, address_space=_], length: Int) raises:
    var offset = 0
    while offset < length:
        var ret = _getrandom_linux_arm(buf + offset, length - offset)
        if ret < 0:
            if ret == -4:  # EINTR
                continue
            raise Error("getrandom syscall failed")
        if ret == 0:
            raise Error("getrandom returned zero bytes")
        offset += ret


def _fill_macos_arm(buf: UnsafePointer[mut=True, UInt8, _, address_space=_], length: Int) raises:
    var offset = 0
    while offset < length:
        var chunk = min(256, length - offset)
        var ret = _getentropy_macos_arm(buf + offset, chunk)
        if ret < 0:
            raise Error("getentropy syscall failed")
        if ret != 0:
            raise Error("getentropy returned unexpected value")
        offset += chunk


def random_fill(buf: Span[mut=True, UInt8, ...]) raises:
    var length = len(buf)
    if length == 0:
        return
    var ptr = buf.unsafe_ptr()

    comptime if CompilationTarget.is_linux() and CompilationTarget.is_x86():
        _fill_linux_x86(ptr, length)

    elif CompilationTarget.is_linux() and CompilationTarget.has_neon():
        _fill_linux_arm(ptr, length)

    elif CompilationTarget.is_macos() and CompilationTarget.is_apple_silicon():
        _fill_macos_arm(ptr, length)

    else:
        CompilationTarget.unsupported_target_error[operation="random_fill"]()


def random_bytes(n: Int) raises -> List[UInt8]:
    if n < 0:
        raise Error("random_bytes length must be non-negative")
    var result = List[UInt8](length=n, fill=0)
    random_fill(Span[mut=True, UInt8, ...](result))
    return result^
