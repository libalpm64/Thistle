# ML-KEM FFI Bindings for Mojo
# All credit and copyright goes to the authors @ https://github.com/pq-code-package/mlkem-native
# FFI bindings by Libalpm64 | Lostlab Technologies, no attribution for the bindings side.

from sys.ffi import OwnedDLHandle
from memory import UnsafePointer
from collections import List
from python import Python


fn _get_lib_path(lib_name: String) raises -> String:
    var os_mod = Python.import_module("os")
    var sys_mod = Python.import_module("sys")
    
    var platform = String(sys_mod.platform)
    var ext: String
    if platform == "darwin":
        ext = "dylib"
    elif platform == "win32":
        ext = "dll"
    else:
        ext = "so"
    
    var libs_dir = String(os_mod.environ.get("THISTLE_LIBS", "libs"))
    var lib_path = libs_dir + "/" + lib_name + "." + ext
    var exists = os_mod.path.exists(lib_path)
    if not exists:
        raise Error("ML-DSA/ML-KEM library not found. Run: pixi run build-pq")
    return lib_path


comptime MLKEM512_SECRETKEYBYTES: Int = 1632
comptime MLKEM512_PUBLICKEYBYTES: Int = 800
comptime MLKEM512_CIPHERTEXTBYTES: Int = 768

comptime MLKEM768_SECRETKEYBYTES: Int = 2400
comptime MLKEM768_PUBLICKEYBYTES: Int = 1184
comptime MLKEM768_CIPHERTEXTBYTES: Int = 1088

comptime MLKEM1024_SECRETKEYBYTES: Int = 3168
comptime MLKEM1024_PUBLICKEYBYTES: Int = 1568
comptime MLKEM1024_CIPHERTEXTBYTES: Int = 1568

comptime MLKEM_BYTES: Int = 32
comptime MLKEM_SYMBYTES: Int = 32

comptime MLK_ERR_OK: Int = 0
comptime MLK_ERR_FAIL: Int = -1


fn mlkem512_keypair(
    pk: UnsafePointer[UInt8, MutAnyOrigin],
    sk: UnsafePointer[UInt8, MutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmlkem512"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, MutAnyOrigin]) -> Int]("PQCP_MLKEM_NATIVE_MLKEM512_keypair")
    return func(pk, sk)


fn mlkem512_keypair_derand(
    pk: UnsafePointer[UInt8, MutAnyOrigin],
    sk: UnsafePointer[UInt8, MutAnyOrigin],
    coins: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmlkem512"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLKEM_NATIVE_MLKEM512_keypair_derand")
    return func(pk, sk, coins)


fn mlkem512_enc(
    ct: UnsafePointer[UInt8, MutAnyOrigin],
    ss: UnsafePointer[UInt8, MutAnyOrigin],
    pk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmlkem512"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLKEM_NATIVE_MLKEM512_enc")
    return func(ct, ss, pk)


fn mlkem512_enc_derand(
    ct: UnsafePointer[UInt8, MutAnyOrigin],
    ss: UnsafePointer[UInt8, MutAnyOrigin],
    pk: UnsafePointer[UInt8, ImmutAnyOrigin],
    coins: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmlkem512"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLKEM_NATIVE_MLKEM512_enc_derand")
    return func(ct, ss, pk, coins)


fn mlkem512_dec(
    ss: UnsafePointer[UInt8, MutAnyOrigin],
    ct: UnsafePointer[UInt8, ImmutAnyOrigin],
    sk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmlkem512"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLKEM_NATIVE_MLKEM512_dec")
    return func(ss, ct, sk)


fn mlkem512_check_pk(
    pk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmlkem512"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLKEM_NATIVE_MLKEM512_check_pk")
    return func(pk)


fn mlkem512_check_sk(
    sk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmlkem512"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLKEM_NATIVE_MLKEM512_check_sk")
    return func(sk)


fn mlkem768_keypair(
    pk: UnsafePointer[UInt8, MutAnyOrigin],
    sk: UnsafePointer[UInt8, MutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmlkem768"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, MutAnyOrigin]) -> Int]("PQCP_MLKEM_NATIVE_MLKEM768_keypair")
    return func(pk, sk)


fn mlkem768_keypair_derand(
    pk: UnsafePointer[UInt8, MutAnyOrigin],
    sk: UnsafePointer[UInt8, MutAnyOrigin],
    coins: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmlkem768"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLKEM_NATIVE_MLKEM768_keypair_derand")
    return func(pk, sk, coins)


fn mlkem768_enc(
    ct: UnsafePointer[UInt8, MutAnyOrigin],
    ss: UnsafePointer[UInt8, MutAnyOrigin],
    pk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmlkem768"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLKEM_NATIVE_MLKEM768_enc")
    return func(ct, ss, pk)


fn mlkem768_enc_derand(
    ct: UnsafePointer[UInt8, MutAnyOrigin],
    ss: UnsafePointer[UInt8, MutAnyOrigin],
    pk: UnsafePointer[UInt8, ImmutAnyOrigin],
    coins: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmlkem768"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLKEM_NATIVE_MLKEM768_enc_derand")
    return func(ct, ss, pk, coins)


fn mlkem768_dec(
    ss: UnsafePointer[UInt8, MutAnyOrigin],
    ct: UnsafePointer[UInt8, ImmutAnyOrigin],
    sk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmlkem768"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLKEM_NATIVE_MLKEM768_dec")
    return func(ss, ct, sk)


fn mlkem768_check_pk(
    pk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmlkem768"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLKEM_NATIVE_MLKEM768_check_pk")
    return func(pk)


fn mlkem768_check_sk(
    sk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmlkem768"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLKEM_NATIVE_MLKEM768_check_sk")
    return func(sk)


fn mlkem1024_keypair(
    pk: UnsafePointer[UInt8, MutAnyOrigin],
    sk: UnsafePointer[UInt8, MutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmlkem1024"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, MutAnyOrigin]) -> Int]("PQCP_MLKEM_NATIVE_MLKEM1024_keypair")
    return func(pk, sk)


fn mlkem1024_keypair_derand(
    pk: UnsafePointer[UInt8, MutAnyOrigin],
    sk: UnsafePointer[UInt8, MutAnyOrigin],
    coins: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmlkem1024"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLKEM_NATIVE_MLKEM1024_keypair_derand")
    return func(pk, sk, coins)


fn mlkem1024_enc(
    ct: UnsafePointer[UInt8, MutAnyOrigin],
    ss: UnsafePointer[UInt8, MutAnyOrigin],
    pk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmlkem1024"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLKEM_NATIVE_MLKEM1024_enc")
    return func(ct, ss, pk)


fn mlkem1024_enc_derand(
    ct: UnsafePointer[UInt8, MutAnyOrigin],
    ss: UnsafePointer[UInt8, MutAnyOrigin],
    pk: UnsafePointer[UInt8, ImmutAnyOrigin],
    coins: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmlkem1024"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLKEM_NATIVE_MLKEM1024_enc_derand")
    return func(ct, ss, pk, coins)


fn mlkem1024_dec(
    ss: UnsafePointer[UInt8, MutAnyOrigin],
    ct: UnsafePointer[UInt8, ImmutAnyOrigin],
    sk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmlkem1024"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLKEM_NATIVE_MLKEM1024_dec")
    return func(ss, ct, sk)


fn mlkem1024_check_pk(
    pk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmlkem1024"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLKEM_NATIVE_MLKEM1024_check_pk")
    return func(pk)


fn mlkem1024_check_sk(
    sk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmlkem1024"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLKEM_NATIVE_MLKEM1024_check_sk")
    return func(sk)
