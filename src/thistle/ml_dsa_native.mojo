# ML-DSA FFI Bindings for Mojo
# All credit and copyright goes to the authors @ https://github.com/pq-code-package/mldsa-native
# FFI bindings by Libalpm64 | Lostlab Technologies, no attribution for the bindings side.
from sys.ffi import OwnedDLHandle
from memory import UnsafePointer, alloc
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


comptime MLDSA44_SECRETKEYBYTES: Int = 2560
comptime MLDSA44_PUBLICKEYBYTES: Int = 1312
comptime MLDSA44_BYTES: Int = 2420

comptime MLDSA65_SECRETKEYBYTES: Int = 4032
comptime MLDSA65_PUBLICKEYBYTES: Int = 1952
comptime MLDSA65_BYTES: Int = 3309

comptime MLDSA87_SECRETKEYBYTES: Int = 4896
comptime MLDSA87_PUBLICKEYBYTES: Int = 2592
comptime MLDSA87_BYTES: Int = 4627

comptime MLDSA_SEEDBYTES: Int = 32
comptime MLDSA_CRHBYTES: Int = 64
comptime MLDSA_RNDBYTES: Int = 32

comptime MLD_ERR_OK: Int = 0
comptime MLD_ERR_FAIL: Int = -1
comptime MLD_ERR_OUT_OF_MEMORY: Int = -2
comptime MLD_ERR_RNG_FAIL: Int = -3

comptime MLD_PREHASH_NONE: Int = 0
comptime MLD_PREHASH_SHA2_224: Int = 1
comptime MLD_PREHASH_SHA2_256: Int = 2
comptime MLD_PREHASH_SHA2_384: Int = 3
comptime MLD_PREHASH_SHA2_512: Int = 4
comptime MLD_PREHASH_SHA2_512_224: Int = 5
comptime MLD_PREHASH_SHA2_512_256: Int = 6
comptime MLD_PREHASH_SHA3_224: Int = 7
comptime MLD_PREHASH_SHA3_256: Int = 8
comptime MLD_PREHASH_SHA3_384: Int = 9
comptime MLD_PREHASH_SHA3_512: Int = 10
comptime MLD_PREHASH_SHAKE_128: Int = 11
comptime MLD_PREHASH_SHAKE_256: Int = 12


fn mldsa44_keypair(
    pk: UnsafePointer[UInt8, MutAnyOrigin],
    sk: UnsafePointer[UInt8, MutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa44"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, MutAnyOrigin]) -> Int]("PQCP_MLDSA_NATIVE_MLDSA44_keypair")
    return func(pk, sk)


fn mldsa44_keypair_internal(
    pk: UnsafePointer[UInt8, MutAnyOrigin],
    sk: UnsafePointer[UInt8, MutAnyOrigin],
    seed: UnsafePointer[UInt8, MutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa44"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, MutAnyOrigin]) -> Int]("PQCP_MLDSA_NATIVE_MLDSA44_keypair_internal")
    return func(pk, sk, seed)


fn mldsa44_signature(
    sig: UnsafePointer[UInt8, MutAnyOrigin],
    siglen: UnsafePointer[UInt64, MutAnyOrigin],
    msg: UnsafePointer[UInt8, ImmutAnyOrigin],
    msg_len: Int,
    ctx: UnsafePointer[UInt8, ImmutAnyOrigin],
    ctx_len: Int,
    sk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa44"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt64, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLDSA_NATIVE_MLDSA44_signature")
    return func(sig, siglen, msg, msg_len, ctx, ctx_len, sk)


fn mldsa44_signature_internal(
    sig: UnsafePointer[UInt8, MutAnyOrigin],
    siglen: UnsafePointer[UInt64, MutAnyOrigin],
    msg: UnsafePointer[UInt8, ImmutAnyOrigin],
    msg_len: Int,
    pre: UnsafePointer[UInt8, ImmutAnyOrigin],
    pre_len: Int,
    rnd: UnsafePointer[UInt8, ImmutAnyOrigin],
    sk: UnsafePointer[UInt8, ImmutAnyOrigin],
    externalmu: Int
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa44"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt64, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], Int) -> Int]("PQCP_MLDSA_NATIVE_MLDSA44_signature_internal")
    return func(sig, siglen, msg, msg_len, pre, pre_len, rnd, sk, externalmu)


fn mldsa44_signature_pre_hash_internal(
    sig: UnsafePointer[UInt8, MutAnyOrigin],
    siglen: UnsafePointer[UInt64, MutAnyOrigin],
    ph: UnsafePointer[UInt8, ImmutAnyOrigin],
    ph_len: Int,
    ctx: UnsafePointer[UInt8, ImmutAnyOrigin],
    ctx_len: Int,
    rnd: UnsafePointer[UInt8, ImmutAnyOrigin],
    sk: UnsafePointer[UInt8, ImmutAnyOrigin],
    hashalg: Int
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa44"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt64, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], Int) -> Int]("PQCP_MLDSA_NATIVE_MLDSA44_signature_pre_hash_internal")
    return func(sig, siglen, ph, ph_len, ctx, ctx_len, rnd, sk, hashalg)


fn mldsa44_signature_pre_hash_shake256(
    sig: UnsafePointer[UInt8, MutAnyOrigin],
    siglen: UnsafePointer[UInt64, MutAnyOrigin],
    msg: UnsafePointer[UInt8, ImmutAnyOrigin],
    msg_len: Int,
    ctx: UnsafePointer[UInt8, ImmutAnyOrigin],
    ctx_len: Int,
    rnd: UnsafePointer[UInt8, ImmutAnyOrigin],
    sk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa44"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt64, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLDSA_NATIVE_MLDSA44_signature_pre_hash_shake256")
    return func(sig, siglen, msg, msg_len, ctx, ctx_len, rnd, sk)


fn mldsa44_verify(
    sig: UnsafePointer[UInt8, ImmutAnyOrigin],
    sig_len: Int,
    msg: UnsafePointer[UInt8, ImmutAnyOrigin],
    msg_len: Int,
    ctx: UnsafePointer[UInt8, ImmutAnyOrigin],
    ctx_len: Int,
    pk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa44"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLDSA_NATIVE_MLDSA44_verify")
    return func(sig, sig_len, msg, msg_len, ctx, ctx_len, pk)


fn mldsa44_verify_internal(
    sig: UnsafePointer[UInt8, ImmutAnyOrigin],
    sig_len: Int,
    msg: UnsafePointer[UInt8, ImmutAnyOrigin],
    msg_len: Int,
    pre: UnsafePointer[UInt8, ImmutAnyOrigin],
    pre_len: Int,
    pk: UnsafePointer[UInt8, ImmutAnyOrigin],
    externalmu: Int
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa44"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int) -> Int]("PQCP_MLDSA_NATIVE_MLDSA44_verify_internal")
    return func(sig, sig_len, msg, msg_len, pre, pre_len, pk, externalmu)


fn mldsa44_verify_pre_hash_internal(
    sig: UnsafePointer[UInt8, ImmutAnyOrigin],
    sig_len: Int,
    ph: UnsafePointer[UInt8, ImmutAnyOrigin],
    ph_len: Int,
    ctx: UnsafePointer[UInt8, ImmutAnyOrigin],
    ctx_len: Int,
    pk: UnsafePointer[UInt8, ImmutAnyOrigin],
    hashalg: Int
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa44"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int) -> Int]("PQCP_MLDSA_NATIVE_MLDSA44_verify_pre_hash_internal")
    return func(sig, sig_len, ph, ph_len, ctx, ctx_len, pk, hashalg)


fn mldsa44_verify_extmu(
    sig: UnsafePointer[UInt8, ImmutAnyOrigin],
    sig_len: Int,
    mu: UnsafePointer[UInt8, ImmutAnyOrigin],
    pk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa44"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLDSA_NATIVE_MLDSA44_verify_extmu")
    return func(sig, sig_len, mu, pk)


fn mldsa65_keypair(
    pk: UnsafePointer[UInt8, MutAnyOrigin],
    sk: UnsafePointer[UInt8, MutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa65"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, MutAnyOrigin]) -> Int]("PQCP_MLDSA_NATIVE_MLDSA65_keypair")
    return func(pk, sk)


fn mldsa65_keypair_internal(
    pk: UnsafePointer[UInt8, MutAnyOrigin],
    sk: UnsafePointer[UInt8, MutAnyOrigin],
    seed: UnsafePointer[UInt8, MutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa65"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, MutAnyOrigin]) -> Int]("PQCP_MLDSA_NATIVE_MLDSA65_keypair_internal")
    return func(pk, sk, seed)


fn mldsa65_signature(
    sig: UnsafePointer[UInt8, MutAnyOrigin],
    siglen: UnsafePointer[UInt64, MutAnyOrigin],
    msg: UnsafePointer[UInt8, ImmutAnyOrigin],
    msg_len: Int,
    ctx: UnsafePointer[UInt8, ImmutAnyOrigin],
    ctx_len: Int,
    sk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa65"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt64, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLDSA_NATIVE_MLDSA65_signature")
    return func(sig, siglen, msg, msg_len, ctx, ctx_len, sk)


fn mldsa65_signature_internal(
    sig: UnsafePointer[UInt8, MutAnyOrigin],
    siglen: UnsafePointer[UInt64, MutAnyOrigin],
    msg: UnsafePointer[UInt8, ImmutAnyOrigin],
    msg_len: Int,
    pre: UnsafePointer[UInt8, ImmutAnyOrigin],
    pre_len: Int,
    rnd: UnsafePointer[UInt8, ImmutAnyOrigin],
    sk: UnsafePointer[UInt8, ImmutAnyOrigin],
    externalmu: Int
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa65"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt64, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], Int) -> Int]("PQCP_MLDSA_NATIVE_MLDSA65_signature_internal")
    return func(sig, siglen, msg, msg_len, pre, pre_len, rnd, sk, externalmu)


fn mldsa65_signature_pre_hash_internal(
    sig: UnsafePointer[UInt8, MutAnyOrigin],
    siglen: UnsafePointer[UInt64, MutAnyOrigin],
    ph: UnsafePointer[UInt8, ImmutAnyOrigin],
    ph_len: Int,
    ctx: UnsafePointer[UInt8, ImmutAnyOrigin],
    ctx_len: Int,
    rnd: UnsafePointer[UInt8, ImmutAnyOrigin],
    sk: UnsafePointer[UInt8, ImmutAnyOrigin],
    hashalg: Int
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa65"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt64, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], Int) -> Int]("PQCP_MLDSA_NATIVE_MLDSA65_signature_pre_hash_internal")
    return func(sig, siglen, ph, ph_len, ctx, ctx_len, rnd, sk, hashalg)


fn mldsa65_signature_pre_hash_shake256(
    sig: UnsafePointer[UInt8, MutAnyOrigin],
    siglen: UnsafePointer[UInt64, MutAnyOrigin],
    msg: UnsafePointer[UInt8, ImmutAnyOrigin],
    msg_len: Int,
    ctx: UnsafePointer[UInt8, ImmutAnyOrigin],
    ctx_len: Int,
    rnd: UnsafePointer[UInt8, ImmutAnyOrigin],
    sk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa65"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt64, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLDSA_NATIVE_MLDSA65_signature_pre_hash_shake256")
    return func(sig, siglen, msg, msg_len, ctx, ctx_len, rnd, sk)


fn mldsa65_verify(
    sig: UnsafePointer[UInt8, ImmutAnyOrigin],
    sig_len: Int,
    msg: UnsafePointer[UInt8, ImmutAnyOrigin],
    msg_len: Int,
    ctx: UnsafePointer[UInt8, ImmutAnyOrigin],
    ctx_len: Int,
    pk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa65"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLDSA_NATIVE_MLDSA65_verify")
    return func(sig, sig_len, msg, msg_len, ctx, ctx_len, pk)


fn mldsa65_verify_internal(
    sig: UnsafePointer[UInt8, ImmutAnyOrigin],
    sig_len: Int,
    msg: UnsafePointer[UInt8, ImmutAnyOrigin],
    msg_len: Int,
    pre: UnsafePointer[UInt8, ImmutAnyOrigin],
    pre_len: Int,
    pk: UnsafePointer[UInt8, ImmutAnyOrigin],
    externalmu: Int
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa65"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int) -> Int]("PQCP_MLDSA_NATIVE_MLDSA65_verify_internal")
    return func(sig, sig_len, msg, msg_len, pre, pre_len, pk, externalmu)


fn mldsa65_verify_pre_hash_internal(
    sig: UnsafePointer[UInt8, ImmutAnyOrigin],
    sig_len: Int,
    ph: UnsafePointer[UInt8, ImmutAnyOrigin],
    ph_len: Int,
    ctx: UnsafePointer[UInt8, ImmutAnyOrigin],
    ctx_len: Int,
    pk: UnsafePointer[UInt8, ImmutAnyOrigin],
    hashalg: Int
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa65"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int) -> Int]("PQCP_MLDSA_NATIVE_MLDSA65_verify_pre_hash_internal")
    return func(sig, sig_len, ph, ph_len, ctx, ctx_len, pk, hashalg)


fn mldsa65_verify_extmu(
    sig: UnsafePointer[UInt8, ImmutAnyOrigin],
    sig_len: Int,
    mu: UnsafePointer[UInt8, ImmutAnyOrigin],
    pk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa65"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLDSA_NATIVE_MLDSA65_verify_extmu")
    return func(sig, sig_len, mu, pk)


fn mldsa87_keypair(
    pk: UnsafePointer[UInt8, MutAnyOrigin],
    sk: UnsafePointer[UInt8, MutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa87"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, MutAnyOrigin]) -> Int]("PQCP_MLDSA_NATIVE_MLDSA87_keypair")
    return func(pk, sk)


fn mldsa87_keypair_internal(
    pk: UnsafePointer[UInt8, MutAnyOrigin],
    sk: UnsafePointer[UInt8, MutAnyOrigin],
    seed: UnsafePointer[UInt8, MutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa87"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt8, MutAnyOrigin]) -> Int]("PQCP_MLDSA_NATIVE_MLDSA87_keypair_internal")
    return func(pk, sk, seed)


fn mldsa87_signature(
    sig: UnsafePointer[UInt8, MutAnyOrigin],
    siglen: UnsafePointer[UInt64, MutAnyOrigin],
    msg: UnsafePointer[UInt8, ImmutAnyOrigin],
    msg_len: Int,
    ctx: UnsafePointer[UInt8, ImmutAnyOrigin],
    ctx_len: Int,
    sk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa87"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt64, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLDSA_NATIVE_MLDSA87_signature")
    return func(sig, siglen, msg, msg_len, ctx, ctx_len, sk)


fn mldsa87_signature_internal(
    sig: UnsafePointer[UInt8, MutAnyOrigin],
    siglen: UnsafePointer[UInt64, MutAnyOrigin],
    msg: UnsafePointer[UInt8, ImmutAnyOrigin],
    msg_len: Int,
    pre: UnsafePointer[UInt8, ImmutAnyOrigin],
    pre_len: Int,
    rnd: UnsafePointer[UInt8, ImmutAnyOrigin],
    sk: UnsafePointer[UInt8, ImmutAnyOrigin],
    externalmu: Int
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa87"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt64, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], Int) -> Int]("PQCP_MLDSA_NATIVE_MLDSA87_signature_internal")
    return func(sig, siglen, msg, msg_len, pre, pre_len, rnd, sk, externalmu)


fn mldsa87_signature_pre_hash_internal(
    sig: UnsafePointer[UInt8, MutAnyOrigin],
    siglen: UnsafePointer[UInt64, MutAnyOrigin],
    ph: UnsafePointer[UInt8, ImmutAnyOrigin],
    ph_len: Int,
    ctx: UnsafePointer[UInt8, ImmutAnyOrigin],
    ctx_len: Int,
    rnd: UnsafePointer[UInt8, ImmutAnyOrigin],
    sk: UnsafePointer[UInt8, ImmutAnyOrigin],
    hashalg: Int
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa87"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt64, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], Int) -> Int]("PQCP_MLDSA_NATIVE_MLDSA87_signature_pre_hash_internal")
    return func(sig, siglen, ph, ph_len, ctx, ctx_len, rnd, sk, hashalg)


fn mldsa87_signature_pre_hash_shake256(
    sig: UnsafePointer[UInt8, MutAnyOrigin],
    siglen: UnsafePointer[UInt64, MutAnyOrigin],
    msg: UnsafePointer[UInt8, ImmutAnyOrigin],
    msg_len: Int,
    ctx: UnsafePointer[UInt8, ImmutAnyOrigin],
    ctx_len: Int,
    rnd: UnsafePointer[UInt8, ImmutAnyOrigin],
    sk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa87"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], UnsafePointer[UInt64, MutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLDSA_NATIVE_MLDSA87_signature_pre_hash_shake256")
    return func(sig, siglen, msg, msg_len, ctx, ctx_len, rnd, sk)


fn mldsa87_verify(
    sig: UnsafePointer[UInt8, ImmutAnyOrigin],
    sig_len: Int,
    msg: UnsafePointer[UInt8, ImmutAnyOrigin],
    msg_len: Int,
    ctx: UnsafePointer[UInt8, ImmutAnyOrigin],
    ctx_len: Int,
    pk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa87"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLDSA_NATIVE_MLDSA87_verify")
    return func(sig, sig_len, msg, msg_len, ctx, ctx_len, pk)


fn mldsa87_verify_internal(
    sig: UnsafePointer[UInt8, ImmutAnyOrigin],
    sig_len: Int,
    msg: UnsafePointer[UInt8, ImmutAnyOrigin],
    msg_len: Int,
    pre: UnsafePointer[UInt8, ImmutAnyOrigin],
    pre_len: Int,
    pk: UnsafePointer[UInt8, ImmutAnyOrigin],
    externalmu: Int
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa87"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int) -> Int]("PQCP_MLDSA_NATIVE_MLDSA87_verify_internal")
    return func(sig, sig_len, msg, msg_len, pre, pre_len, pk, externalmu)


fn mldsa87_verify_pre_hash_internal(
    sig: UnsafePointer[UInt8, ImmutAnyOrigin],
    sig_len: Int,
    ph: UnsafePointer[UInt8, ImmutAnyOrigin],
    ph_len: Int,
    ctx: UnsafePointer[UInt8, ImmutAnyOrigin],
    ctx_len: Int,
    pk: UnsafePointer[UInt8, ImmutAnyOrigin],
    hashalg: Int
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa87"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], Int) -> Int]("PQCP_MLDSA_NATIVE_MLDSA87_verify_pre_hash_internal")
    return func(sig, sig_len, ph, ph_len, ctx, ctx_len, pk, hashalg)


fn mldsa87_verify_extmu(
    sig: UnsafePointer[UInt8, ImmutAnyOrigin],
    sig_len: Int,
    mu: UnsafePointer[UInt8, ImmutAnyOrigin],
    pk: UnsafePointer[UInt8, ImmutAnyOrigin]
) raises -> Int:
    var lib = OwnedDLHandle(_get_lib_path("libmldsa87"))
    var func = lib.get_function[fn(UnsafePointer[UInt8, ImmutAnyOrigin], Int, UnsafePointer[UInt8, ImmutAnyOrigin], UnsafePointer[UInt8, ImmutAnyOrigin]) -> Int]("PQCP_MLDSA_NATIVE_MLDSA87_verify_extmu")
    return func(sig, sig_len, mu, pk)


fn nibble_to_hex_char(n: UInt8) -> UInt8:
    if n < 10:
        return n + 48
    else:
        return n + 55


fn bytes_to_hex_str(data: List[UInt8]) -> String:
    var result = String()
    for i in range(len(data)):
        var b = data[i]
        var high = (b >> 4) & 0x0F
        var low = b & 0x0F
        result += chr(Int(nibble_to_hex_char(high)))
        result += chr(Int(nibble_to_hex_char(low)))
    return result
