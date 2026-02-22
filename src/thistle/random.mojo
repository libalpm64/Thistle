from sys.ffi import OwnedDLHandle
from memory import UnsafePointer, alloc
from collections import List
from python import Python


fn _get_random_lib_path() raises -> String:
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
    var lib_path = libs_dir + "/randombytes." + ext
    var exists = os_mod.path.exists(lib_path)
    if not exists:
        raise Error("Random library not found. Run: pixi run build-pq")
    return lib_path


fn random_fill(buf: UnsafePointer[UInt8, MutAnyOrigin], len: Int) raises:
    var lib = OwnedDLHandle(_get_random_lib_path())
    var func = lib.get_function[fn(UnsafePointer[UInt8, MutAnyOrigin], Int)]("randombytes")
    func(buf, len)


fn random_bytes(n: Int) raises -> List[UInt8]:
    var buf = alloc[UInt8](n)
    random_fill(buf, n)
    var result = List[UInt8](capacity=n)
    for i in range(n):
        result.append(buf[i])
    buf.free()
    return result^
