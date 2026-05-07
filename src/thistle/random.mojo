from std.ffi import OwnedDLHandle
from std.memory import UnsafePointer
from std.collections import List
from std.python import Python

def _get_random_lib_path() raises -> String:
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


def random_fill(buf: UnsafePointer[UInt8, MutAnyOrigin], len: Int) raises:
    var lib = OwnedDLHandle(_get_random_lib_path())
    var func = lib.get_function[def(UnsafePointer[UInt8, MutAnyOrigin], Int)]("randombytes")
    func(buf, len)


def random_bytes(n: Int) raises -> List[UInt8]:
    var result = List[UInt8](capacity=n)
    for i in range(n):
        result.append(0)
    random_fill(result.unsafe_ptr(), n)
    return result^
