"""
Wycheproof X25519 test suite
"""
from std.collections import List
from std.python import Python
from thistle.x25519 import x25519
from thistle.utils import StackInlineArray

def hex_to_bytes(s: String) -> List[UInt8]:
    var r = List[UInt8]()
    var b = s.as_bytes()
    var n = s.byte_length()
    for i in range(0, n, 2):
        var hi_off = 39 if b[i] > 96 else (7 if b[i] > 64 else 0)
        var lo_off = 39 if b[i + 1] > 96 else (7 if b[i + 1] > 64 else 0)
        var hi = UInt8((b[i] - 48) - UInt8(hi_off))
        var lo = UInt8((b[i + 1] - 48) - UInt8(lo_off))
        r.append((hi << 4) | lo)
    return r^

def matches32(actual: StackInlineArray[UInt8, 32], expected: List[UInt8]) -> Bool:
    for i in range(32):
        if actual[i] != expected[i]:
            return False
    return True

def run_case(tc_id: String, private_hex: String, public_hex: String, shared_hex: String) raises -> Bool:
    var private_key = hex_to_bytes(private_hex)
    var public_key = hex_to_bytes(public_hex)
    var expected = hex_to_bytes(shared_hex)
    var actual = StackInlineArray[UInt8, 32](uninitialized=True)
    x25519(Span[UInt8, ...](private_key), Span[UInt8, ...](public_key), actual.unsafe_ptr())
    if not matches32(actual, expected):
        print("Test ", tc_id, " mismatch")
        return False
    return True

def main() raises:
    print("Wycheproof X25519")
    var py = Python.import_module("json")
    var builtins = Python.import_module("builtins")

    var fh = builtins.open("tests/Wycheproof/x25519_test.json", "r")
    var root = py.load(fh)
    fh.close()

    var groups = root["testGroups"]
    var ok_count = 0
    var fail_count = 0

    for g in groups:
        for t in g["tests"]:
            var tc_id = String(t["tcId"])
            var private_hex = String(t["private"])
            var public_hex = String(t["public"])
            var shared_hex = String(t["shared"])

            if run_case(tc_id, private_hex, public_hex, shared_hex):
                ok_count += 1
            else:
                fail_count += 1

    print("Wycheproof x25519: ", ok_count, " passed, ", fail_count, " failed")
    if fail_count > 0:
        raise Error("Wycheproof X25519 tests failed")
