# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Libalpm64, Lostlab Technologies.

"""
Wycheproof Ed25519 test suite
By Libalpm64
"""

from std.collections import List
from std.python import Python
from thistle.ed25519 import ed25519_verify

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


def run_case(tc_id: String, pk_hex: String, msg_hex: String, sig_hex: String, expected_valid: Bool) -> Bool:
    var pk = hex_to_bytes(pk_hex)
    var msg = hex_to_bytes(msg_hex)
    var sig = hex_to_bytes(sig_hex)
    var got = ed25519_verify(Span[UInt8, ...](pk), Span[UInt8, ...](msg), Span[UInt8, ...](sig))
    if got != expected_valid:
        print("Test ", tc_id, " mismatch: expected=", expected_valid, " got=", got)
        return False
    return True


def main() raises:
    print("Wycheproof Ed25519")
    var py = Python.import_module("json")
    var builtins = Python.import_module("builtins")

    var fh = builtins.open("tests/Wycheproof/ed25519_test.json", "r")
    var root = py.load(fh)
    fh.close()

    var groups = root["testGroups"]
    var ok_count = 0
    var fail_count = 0

    for g in groups:
        var pk_hex = String(g["publicKey"]["pk"])
        for t in g["tests"]:
            var tc_id = String(t["tcId"])
            var msg_hex = String(t["msg"])
            var sig_hex = String(t["sig"])
            var result = String(t["result"])
            var expected_valid = result == "valid"

            if run_case(tc_id, pk_hex, msg_hex, sig_hex, expected_valid):
                ok_count += 1
            else:
                fail_count += 1

    print("Wycheproof results: ", ok_count, " OK, ", fail_count, " FAIL")
    if fail_count > 0:
        raise Error("Wycheproof tests failed")
