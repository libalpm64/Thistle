"""
Wycheproof RSASSA-PSS test.
"""

from std.collections import List
from std.python import Python, PythonObject
from thistle.rsa import rsa_pss_verify, SHA1, SHA224, SHA256, SHA384, SHA512


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


def sha_id(name: String) raises -> Int:
    if name == "SHA-1":
        return SHA1
    if name == "SHA-224":
        return SHA224
    if name == "SHA-256":
        return SHA256
    if name == "SHA-384":
        return SHA384
    if name == "SHA-512":
        return SHA512
    raise Error("unknown sha: " + name)


def run_file(py: PythonObject, builtins: PythonObject, path: String) raises -> Bool:
    var fh = builtins.open(path, "r", encoding="utf-8")
    var root = py.load(fh)
    fh.close()

    var ok_count = 0
    var fail_count = 0
    for g in root["testGroups"]:
        var sha = sha_id(String(g["sha"]))
        var mgf_sha = sha_id(String(g["mgfSha"]))
        var s_len = Int(py=g["sLen"])
        var n = hex_to_bytes(String(g["publicKey"]["modulus"]))
        var e = hex_to_bytes(String(g["publicKey"]["publicExponent"]))
        for t in g["tests"]:
            var msg = hex_to_bytes(String(t["msg"]))
            var sig = hex_to_bytes(String(t["sig"]))
            var result = String(t["result"])
            var got = False
            try:
                got = rsa_pss_verify(
                    Span[UInt8, ...](n), Span[UInt8, ...](e),
                    Span[UInt8, ...](msg), Span[UInt8, ...](sig),
                    sha, mgf_sha, s_len,
                )
            except:
                got = False
            var pass_case = True
            if result == "valid" and not got:
                pass_case = False
            if result == "invalid" and got:
                pass_case = False
            if pass_case:
                ok_count += 1
            else:
                fail_count += 1
                print("Test ", String(t["tcId"]), " result=", result, " got=", got)
    print(path, ": ", ok_count, " OK, ", fail_count, " FAIL")
    return fail_count == 0


def main() raises:
    print("Wycheproof RSASSA-PSS")
    var py = Python.import_module("json")
    var builtins = Python.import_module("builtins")

    var all_ok = True
    all_ok = run_file(py, builtins, "tests/Wycheproof/rsa_pss_2048_sha256_mgf1_32_test.json") and all_ok
    all_ok = run_file(py, builtins, "tests/Wycheproof/rsa_pss_3072_sha256_mgf1_32_test.json") and all_ok
    all_ok = run_file(py, builtins, "tests/Wycheproof/rsa_pss_4096_sha512_mgf1_64_test.json") and all_ok
    all_ok = run_file(py, builtins, "tests/Wycheproof/rsa_pss_misc_test.json") and all_ok
    all_ok = run_file(py, builtins, "tests/Wycheproof/rsa_pss_misc_params_test.json") and all_ok
    if not all_ok:
        raise Error("Wycheproof RSA-PSS failures")
