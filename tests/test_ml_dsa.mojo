from std.collections import List
from std.python import Python, PythonObject
from thistle.ml_dsa import (
    MLDSAParams,
    MLDSAPrivateKey,
    mldsa_private_key_from_seed,
    mldsa_private_key_from_semiexpanded,
    mldsa_public_key_from_seed,
    mldsa_sign,
    mldsa_sign_external_mu,
    mldsa_verify,
    mldsa_keygen,
    mldsa44_keygen,
    mldsa65_keygen,
    mldsa87_keygen,
    mldsa_sign_hedged,
    mldsa_sign_deterministic,
    params44,
    params65,
    params87,
    private_key_size,
    public_key_size,
    signature_size,
    new_public_key,
)

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


def bytes_equal(a: List[UInt8], b: List[UInt8]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def matches_hex(actual: List[UInt8], expected_hex: String) -> Bool:
    if len(actual) * 2 != expected_hex.byte_length():
        return False
    return bytes_equal(actual, hex_to_bytes(expected_hex))


def zero_random() -> List[UInt8]:
    var r = List[UInt8](capacity=32)
    for _ in range(32):
        r.append(0)
    return r^


def load_json(path: String, py: PythonObject) raises -> PythonObject:
    var builtins = Python.import_module("builtins")
    var fh = builtins.open(path, "r")
    try:
        var root = py.load(fh)
        return root
    finally:
        fh.close()


def has_field(obj: PythonObject, name: String) raises -> Bool:
    return Bool(obj.__contains__(name))


def get_context(t: PythonObject) raises -> List[UInt8]:
    if has_field(t, "ctx"):
        return hex_to_bytes(String(t["ctx"]))
    return List[UInt8]()


def get_params(level: Int) raises -> MLDSAParams:
    if level == 44:
        return params44()
    if level == 65:
        return params65()
    if level == 87:
        return params87()
    raise Error("invalid ML-DSA level: " + String(level))


def run_verify_file(path: String, level: Int, py: PythonObject) raises -> Tuple[Int, Int]:
    var root = load_json(path, py)
    var p = get_params(level)
    var passed = 0
    var failed = 0
    for g in root["testGroups"]:
        var pk = hex_to_bytes(String(g["publicKey"]))
        if len(pk) != public_key_size(p):
            for t in g["tests"]:
                if String(t["result"]) == "valid":
                    print(path, " tcId=", String(t["tcId"]), " invalid public key for valid vector")
                    failed += 1
                else:
                    passed += 1
            continue
        var pub = new_public_key(Span[UInt8, ...](pk), p)
        for t in g["tests"]:
            var tc_id = String(t["tcId"])
            var expected = String(t["result"]) == "valid"
            var sig = hex_to_bytes(String(t["sig"]))
            var msg = hex_to_bytes(String(t["msg"]))
            var ctx = get_context(t)
            var got: Bool
            try:
                got = mldsa_verify(pub, Span[UInt8, ...](msg), Span[UInt8, ...](sig), Span[UInt8, ...](ctx))
            except:
                got = False
            if got != expected:
                print(path, " tcId=", tc_id, " verify mismatch")
                failed += 1
            else:
                passed += 1
    return passed, failed


def run_sign_seed_file(path: String, level: Int, py: PythonObject) raises -> Tuple[Int, Int]:
    var root = load_json(path, py)
    var p = get_params(level)
    var passed = 0
    var failed = 0
    var rnd = zero_random()
    for g in root["testGroups"]:
        var seed = hex_to_bytes(String(g["privateSeed"]))
        var expected_key_valid = len(seed) == 32
        if expected_key_valid:
            try:
                var priv = mldsa_private_key_from_seed(Span[UInt8, ...](seed), p)
                if has_field(g, "publicKey"):
                    if not matches_hex(priv.pub.raw, String(g["publicKey"])):
                        print(path, " public key mismatch")
                        failed += 1
                        continue
                for t in g["tests"]:
                    var tc_id = String(t["tcId"])
                    var expected = String(t["result"]) == "valid"
                    var got: Bool
                    try:
                        if has_field(t, "mu") and String(t["mu"]) != "":
                            var mu = hex_to_bytes(String(t["mu"]))
                            var sig = mldsa_sign_external_mu(priv, Span[UInt8, ...](mu), Span[UInt8, ...](rnd))
                            got = matches_hex(sig, String(t["sig"]))
                        else:
                            var msg = hex_to_bytes(String(t["msg"]))
                            var ctx = get_context(t)
                            var sig = mldsa_sign(priv, Span[UInt8, ...](msg), Span[UInt8, ...](ctx), Span[UInt8, ...](rnd))
                            got = matches_hex(sig, String(t["sig"]))
                    except:
                        got = False
                    if got != expected:
                        print(path, " tcId=", tc_id, " sign-seed mismatch")
                        failed += 1
                    else:
                        passed += 1
                continue
            except:
                pass
        for t in g["tests"]:
            var tc_id = String(t["tcId"])
            var expected = String(t["result"]) == "valid"
            var got = False
            if got != expected:
                print(path, " tcId=", tc_id, " sign-seed mismatch")
                failed += 1
            else:
                passed += 1
    return passed, failed


def run_sign_noseed_file(path: String, level: Int, py: PythonObject) raises -> Tuple[Int, Int]:
    var root = load_json(path, py)
    var p = get_params(level)
    var passed = 0
    var failed = 0
    var rnd = zero_random()
    for g in root["testGroups"]:
        var sk = hex_to_bytes(String(g["privateKey"]))
        var expected_key_valid = len(sk) == private_key_size(p)
        if expected_key_valid:
            try:
                var priv = mldsa_private_key_from_semiexpanded(Span[UInt8, ...](sk), p)
                if has_field(g, "publicKey") and String(g["publicKey"]) != "None":
                    if not matches_hex(priv.pub.raw, String(g["publicKey"])):
                        print(path, " public key mismatch")
                        failed += 1
                        continue
                for t in g["tests"]:
                    var tc_id = String(t["tcId"])
                    var expected = String(t["result"]) == "valid"
                    var got: Bool
                    try:
                        if has_field(t, "mu") and String(t["mu"]) != "":
                            var mu = hex_to_bytes(String(t["mu"]))
                            var sig = mldsa_sign_external_mu(priv, Span[UInt8, ...](mu), Span[UInt8, ...](rnd))
                            got = matches_hex(sig, String(t["sig"]))
                        else:
                            var msg = hex_to_bytes(String(t["msg"]))
                            var ctx = get_context(t)
                            var sig = mldsa_sign(priv, Span[UInt8, ...](msg), Span[UInt8, ...](ctx), Span[UInt8, ...](rnd))
                            got = matches_hex(sig, String(t["sig"]))
                    except:
                        got = False
                    if got != expected:
                        print(path, " tcId=", tc_id, " sign-noseed mismatch")
                        failed += 1
                    else:
                        passed += 1
                continue
            except:
                pass
        for t in g["tests"]:
            var tc_id = String(t["tcId"])
            var expected = String(t["result"]) == "valid"
            var got = False
            if got != expected:
                print(path, " tcId=", tc_id, " sign-noseed mismatch")
                failed += 1
            else:
                passed += 1
    return passed, failed



def run_external_api_smoke_tests() raises -> Tuple[Int, Int]:
    var passed = 0
    var failed = 0

    var msg = List[UInt8](capacity=3)
    msg.append(UInt8(97))
    msg.append(UInt8(98))
    msg.append(UInt8(99))
    var ctx = List[UInt8]()

    try:
        var priv44 = mldsa44_keygen()
        if len(priv44.pub.raw) != public_key_size(params44()):
            print("external API: ML-DSA-44 keygen produced wrong public key size")
            failed += 1
        else:
            passed += 1

        var sig_h = mldsa_sign_hedged(priv44, Span[UInt8, ...](msg), Span[UInt8, ...](ctx))
        if not mldsa_verify(priv44.pub, Span[UInt8, ...](msg), Span[UInt8, ...](sig_h), Span[UInt8, ...](ctx)):
            print("external API: ML-DSA-44 hedged signature did not verify")
            failed += 1
        else:
            passed += 1

        var sig_d = mldsa_sign_deterministic(priv44, Span[UInt8, ...](msg), Span[UInt8, ...](ctx))
        if not mldsa_verify(priv44.pub, Span[UInt8, ...](msg), Span[UInt8, ...](sig_d), Span[UInt8, ...](ctx)):
            print("external API: ML-DSA-44 deterministic signature did not verify")
            failed += 1
        else:
            passed += 1
    except:
        print("external API: ML-DSA-44 smoke test raised")
        failed += 3

    try:
        var priv65 = mldsa65_keygen()
        if len(priv65.pub.raw) != public_key_size(params65()):
            print("external API: ML-DSA-65 keygen produced wrong public key size")
            failed += 1
        else:
            passed += 1
    except:
        print("external API: ML-DSA-65 keygen raised")
        failed += 1

    try:
        var priv87 = mldsa87_keygen()
        if len(priv87.pub.raw) != public_key_size(params87()):
            print("external API: ML-DSA-87 keygen produced wrong public key size")
            failed += 1
        else:
            passed += 1
    except:
        print("external API: ML-DSA-87 keygen raised")
        failed += 1

    return passed, failed


def main() raises:
    print("ML-DSA test suite")
    var py = Python.import_module("json")
    var passed = 0
    var failed = 0
    var result = run_external_api_smoke_tests()
    passed += result[0]
    failed += result[1]

    result = run_sign_seed_file("tests/Wycheproof/mldsa_44_sign_seed_test.json", 44, py)
    passed += result[0]
    failed += result[1]
    result = run_sign_seed_file("tests/Wycheproof/mldsa_65_sign_seed_test.json", 65, py)
    passed += result[0]
    failed += result[1]
    result = run_sign_seed_file("tests/Wycheproof/mldsa_87_sign_seed_test.json", 87, py)
    passed += result[0]
    failed += result[1]

    result = run_sign_noseed_file("tests/Wycheproof/mldsa_44_sign_noseed_test.json", 44, py)
    passed += result[0]
    failed += result[1]
    result = run_sign_noseed_file("tests/Wycheproof/mldsa_65_sign_noseed_test.json", 65, py)
    passed += result[0]
    failed += result[1]
    result = run_sign_noseed_file("tests/Wycheproof/mldsa_87_sign_noseed_test.json", 87, py)
    passed += result[0]
    failed += result[1]

    result = run_verify_file("tests/Wycheproof/mldsa_44_verify_test.json", 44, py)
    passed += result[0]
    failed += result[1]
    result = run_verify_file("tests/Wycheproof/mldsa_65_verify_test.json", 65, py)
    passed += result[0]
    failed += result[1]
    result = run_verify_file("tests/Wycheproof/mldsa_87_verify_test.json", 87, py)
    passed += result[0]
    failed += result[1]

    print("ML-DSA test suite: ", passed, " passed, ", failed, " failed")
    if failed > 0:
        raise Error("ML-DSA test suite failed")
