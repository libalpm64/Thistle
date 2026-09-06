from std.collections import List
from std.python import Python, PythonObject
from thistle.ml_kem import (
    N,
    Q,
    POLYBYTES,
    SYMBYTES,
    Poly,
    barrett_reduce,
    cbd2,
    cbd3,
    mlkem_decaps,
    mlkem_encaps,
    mlkem_encaps_seed,
    mlkem_encaps_seed_vector,
    mlkem_keygen,
    mlkem_keygen_seed,
    mlkem512_encaps,
    mlkem512_decaps,
    mlkem512_keygen,
    mlkem768_encaps,
    mlkem768_decaps,
    mlkem768_keygen,
    mlkem1024_encaps,
    mlkem1024_decaps,
    mlkem1024_keygen,
    montgomery_reduce,
    poly_frombytes,
    poly_frommsg,
    poly_ntt,
    poly_reduce,
    poly_tobytes,
    poly_tomsg
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


def matches_hex(actual: List[UInt8], expected_hex: String) -> Bool:
    if len(actual) * 2 != expected_hex.byte_length():
        return False
    var expected = hex_to_bytes(expected_hex)
    if len(actual) != len(expected):
        return False
    for i in range(len(actual)):
        if actual[i] != expected[i]:
            return False
    return True


def list_equal(a: List[UInt8], b: List[UInt8]) -> Bool:
    if len(a) != len(b):
        return False
    var diff = UInt8(0)
    for i in range(len(a)):
        diff |= a[i] ^ b[i]
    return diff == 0


def test_mlkem_external_api() raises -> Tuple[Int, Int]:
    var passed = 0
    var failed = 0

    var pair512 = mlkem512_keygen()
    var ek512 = pair512[0].copy()
    var dk512 = pair512[1].copy()
    var enc512 = mlkem512_encaps(Span[UInt8, ...](ek512))
    if not enc512[2]:
        print("ML-KEM external API: ML-KEM-512 encaps rejected generated key")
        failed += 1
    else:
        var ct512 = enc512[0].copy()
        var ss512 = enc512[1].copy()
        var dec512 = mlkem512_decaps(Span[UInt8, ...](dk512), Span[UInt8, ...](ct512))
        if not dec512[1] or not list_equal(ss512, dec512[0].copy()):
            print("ML-KEM external API: ML-KEM-512 decaps mismatch")
            failed += 1
        else:
            passed += 1

    var pair768 = mlkem768_keygen()
    var ek768 = pair768[0].copy()
    var dk768 = pair768[1].copy()
    var enc768 = mlkem768_encaps(Span[UInt8, ...](ek768))
    if not enc768[2]:
        print("ML-KEM external API: ML-KEM-768 encaps rejected generated key")
        failed += 1
    else:
        var ct768 = enc768[0].copy()
        var ss768 = enc768[1].copy()
        var dec768 = mlkem768_decaps(Span[UInt8, ...](dk768), Span[UInt8, ...](ct768))
        if not dec768[1] or not list_equal(ss768, dec768[0].copy()):
            print("ML-KEM external API: ML-KEM-768 decaps mismatch")
            failed += 1
        else:
            passed += 1

    var pair1024 = mlkem1024_keygen()
    var ek1024 = pair1024[0].copy()
    var dk1024 = pair1024[1].copy()
    var enc1024 = mlkem1024_encaps(Span[UInt8, ...](ek1024))
    if not enc1024[2]:
        print("ML-KEM external API: ML-KEM-1024 encaps rejected generated key")
        failed += 1
    else:
        var ct1024 = enc1024[0].copy()
        var ss1024 = enc1024[1].copy()
        var dec1024 = mlkem1024_decaps(Span[UInt8, ...](dk1024), Span[UInt8, ...](ct1024))
        if not dec1024[1] or not list_equal(ss1024, dec1024[0].copy()):
            print("ML-KEM external API: ML-KEM-1024 decaps mismatch")
            failed += 1
        else:
            passed += 1

    var generic = mlkem_keygen("ML-KEM-512")
    var generic_ek = generic[0].copy()
    var generic_dk = generic[1].copy()
    var generic_enc = mlkem_encaps(Span[UInt8, ...](generic_ek), "ML-KEM-512")
    if not generic_enc[2]:
        print("ML-KEM external API: generic encaps rejected generated key")
        failed += 1
    else:
        var generic_ct = generic_enc[0].copy()
        var generic_ss = generic_enc[1].copy()
        var generic_dec = mlkem_decaps(Span[UInt8, ...](generic_dk), Span[UInt8, ...](generic_ct), "ML-KEM-512")
        if not generic_dec[1] or not list_equal(generic_ss, generic_dec[0].copy()):
            print("ML-KEM external API: generic decaps mismatch")
            failed += 1
        else:
            passed += 1

    var seeded_m = List[UInt8](length=SYMBYTES, fill=0)
    for i in range(SYMBYTES):
        seeded_m[i] = UInt8(i)
    var seeded_standard = mlkem_encaps_seed(
        Span[UInt8, ...](generic_ek), Span[UInt8, ...](seeded_m), "ML-KEM-512"
    )
    var seeded_vector = mlkem_encaps_seed_vector(
        Span[UInt8, ...](generic_ek), Span[UInt8, ...](seeded_m), "ML-KEM-512"
    )
    if not seeded_standard[2] or not seeded_vector[2]:
        print("ML-KEM external API: seeded encaps rejected generated key")
        failed += 1
    elif (
        not list_equal(seeded_standard[0].copy(), seeded_vector[1].copy())
        or not list_equal(seeded_standard[1].copy(), seeded_vector[0].copy())
    ):
        print("ML-KEM external API: seeded encaps output order mismatch")
        failed += 1
    else:
        passed += 1

    return (passed, failed)


def load_json(path: String, py: PythonObject) raises -> PythonObject:
    var builtins = Python.import_module("builtins")
    var fh = builtins.open(path, "r", encoding="utf-8")
    try:
        var root = py.load(fh)
        return root
    finally:
        fh.close()


def test_mlkem_core() raises -> Tuple[Int, Int]:
    var p = Poly()
    for i in range(N):
        p.coeffs[i] = Int16((i * 17 + 23) % Q)

    poly_reduce(p)
    var encoded = List[UInt8](capacity=POLYBYTES)
    poly_tobytes(encoded, p)
    if len(encoded) != POLYBYTES:
        print("ML-KEM core: poly_tobytes produced wrong length")
        return (0, 1)

    var decoded = Poly()
    if not poly_frombytes(decoded, Span[UInt8, ...](encoded)):
        print("ML-KEM core: poly_frombytes rejected canonical polynomial")
        return (0, 1)

    for i in range(N):
        var canon = p.coeffs[i]
        canon += (canon >> 15) & Int16(Q)
        if canon != decoded.coeffs[i]:
            print("ML-KEM core: poly_tobytes/poly_frombytes mismatch")
            return (0, 1)

    var msg = List[UInt8](capacity=32)
    for i in range(32):
        msg.append(UInt8(i))
    var from_msg = Poly()
    poly_frommsg(from_msg, Span[UInt8, ...](msg))
    var round_msg = List[UInt8](capacity=32)
    poly_tomsg(round_msg, from_msg)
    if len(round_msg) != 32:
        print("ML-KEM core: poly_tomsg produced wrong length")
        return (0, 1)

    var seed2 = List[UInt8](capacity=128)
    for i in range(128):
        seed2.append(UInt8(i))
    var cbd_eta2 = Poly()
    cbd2(cbd_eta2, Span[UInt8, ...](seed2))

    var seed3 = List[UInt8](capacity=192)
    for i in range(192):
        seed3.append(UInt8(i))
    var cbd_eta3 = Poly()
    cbd3(cbd_eta3, Span[UInt8, ...](seed3))

    var ntt_poly = p.copy()
    poly_ntt(ntt_poly)

    _ = montgomery_reduce(123456)
    _ = barrett_reduce(1234)
    return (1, 0)


def run_keygen_file(path: String, py: PythonObject) raises -> Tuple[Int, Int]:
    var root = load_json(path, py)
    var passed = 0
    var failed = 0
    for g in root["testGroups"]:
        var parameter_set = String(g["parameterSet"])
        for t in g["tests"]:
            if String(t["result"]) != "valid":
                continue
            var tc_id = String(t["tcId"])
            var seed = hex_to_bytes(String(t["seed"]))
            var pair = mlkem_keygen_seed(Span[UInt8, ...](seed), parameter_set)
            var ek = pair[0].copy()
            var dk = pair[1].copy()
            if not matches_hex(ek, String(t["ek"])):
                print(path, " tcId=", tc_id, " ek mismatch")
                failed += 1
                continue
            if not matches_hex(dk, String(t["dk"])):
                print(path, " tcId=", tc_id, " dk mismatch")
                failed += 1
                continue
            passed += 1
    return passed, failed


def run_encaps_file(path: String, py: PythonObject) raises -> Tuple[Int, Int]:
    var root = load_json(path, py)
    var passed = 0
    var failed = 0
    for g in root["testGroups"]:
        var parameter_set = String(g["parameterSet"])
        for t in g["tests"]:
            var tc_id = String(t["tcId"])
            var expected_valid = String(t["result"]) == "valid"
            var m = hex_to_bytes(String(t["m"]))
            var ek = hex_to_bytes(String(t["ek"]))
            var result = mlkem_encaps_seed_vector(
                Span[UInt8, ...](ek), Span[UInt8, ...](m), parameter_set
            )
            var got_valid = result[2]
            if got_valid != expected_valid:
                print(path, " tcId=", tc_id, " validity mismatch")
                failed += 1
                continue
            if got_valid:
                var shared = result[0].copy()
                var ciphertext = result[1].copy()
                if not matches_hex(ciphertext, String(t["c"])):
                    print(path, " tcId=", tc_id, " ciphertext mismatch")
                    failed += 1
                    continue
                if not matches_hex(shared, String(t["K"])):
                    print(path, " tcId=", tc_id, " shared secret mismatch")
                    failed += 1
                    continue
            passed += 1
    return passed, failed


def run_decaps_file(path: String, py: PythonObject) raises -> Tuple[Int, Int]:
    var root = load_json(path, py)
    var passed = 0
    var failed = 0
    for g in root["testGroups"]:
        var parameter_set = String(g["parameterSet"])
        for t in g["tests"]:
            var tc_id = String(t["tcId"])
            var expected_valid = String(t["result"]) == "valid"
            var dk = hex_to_bytes(String(t["dk"]))
            var c = hex_to_bytes(String(t["c"]))
            var result = mlkem_decaps(
                Span[UInt8, ...](dk), Span[UInt8, ...](c), parameter_set
            )
            var got_valid = result[1]
            if got_valid != expected_valid:
                print(path, " tcId=", tc_id, " validity mismatch")
                failed += 1
                continue
            if got_valid:
                var shared = result[0].copy()
                var expected_k = String(t.get("K", ""))
                if expected_k != "" and not matches_hex(shared, expected_k):
                    print(path, " tcId=", tc_id, " shared secret mismatch")
                    failed += 1
                    continue
            passed += 1
    return passed, failed


def run_full_file(path: String, py: PythonObject) raises -> Tuple[Int, Int]:
    var root = load_json(path, py)
    var passed = 0
    var failed = 0
    for g in root["testGroups"]:
        var parameter_set = String(g["parameterSet"])
        for t in g["tests"]:
            var tc_id = String(t["tcId"])
            if String(t["result"]) != "valid":
                continue
            var seed = hex_to_bytes(String(t["seed"]))
            var pair = mlkem_keygen_seed(Span[UInt8, ...](seed), parameter_set)
            var ek = pair[0].copy()
            var dk = pair[1].copy()
            if not matches_hex(ek, String(t["ek"])):
                print(path, " tcId=", tc_id, " ek mismatch")
                failed += 1
                continue
            var c = hex_to_bytes(String(t["c"]))
            var dec = mlkem_decaps(
                Span[UInt8, ...](dk), Span[UInt8, ...](c), parameter_set
            )
            if not dec[1]:
                print(path, " tcId=", tc_id, " decaps rejected")
                failed += 1
                continue
            var shared = dec[0].copy()
            if not matches_hex(shared, String(t["K"])):
                print(path, " tcId=", tc_id, " shared secret mismatch")
                failed += 1
                continue
            passed += 1
    return passed, failed


def run_nist_keygen_file(prompt_path: String, expected_path: String, py: PythonObject) raises -> Tuple[Int, Int]:
    var prompt = load_json(prompt_path, py)
    var expected = load_json(expected_path, py)
    var passed = 0
    var failed = 0
    for group_idx in range(Int(py=prompt["testGroups"].__len__())):
        var g = prompt["testGroups"][group_idx]
        var eg = expected["testGroups"][group_idx]
        var parameter_set = String(g["parameterSet"])
        var tests = g["tests"]
        var expected_tests = eg["tests"]
        for test_idx in range(Int(py=tests.__len__())):
            var t = tests[test_idx]
            var et = expected_tests[test_idx]
            var tc_id = String(t["tcId"])
            var d = hex_to_bytes(String(t["d"]))
            var z = hex_to_bytes(String(t["z"]))
            var seed = List[UInt8](capacity=64)
            for i in range(32):
                seed.append(d[i])
            for i in range(32):
                seed.append(z[i])
            var pair = mlkem_keygen_seed(Span[UInt8, ...](seed), parameter_set)
            var ek = pair[0].copy()
            var dk = pair[1].copy()
            if not matches_hex(ek, String(et["ek"])):
                print(prompt_path, " tcId=", tc_id, " NIST ek mismatch")
                failed += 1
                continue
            if not matches_hex(dk, String(et["dk"])):
                print(prompt_path, " tcId=", tc_id, " NIST dk mismatch")
                failed += 1
                continue
            passed += 1
    return passed, failed


def run_nist_encapdecap_file(prompt_path: String, expected_path: String, py: PythonObject) raises -> Tuple[Int, Int]:
    var prompt = load_json(prompt_path, py)
    var expected = load_json(expected_path, py)
    var passed = 0
    var failed = 0
    for group_idx in range(Int(py=prompt["testGroups"].__len__())):
        var g = prompt["testGroups"][group_idx]
        var eg = expected["testGroups"][group_idx]
        var parameter_set = String(g["parameterSet"])
        var function = String(g["function"])
        var tests = g["tests"]
        var expected_tests = eg["tests"]
        for test_idx in range(Int(py=tests.__len__())):
            var t = tests[test_idx]
            var et = expected_tests[test_idx]
            var tc_id = String(t["tcId"])
            if function == "encapsulation":
                var ek = hex_to_bytes(String(t["ek"]))
                var m = hex_to_bytes(String(t["m"]))
                var result = mlkem_encaps_seed_vector(Span[UInt8, ...](ek), Span[UInt8, ...](m), parameter_set)
                if not result[2]:
                    print(prompt_path, " tcId=", tc_id, " NIST encaps rejected")
                    failed += 1
                    continue
                var shared = result[0].copy()
                var ciphertext = result[1].copy()
                if not matches_hex(ciphertext, String(et["c"])):
                    print(prompt_path, " tcId=", tc_id, " NIST ciphertext mismatch")
                    failed += 1
                    continue
                if not matches_hex(shared, String(et["k"])):
                    print(prompt_path, " tcId=", tc_id, " NIST shared secret mismatch")
                    failed += 1
                    continue
                passed += 1
            elif function == "decapsulation":
                var dk = hex_to_bytes(String(t["dk"]))
                var c = hex_to_bytes(String(t["c"]))
                var result = mlkem_decaps(Span[UInt8, ...](dk), Span[UInt8, ...](c), parameter_set)
                if not result[1]:
                    print(prompt_path, " tcId=", tc_id, " NIST decaps rejected")
                    failed += 1
                    continue
                var shared = result[0].copy()
                if not matches_hex(shared, String(et["k"])):
                    print(prompt_path, " tcId=", tc_id, " NIST decaps shared secret mismatch")
                    failed += 1
                    continue
                passed += 1
            else:
                # The pure Mojo API does not expose standalone key-check functions yet.
                pass
    return passed, failed


def main() raises:
    print("ML-KEM test suite")
    var py = Python.import_module("json")

    var passed = 0
    var failed = 0

    var result = test_mlkem_external_api()
    passed += result[0]
    failed += result[1]

    result = test_mlkem_core()
    passed += result[0]
    failed += result[1]

    result = run_keygen_file("tests/Wycheproof/mlkem_512_keygen_seed_test.json", py)
    passed += result[0]
    failed += result[1]
    result = run_keygen_file("tests/Wycheproof/mlkem_768_keygen_seed_test.json", py)
    passed += result[0]
    failed += result[1]
    result = run_keygen_file("tests/Wycheproof/mlkem_1024_keygen_seed_test.json", py)
    passed += result[0]
    failed += result[1]

    result = run_encaps_file("tests/Wycheproof/mlkem_512_encaps_test.json", py)
    passed += result[0]
    failed += result[1]
    result = run_encaps_file("tests/Wycheproof/mlkem_768_encaps_test.json", py)
    passed += result[0]
    failed += result[1]
    result = run_encaps_file("tests/Wycheproof/mlkem_1024_encaps_test.json", py)
    passed += result[0]
    failed += result[1]

    result = run_decaps_file("tests/Wycheproof/mlkem_512_semi_expanded_decaps_test.json", py)
    passed += result[0]
    failed += result[1]
    result = run_decaps_file("tests/Wycheproof/mlkem_768_semi_expanded_decaps_test.json", py)
    passed += result[0]
    failed += result[1]
    result = run_decaps_file("tests/Wycheproof/mlkem_1024_semi_expanded_decaps_test.json", py)
    passed += result[0]
    failed += result[1]

    result = run_full_file("tests/Wycheproof/mlkem_512_test.json", py)
    passed += result[0]
    failed += result[1]
    result = run_full_file("tests/Wycheproof/mlkem_768_test.json", py)
    passed += result[0]
    failed += result[1]
    result = run_full_file("tests/Wycheproof/mlkem_1024_test.json", py)
    passed += result[0]
    failed += result[1]

    result = run_nist_keygen_file("tests/NIST/ML-KEM-keyGen-FIPS203/prompt.json", "tests/NIST/ML-KEM-keyGen-FIPS203/expectedResults.json", py)
    passed += result[0]
    failed += result[1]
    result = run_nist_encapdecap_file("tests/NIST/ML-KEM-encapDecap-FIPS203/prompt.json", "tests/NIST/ML-KEM-encapDecap-FIPS203/expectedResults.json", py)
    passed += result[0]
    failed += result[1]

    # ML-KEM vectors cover the pure Mojo implementation; key-check-only ACVP groups are skipped.
    print("ML-KEM test suite: ", passed, " passed, ", failed, " failed")
    if failed > 0:
        raise Error("ML-KEM test suite failed")
