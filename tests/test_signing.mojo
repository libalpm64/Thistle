from std.collections import List
from std.python import Python, PythonObject
from thistle.p256 import (
    p256_ecdsa_sign,
    p256_ecdsa_verify,
    p256_ecdsa_sign_der,
    p256_ecdsa_verify_der,
    p256_keygen,
    p256_public_key,
)
from thistle.p384 import (
    p384_ecdsa_sign,
    p384_ecdsa_verify,
    p384_ecdsa_sign_der,
    p384_ecdsa_verify_der,
    p384_keygen,
    p384_public_key,
)
from thistle.x25519 import x25519_keygen, x25519_public_key
from thistle.pbkdf2 import hmac_sha384
from thistle.rsa import (
    rsa_pss_sign_with_salt,
    rsa_pss_verify,
    rsa_pkcs1_v15_sha256_verify,
    RsaPrivateKey,
    RsaCrtPrivateKey,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
)

def hex_bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    var data = s.as_bytes()
    for i in range(0, s.byte_length(), 2):
        var hi_off = 39 if data[i] > 96 else (7 if data[i] > 64 else 0)
        var lo_off = 39 if data[i + 1] > 96 else (7 if data[i + 1] > 64 else 0)
        var hi = UInt8((data[i] - 48) - UInt8(hi_off))
        var lo = UInt8((data[i + 1] - 48) - UInt8(lo_off))
        out.append((hi << 4) | lo)
    return out^


def equal(a: List[UInt8], b: List[UInt8]) -> Bool:
    if len(a) != len(b):
        return False
    var diff = UInt8(0)
    for i in range(len(a)):
        diff |= a[i] ^ b[i]
    return diff == 0


def test_hmac_sha384() raises:
    var key = List[UInt8](length=20, fill=0x0B)
    var data = hex_bytes("4869205468657265")
    var expected = hex_bytes(
        "AFD03944D84895626B0825F4AB46907F"
        "15F9DADBE4101EC682AA034C7CEBC59C"
        "FAEA9EA9076EDE7F4AF152E8B2FA9CB6"
    )
    var got = hmac_sha384(Span[UInt8, ...](key), Span[UInt8, ...](data))
    if not equal(got, expected):
        raise Error("HMAC-SHA384 short-key vector mismatch")

    key = List[UInt8](length=131, fill=0xAA)
    data = hex_bytes(
        "54657374205573696E67204C6172676572"
        "205468616E20426C6F636B2D53697A6520"
        "4B6579202D2048617368204B6579204669"
        "727374"
    )
    expected = hex_bytes(
        "4ECE084485813E9088D2C63A041BC5B4"
        "4F9EF1012A2B588F3CD11F05033AC4C6"
        "0C2EF6AB4030FE8296248DF163F44952"
    )
    got = hmac_sha384(Span[UInt8, ...](key), Span[UInt8, ...](data))
    if not equal(got, expected):
        raise Error("HMAC-SHA384 long-key vector mismatch")


def test_p256() raises:
    var private_key = hex_bytes(
        "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"
    )
    var public_key = hex_bytes(
        "0460FED4BA255A9D31C961EB74C6356D68"
        "C049B8923B61FA6CE669622E60F29FB6"
        "7903FE1008B8BC99A41AE9E95628BC64"
        "F2F1B20C2D7E9F5177A3C294D4462299"
    )
    var expected = hex_bytes(
        "EFD48B2AACB6A8FD1140DD9CD45E81D6"
        "9D2C877B56AAF991C34D0EA84EAF3716"
        "F7CB1C942D657C41D436C7A1B6E29F65"
        "F3E900DBB9AFF4064DC4AB2F843ACDA8"
    )
    var message = hex_bytes("73616D706C65")
    var signature = List[UInt8](unsafe_uninit_length=64)
    if not p256_ecdsa_sign(
        Span[UInt8, ...](private_key),
        Span[UInt8, ...](message),
        Span[mut=True, UInt8, ...](signature),
    ):
        raise Error("P-256 signing failed")
    if not equal(signature, expected):
        raise Error("P-256 RFC 6979 vector mismatch")
    if not p256_ecdsa_verify(
        Span[UInt8, ...](public_key),
        Span[UInt8, ...](message),
        Span[UInt8, ...](signature),
    ):
        raise Error("P-256 verification failed")
    signature[0] ^= 1
    if p256_ecdsa_verify(
        Span[UInt8, ...](public_key),
        Span[UInt8, ...](message),
        Span[UInt8, ...](signature),
    ):
        raise Error("P-256 accepted a changed signature")
    var der = p256_ecdsa_sign_der(
        Span[UInt8, ...](private_key), Span[UInt8, ...](message)
    )
    if not p256_ecdsa_verify_der(
        Span[UInt8, ...](public_key),
        Span[UInt8, ...](message),
        Span[UInt8, ...](der),
    ):
        raise Error("P-256 DER signature failed")


def test_p384() raises:
    var private_key = hex_bytes(
        "6B9D3DAD2E1B8C1C05B19875B6659F4D"
        "E23C3B667BF297BA9AA47740787137D8"
        "96D5724E4C70A825F872C9EA60D2EDF5"
    )
    var public_key = hex_bytes(
        "04EC3A4E415B4E19A4568618029F427FA5"
        "DA9A8BC4AE92E02E06AAE5286B300C64"
        "DEF8F0EA9055866064A254515480BC13"
        "8015D9B72D7D57244EA8EF9AC0C62189"
        "6708A59367F9DFB9F54CA84B3F1C9DB1"
        "288B231C3AE0D4FE7344FD2533264720"
    )
    var expected = hex_bytes(
        "94EDBB92A5ECB8AAD4736E56C691916B"
        "3F88140666CE9FA73D64C4EA95AD133C"
        "81A648152E44ACF96E36DD1E80FABE46"
        "99EF4AEB15F178CEA1FE40DB2603138F"
        "130E740A19624526203B6351D0A3A94F"
        "A329C145786E679E7B82C71A38628AC8"
    )
    var message = hex_bytes("73616D706C65")
    var signature = List[UInt8](unsafe_uninit_length=96)
    if not p384_ecdsa_sign(
        Span[UInt8, ...](private_key),
        Span[UInt8, ...](message),
        Span[mut=True, UInt8, ...](signature),
    ):
        raise Error("P-384 signing failed")
    if not equal(signature, expected):
        raise Error("P-384 RFC 6979 vector mismatch")
    if not p384_ecdsa_verify(
        Span[UInt8, ...](public_key),
        Span[UInt8, ...](message),
        Span[UInt8, ...](signature),
    ):
        raise Error("P-384 verification failed")
    signature[0] ^= 1
    if p384_ecdsa_verify(
        Span[UInt8, ...](public_key),
        Span[UInt8, ...](message),
        Span[UInt8, ...](signature),
    ):
        raise Error("P-384 accepted a changed signature")
    var der = p384_ecdsa_sign_der(
        Span[UInt8, ...](private_key), Span[UInt8, ...](message)
    )
    if not p384_ecdsa_verify_der(
        Span[UInt8, ...](public_key),
        Span[UInt8, ...](message),
        Span[UInt8, ...](der),
    ):
        raise Error("P-384 DER signature failed")


def test_keygen() raises:
    var p256_pair = p256_keygen()
    var p256_private = p256_pair[0].copy()
    var p256_public = p256_pair[1].copy()
    var p256_check = List[UInt8](unsafe_uninit_length=65)
    if not p256_public_key(
        Span[UInt8, ...](p256_private),
        Span[mut=True, UInt8, ...](p256_check),
    ) or not equal(p256_public, p256_check):
        raise Error("P-256 key generation failed")

    var p384_pair = p384_keygen()
    var p384_private = p384_pair[0].copy()
    var p384_public = p384_pair[1].copy()
    var p384_check = List[UInt8](unsafe_uninit_length=97)
    if not p384_public_key(
        Span[UInt8, ...](p384_private),
        Span[mut=True, UInt8, ...](p384_check),
    ) or not equal(p384_public, p384_check):
        raise Error("P-384 key generation failed")

    var x_pair = x25519_keygen()
    var x_private = x_pair[0].copy()
    var x_public = x_pair[1].copy()
    var x_check = List[UInt8](unsafe_uninit_length=32)
    x25519_public_key(
        Span[UInt8, ...](x_private), Span[mut=True, UInt8, ...](x_check)
    )
    if not equal(x_public, x_check):
        raise Error("X25519 key generation failed")


def test_rsa_pss_signing() raises:
    var n = hex_bytes(
        "00c0704ded9d79d29aca25c59bb4711b75a4776fe463b527d2b3eea57198a692081a2645dac540597852a70a22327f38d2068378e37f8d074246eb1879a3a34c530bfa91f629f91c8f9089f489332a6febaa83014cea0e2f7511e8338fe265e8296b7f934529244820f21a7c38de946b182a023ef85c306d1e14ddbfeed54b6daaf5e5c31d02d627e4d068c133511cef3d44bf7a0941b80621193250c8d8fb1893550b3ce828d220a64c9086f01f50c3dc3d1a8081ba185f4798e6bc4a1b913ecfaaf6b45b109a94c765fdb6f662847c1bd48ff83b6f7882ed75f3fb54a176e39ca7856de1e9fd09dd90fcb133ad19b6851e05d8d39b695731fdd3da6a5539e44f"
    )
    var e = hex_bytes("010001")
    var d = hex_bytes(
        "0270aa1c4c35e23cc2396e63060bb51c6dc471efc46fe49c6059b351586d2c46dc060636baef90f2dca16f987569758ffc33289241e8c8e1c7426de204f82a1c97774ae88329bc79f98c3644931883a8ca55b4eb83c0404bccb954060c09dcc2c1b1316ddc12b0b3723e71bacadfb8e7ea8872c1f5714bc0e8e4d2ed35592a7fcdcb88d3811257ee5fce82d85691b2981193479c475ef5708ba353934063a32b0323db2376ae0d5a148df1e7e1ec85bc35b3c23e3a9764119aafe981c93a22a002e187536e00d49b2b8ed8b4e5fd5d8290fdefce5c28503697d2666a96b3b500d45fb9dc0b189eba23f384eeae86ed3ef13040b35bd1cdaa22fb8ea175efe981"
    )
    var msg = hex_bytes("74686973746c65")
    var salt = List[UInt8](length=32, fill=0xA5)
    var sig = rsa_pss_sign_with_salt(
        Span[UInt8, ...](n),
        Span[UInt8, ...](e),
        Span[UInt8, ...](d),
        Span[UInt8, ...](msg),
        Span[UInt8, ...](salt),
        SHA256,
        SHA256,
    )
    if not rsa_pss_verify(
        Span[UInt8, ...](n),
        Span[UInt8, ...](e),
        Span[UInt8, ...](msg),
        Span[UInt8, ...](sig),
        SHA256,
        SHA256,
        32,
    ):
        raise Error("verify")
    var p = hex_bytes(
        "00f66e24d722fc16717d7d080c045c7d20c93ecf25c122a4117b04d0c98e57ab797de6bdcf803af3a18081f1b807ef78dd7030b70eff4d3b449569b70cc52ea74ef487dee8f4333ee6f4450ba47dbb33a676c0a1676b3d3f562d68697d88a6a0a135d2b46749541078df0b61e22d91d1d91bb32145e77cdadec3ca5a69cf6cdac1"
    )
    var q = hex_bytes(
        "00c7e968f759955e8d9709b66d69151cd994a80ad50771170be5b00d87287a483dc9efbb60cd1751f208bccdf4ad970037f720a38f6e33fc94cd6b17d0fb390c857c59d260c20fa86ff3691b8883aa52a545028a2ee7fd898ccc65e9a43aead8890966de847fcd126b9251273552ac9f65f1ef8e15b4cc4c492b582cd1d48cd30f"
    )
    var dp = hex_bytes(
        "6c97fd041116a58d3d8f6b8c601fa1c460ea9cbe366ddd7f1686f8bad94f28f150d9edab1306e775b3fb8f5959a5ddcd373340780b692d44fbd2aa27a67cf89d82849d666ab66a71bc12f11e7b899329380b8b14d7dd159c14467eb62311ca973ff0aa2f19d141b1021931f949bb888df3f6ec22b1f00343476454936c24bc01"
    )
    var dq = hex_bytes(
        "2e662b59b5ae288afe725fa8174ab22e82055ab6450ae789785f1b54b27d674508189f4a01701731f0fb39663fe01b49e20eee477d118ddf4faa3a95e3a94311bc61f0a54a856dd7c60c303ac82c811020eb4cfd44152196cf5e1c1365255aeabb86e7c0a3150ae072ce6926443112b20bac49331a8a8c6e33243d0adaa570db"
    )
    var qi = hex_bytes(
        "1ef4768bcc0e93c2ab12829f41e55b2362f6a374b497cb56e3ff5a3b83f1bff4a1a7711b15e6e007449a339773c08a9745c818219f018d9732fb2e8beb7ce90ad86514f90bcc879d6b4285ed4c65ad27c62232e3fd9a695804e0adf03b069ce3cc7751808197a97690160e39c022eaa51f5902323ec2297b3baa8a36736c1ca5"
    )
    var crt = RsaCrtPrivateKey(
        Span[UInt8, ...](n),
        Span[UInt8, ...](e),
        Span[UInt8, ...](p),
        Span[UInt8, ...](q),
        Span[UInt8, ...](dp),
        Span[UInt8, ...](dq),
        Span[UInt8, ...](qi),
    )
    var sig2 = List[UInt8](unsafe_uninit_length=256)
    if not crt.pss_sign_with_salt(
        Span[UInt8, ...](msg),
        Span[UInt8, ...](salt),
        SHA256,
        SHA256,
        sig2.unsafe_ptr(),
    ):
        raise Error("crt sign")
    if not rsa_pss_verify(
        Span[UInt8, ...](n),
        Span[UInt8, ...](e),
        Span[UInt8, ...](msg),
        Span[UInt8, ...](sig2),
        SHA256,
        SHA256,
        32,
    ):
        raise Error("crt verify")
    if not equal(sig, sig2):
        raise Error("CRT result mismatch")
    var full_key = RsaPrivateKey(
        Span[UInt8, ...](n),
        Span[UInt8, ...](e),
        Span[UInt8, ...](d),
    )
    var oversized_salt_rejected = False
    try:
        _ = full_key.pss_sign(
            Span[UInt8, ...](msg),
            SHA256,
            SHA256,
            1_000_000_000,
        )
    except:
        oversized_salt_rejected = True
    if not oversized_salt_rejected:
        raise Error("RSA-PSS accepted an oversized salt")
    var bad_private_exponent = n.copy()
    var invalid_private_rejected = False
    try:
        _ = RsaPrivateKey(
            Span[UInt8, ...](n),
            Span[UInt8, ...](e),
            Span[UInt8, ...](bad_private_exponent),
        )
    except:
        invalid_private_rejected = True
    if not invalid_private_rejected:
        raise Error("RSA accepted a private exponent equal to its modulus")
    sig2[0] ^= 1
    if rsa_pss_verify(
        Span[UInt8, ...](n),
        Span[UInt8, ...](e),
        Span[UInt8, ...](msg),
        Span[UInt8, ...](sig2),
        SHA256,
        SHA256,
        32,
    ):
        raise Error("changed signature accepted")
    print("RSA-PSS signing tests passed")

def run_ecdsa_file(
    json: PythonObject,
    builtins: PythonObject,
    path: String,
    curve_size: Int,
) raises -> Bool:
    var file = builtins.open(path, "r")
    var root = json.load(file)
    file.close()
    var passed = 0
    var failed = 0
    for group in root["testGroups"]:
        var public_key = hex_bytes(String(group["publicKey"]["uncompressed"]))
        for test in group["tests"]:
            var message = hex_bytes(String(test["msg"]))
            var signature = hex_bytes(String(test["sig"]))
            var valid: Bool
            if curve_size == 32:
                valid = p256_ecdsa_verify_der(
                    Span[UInt8, ...](public_key),
                    Span[UInt8, ...](message),
                    Span[UInt8, ...](signature),
                )
            else:
                valid = p384_ecdsa_verify_der(
                    Span[UInt8, ...](public_key),
                    Span[UInt8, ...](message),
                    Span[UInt8, ...](signature),
                )
            var result = String(test["result"])
            if (
                (result == "valid" and valid)
                or (result == "invalid" and not valid)
                or result == "acceptable"
            ):
                passed += 1
            else:
                failed += 1
                print(path, String(test["tcId"]), result, valid)
    print(path, passed, "passed,", failed, "failed")
    return failed == 0


def test_ecdsa_wycheproof() raises:
    var json = Python.import_module("json")
    var builtins = Python.import_module("builtins")
    var ok = run_ecdsa_file(
        json,
        builtins,
        "tests/Wycheproof/ecdsa_secp256r1_sha256_test.json",
        32,
    )
    ok = (
        run_ecdsa_file(
            json,
            builtins,
            "tests/Wycheproof/ecdsa_secp384r1_sha384_test.json",
            48,
        )
        and ok
    )
    if not ok:
        raise Error("Wycheproof ECDSA failures")

def test_rsa_pkcs1_wycheproof() raises:
    var json = Python.import_module("json")
    var builtins = Python.import_module("builtins")
    var file = builtins.open(
        "tests/Wycheproof/rsa_signature_2048_sha256_test.json", "r"
    )
    var root = json.load(file)
    file.close()
    var passed = 0
    var failed = 0
    for group in root["testGroups"]:
        var modulus = hex_bytes(String(group["publicKey"]["modulus"]))
        var exponent = hex_bytes(String(group["publicKey"]["publicExponent"]))
        for test in group["tests"]:
            var message = hex_bytes(String(test["msg"]))
            var signature = hex_bytes(String(test["sig"]))
            var valid = rsa_pkcs1_v15_sha256_verify(
                Span[UInt8, ...](modulus),
                Span[UInt8, ...](exponent),
                Span[UInt8, ...](message),
                Span[UInt8, ...](signature),
            )
            var result = String(test["result"])
            if (
                (result == "valid" and valid)
                or (result == "invalid" and not valid)
                or result == "acceptable"
            ):
                passed += 1
            else:
                failed += 1
                print("failed", String(test["tcId"]), result, valid)
    print("Wycheproof RSA PKCS#1 v1.5:", passed, "passed,", failed, "failed")
    if failed != 0:
        raise Error("Wycheproof RSA PKCS#1 v1.5 failures")

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


def run_pss_file(py: PythonObject, builtins: PythonObject, path: String) raises -> Bool:
    var fh = builtins.open(path, "r", encoding="utf-8")
    var root = py.load(fh)
    fh.close()

    var ok_count = 0
    var fail_count = 0
    for g in root["testGroups"]:
        var sha = sha_id(String(g["sha"]))
        var mgf_sha = sha_id(String(g["mgfSha"]))
        var s_len = Int(py=g["sLen"])
        var n = hex_bytes(String(g["publicKey"]["modulus"]))
        var e = hex_bytes(String(g["publicKey"]["publicExponent"]))
        for t in g["tests"]:
            var msg = hex_bytes(String(t["msg"]))
            var sig = hex_bytes(String(t["sig"]))
            var result = String(t["result"])
            var got: Bool
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
    print(path, ": ", ok_count, " ok, ", fail_count, " fail ")
    return fail_count == 0


def test_rsa_pss_wycheproof() raises:
    print("Wycheproof RSASSA-PSS")
    var py = Python.import_module("json")
    var builtins = Python.import_module("builtins")

    var all_ok = True
    all_ok = run_pss_file(py, builtins, "tests/Wycheproof/rsa_pss_2048_sha256_mgf1_32_test.json") and all_ok
    all_ok = run_pss_file(py, builtins, "tests/Wycheproof/rsa_pss_3072_sha256_mgf1_32_test.json") and all_ok
    all_ok = run_pss_file(py, builtins, "tests/Wycheproof/rsa_pss_4096_sha512_mgf1_64_test.json") and all_ok
    all_ok = run_pss_file(py, builtins, "tests/Wycheproof/rsa_pss_misc_test.json") and all_ok
    all_ok = run_pss_file(py, builtins, "tests/Wycheproof/rsa_pss_misc_params_test.json") and all_ok
    if not all_ok:
        raise Error("Wycheproof RSA-PSS failures")

def main() raises:
    test_hmac_sha384()
    test_p256()
    test_p384()
    test_keygen()
    test_rsa_pss_signing()
    test_ecdsa_wycheproof()
    test_rsa_pkcs1_wycheproof()
    test_rsa_pss_wycheproof()
    print("All signing tests passed")
