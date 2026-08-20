"""
This test file is for testing the Wycheproof P-256 ECDH test vectors.
"""
from std.collections import List
from std.python import Python
from thistle.p256 import p256_ecdh
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

def extract_p256_public_key(public_der: List[UInt8]) -> List[UInt8]:
    # RFC 5480 section 2.1 identifies EC public keys with id-ecPublicKey plus
    # a namedCurve OID. SEC 2 v2.0 appendix A assigns secp256r1:
    # 1.2.840.10045.3.1.7, DER-encoded as 06 08 2A 86 48 CE 3D 03 01 07.
    #
    # RFC 5480 section 2.2 stores the SEC 1 ECPoint in subjectPublicKey as a
    # BIT STRING. Wycheproof includes malformed-but-acceptable ASN.1 wrappers;
    # this test harness deliberately extracts only the final SEC 1 point when
    # the P-256 OID is present. The production p256_ecdh API receives raw SEC 1
    # point bytes and does not parse ASN.1.
    var has_p256_oid = False
    for i in range(len(public_der) - 9):
        if (
            public_der[i] == 0x06
            and public_der[i + 1] == 0x08
            and public_der[i + 2] == 0x2A
            and public_der[i + 3] == 0x86
            and public_der[i + 4] == 0x48
            and public_der[i + 5] == 0xCE
            and public_der[i + 6] == 0x3D
            and public_der[i + 7] == 0x03
            and public_der[i + 8] == 0x01
            and public_der[i + 9] == 0x07
        ):
            has_p256_oid = True
    if not has_p256_oid:
        return List[UInt8]()
    if len(public_der) >= 65 and public_der[len(public_der) - 65] == 0x04:
        var out = List[UInt8](capacity=65)
        for j in range(65):
            out.append(public_der[len(public_der) - 65 + j])
        return out^
    if len(public_der) >= 33 and (
        public_der[len(public_der) - 33] == 0x02
        or public_der[len(public_der) - 33] == 0x03
    ):
        var out = List[UInt8](capacity=33)
        for j in range(33):
            out.append(public_der[len(public_der) - 33 + j])
        return out^
    return List[UInt8]()


def extract_trailing_sec1_p256_public_key(
    public_der: List[UInt8],
) -> List[UInt8]:
    if len(public_der) >= 65 and public_der[len(public_der) - 65] == 0x04:
        var out = List[UInt8](capacity=65)
        for j in range(65):
            out.append(public_der[len(public_der) - 65 + j])
        return out^
    if len(public_der) >= 33 and (
        public_der[len(public_der) - 33] == 0x02
        or public_der[len(public_der) - 33] == 0x03
    ):
        var out = List[UInt8](capacity=33)
        for j in range(33):
            out.append(public_der[len(public_der) - 33 + j])
        return out^
    return List[UInt8]()


def normalize_p256_private_key(var private_key: List[UInt8]) -> List[UInt8]:
    # DER INTEGER values may include a leading 00 octet to keep the integer
    # positive. SEC 1 scalar input to p256_ecdh is the fixed 32-octet value.
    if len(private_key) == 32:
        return private_key^
    if len(private_key) == 33 and private_key[0] == 0:
        var out = List[UInt8](capacity=32)
        for i in range(32):
            out.append(private_key[i + 1])
        return out^
    if len(private_key) < 32:
        var out = List[UInt8](capacity=32)
        for _ in range(32 - len(private_key)):
            out.append(0)
        for i in range(len(private_key)):
            out.append(private_key[i])
        return out^
    return List[UInt8]()


def matches32(
    actual: StackInlineArray[UInt8, 32], expected: List[UInt8]
) -> Bool:
    for i in range(32):
        if actual[i] != expected[i]:
            return False
    return True


def run_case(
    tc_id: String,
    private_hex: String,
    public_hex: String,
    shared_hex: String,
    result: String,
) -> Bool:
    var is_valid = result == "valid"
    var is_acceptable = result == "acceptable"
    var private_key = normalize_p256_private_key(hex_to_bytes(private_hex))
    var public_der = hex_to_bytes(public_hex)
    var public_key = extract_p256_public_key(public_der)
    if (is_valid or is_acceptable) and len(public_key) == 0:
        # Several Wycheproof "acceptable" cases intentionally corrupt the
        # ASN.1 wrapper but leave a recoverable SEC 1 point. This fallback is
        # test-harness-only; the p256_ecdh API accepts raw SEC 1.
        public_key = extract_trailing_sec1_p256_public_key(public_der)
    var expected = hex_to_bytes(shared_hex)
    var actual = StackInlineArray[UInt8, 32](uninitialized=True)
    var got = p256_ecdh(
        Span[UInt8, ...](private_key),
        Span[UInt8, ...](public_key),
        Span[mut=True, UInt8, ...](unsafe_ptr=actual.unsafe_ptr(), length=32),
    )
    if is_valid and not got:
        print(
            "Test ",
            tc_id,
            " validity mismatch: valid vector was rejected",
        )
        return False
    if (not is_valid and not is_acceptable) and got:
        print("Test ", tc_id, " validity mismatch: invalid vector was accepted")
        return False
    if got and not matches32(actual, expected):
        print("Test ", tc_id, " shared secret mismatch")
        return False
    return True

def main() raises:
    print("Wycheproof P-256 ECDH")
    var py = Python.import_module("json")
    var builtins = Python.import_module("builtins")

    var fh = builtins.open("tests/Wycheproof/ecdh_secp256r1_test.json", "r", encoding="utf-8")
    var root = py.load(fh)
    fh.close()

    var ok_count = 0
    var fail_count = 0
    for g in root["testGroups"]:
        for t in g["tests"]:
            var tc_id = String(t["tcId"])
            var result = String(t["result"])
            if run_case(
                tc_id,
                String(t["private"]),
                String(t["public"]),
                String(t["shared"]),
                result,
            ):
                ok_count += 1
            else:
                fail_count += 1

    print(
        "Wycheproof P-256 ECDH: ", ok_count, " passed, ", fail_count, " failed"
    )
    if fail_count > 0:
        raise Error("Wycheproof P-256 ECDH failed")
