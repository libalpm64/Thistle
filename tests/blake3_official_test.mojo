from collections import List
from thistle.blake3 import blake3_parallel_hash


fn char_to_int(c: UInt8) -> Int:
    if c >= 48 and c <= 57:  # '0'-'9'
        return Int(c) - 48
    if c >= 97 and c <= 102:  # 'a'-'f'
        return Int(c) - 97 + 10
    if c >= 65 and c <= 70:  # 'A'-'F'
        return Int(c) - 65 + 10
    return 0


fn hex_to_bytes(hex_str: String) -> List[UInt8]:
    var out = List[UInt8](capacity=len(hex_str) // 2)
    var p = hex_str.unsafe_ptr()
    for i in range(0, len(hex_str), 2):
        var h = char_to_int(p[i])
        var l = char_to_int(p[i + 1])
        out.append(UInt8(h * 16 + l))
    return out^


fn generate_test_data(length: Int) -> List[UInt8]:
    var data = List[UInt8](capacity=length)
    for i in range(length):
        data.append(UInt8(i % 251))
    return data^


@fieldwise_init
struct TestCase(Copyable, Movable):
    var input_len: Int
    var hash: String


fn run_test(tc: TestCase) raises -> Bool:
    var data = generate_test_data(tc.input_len)
    var expected = hex_to_bytes(tc.hash)
    var out_len = len(expected)

    var result = blake3_parallel_hash(Span[UInt8](data), out_len)

    if len(result) != out_len:
        print(
            "failed Test",
            tc.input_len,
            "bytes: Length mismatch (got",
            len(result),
            "expected",
            out_len,
            ")",
        )
        return False

    var is_match = True
    var first_fail = -1
    for i in range(out_len):
        if result[i] != expected[i]:
            is_match = False
            first_fail = i
            break

    if not is_match:
        print(
            "Test", tc.input_len, "bytes: Hash mismatch at index", first_fail
        )
        print(
            "  Expected (snippet): ",
            tc.hash[first_fail * 2 : min(len(tc.hash), first_fail * 2 + 16)],
        )
        print(
            "  Got byte:",
            hex(Int(result[first_fail])),
            " Expected byte:",
            hex(Int(expected[first_fail])),
        )
        return False

    print("Test", tc.input_len, "bytes: PASSED")
    return True


fn main() raises:
    print("BLAKE3 Official Test Vectors (Extended Output Validation)")

    var cases = List[TestCase]()
    cases.append(
        TestCase(
            input_len=0,
            hash="af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a26f5487789e8f660afe6c99ef9e0c52b92e7393024a80459cf91f476f9ffdbda7001c22e159b402631f277ca96f2defdf1078282314e763699a31c5363165421cce14d",
        )
    )
    cases.append(
        TestCase(
            input_len=1,
            hash="2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213c3a6cb8bf623e20cdb535f8d1a5ffb86342d9c0b64aca3bce1d31f60adfa137b358ad4d79f97b47c3d5e79f179df87a3b9776ef8325f8329886ba42f07fb138bb502f4081cbcec3195c5871e6c23e2cc97d3c69a613eba131e5f1351f3f1da786545e5",
        )
    )
    cases.append(
        TestCase(
            input_len=64,
            hash="4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98fc9cc56cb831ffe33ea8e7e1d1df09b26efd2767670066aa82d023b1dfe8ab1b2b7fbb5b97592d46ffe3e05a6a9b592e2949c74160e4674301bc3f97e04903f8c6cf95b863174c33228924cdef7ae47559b10b294acd660666c4538833582b43f82d74",
        )
    )
    cases.append(
        TestCase(
            input_len=1024,
            hash="42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af71cf8107265ecdaf8505b95d8fcec83a98a6a96ea5109d2c179c47a387ffbb404756f6eeae7883b446b70ebb144527c2075ab8ab204c0086bb22b7c93d465efc57f8d917f0b385c6df265e77003b85102967486ed57db5c5ca170ba441427ed9afa684e",
        )
    )
    cases.append(
        TestCase(
            input_len=1025,
            hash="d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444f4c4a22b4b399155358a994e52bf255de60035742ec71bd08ac275a1b51cc6bfe332b0ef84b409108cda080e6269ed4b3e2c3f7d722aa4cdc98d16deb554e5627be8f955c98e1d5f9565a9194cad0c4285f93700062d9595adb992ae68ff12800ab67a",
        )
    )
    cases.append(
        TestCase(
            input_len=2048,
            hash="e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a9a60bf80001410ec9eea6698cd537939fad4749edd484cb541aced55cd9bf54764d063f23f6f1e32e12958ba5cfeb1bf618ad094266d4fc3c968c2088f677454c288c67ba0dba337b9d91c7e1ba586dc9a5bc2d5e90c14f53a8863ac75655461cea8f9",
        )
    )
    cases.append(
        TestCase(
            input_len=102400,
            hash="bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085e01c59dab908c04c3342b816941a26d69c2605ebee5ec5291cc55e15b76146e6745f0601156c3596cb75065a9c57f35585a52e1ac70f69131c23d611ce11ee4ab1ec2c009012d236648e77be9295dd0426f29b764d65de58eb7d01dd42248204f45f8e",
        )
    )

    var passed = 0
    for i in range(len(cases)):
        if run_test(cases[i]):
            passed += 1


    print("Passed", passed, "/", len(cases), "selected official vectors")
    if passed == len(cases):
        print(
            "BLAKE3 validated against 131-byte official inputs"
        )
    else:
        print("Validation failed")

    if passed != len(cases):
        raise Error("Test failure")
