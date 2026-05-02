
from std.collections import List
from thistle.ed25519 import ed25519_verify

fn hex_to_bytes(s: String) -> List[UInt8]:
    var r = List[UInt8]()
    var b = s.as_bytes()
    for i in range(0, len(s), 2):
        var hi = UInt8((b[i] - 48) - (39 if b[i] > 96 else (7 if b[i] > 64 else 0)))
        var lo = UInt8((b[i+1] - 48) - (39 if b[i+1] > 96 else (7 if b[i+1] > 64 else 0)))
        r.append((hi << 4) | lo)
    return r^

fn main() raises:
    var ok_count = 0
    var fail_count = 0

    # Test 1
    if ed25519_verify(
        Span[UInt8, ...](hex_to_bytes("7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa")),
        Span[UInt8, ...](hex_to_bytes("")),
        Span[UInt8, ...](hex_to_bytes("d4fbdb52bfa726b44d1786a8c0d171c3e62ca83c9e5bbe63de0bb2483f8fd6cc1429ab72cafc41ab56af02ff8fcc43b99bfe4c7ae940f60f38ebaa9d311c4007"))
    ):
        ok_count += 1
    else:
        print("Test 1 FAILED")
        fail_count += 1

    # Test 2
    if ed25519_verify(
        Span[UInt8, ...](hex_to_bytes("7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa")),
        Span[UInt8, ...](hex_to_bytes("78")),
        Span[UInt8, ...](hex_to_bytes("d80737358ede548acb173ef7e0399f83392fe8125b2ce877de7975d8b726ef5b1e76632280ee38afad12125ea44b961bf92f1178c9fa819d020869975bcbe109"))
    ):
        ok_count += 1
    else:
        print("Test 2 FAILED")
        fail_count += 1

    # Test 3
    if ed25519_verify(
        Span[UInt8, ...](hex_to_bytes("7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa")),
        Span[UInt8, ...](hex_to_bytes("54657374")),
        Span[UInt8, ...](hex_to_bytes("7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab07a9155711ecfaf7f99f277bad0c6ae7e39d4eef676573336a5c51eb6f946b30d"))
    ):
        ok_count += 1
    else:
        print("Test 3 FAILED")
        fail_count += 1

    # Test 4
    if ed25519_verify(
        Span[UInt8, ...](hex_to_bytes("7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa")),
        Span[UInt8, ...](hex_to_bytes("48656c6c6f")),
        Span[UInt8, ...](hex_to_bytes("1c1ad976cbaae3b31dee07971cf92c928ce2091a85f5899f5e11ecec90fc9f8e93df18c5037ec9b29c07195ad284e63d548cd0a6fe358cc775bd6c1608d2c905"))
    ):
        ok_count += 1
    else:
        print("Test 4 FAILED")
        fail_count += 1

    # Test 5
    if ed25519_verify(
        Span[UInt8, ...](hex_to_bytes("7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa")),
        Span[UInt8, ...](hex_to_bytes("313233343030")),
        Span[UInt8, ...](hex_to_bytes("657c1492402ab5ce03e2c3a7f0384d051b9cf3570f1207fc78c1bcc98c281c2bf0cf5b3a289976458a1be6277a5055545253b45b07dcc1abd96c8b989c00f301"))
    ):
        ok_count += 1
    else:
        print("Test 5 FAILED")
        fail_count += 1

    # Test 6
    if ed25519_verify(
        Span[UInt8, ...](hex_to_bytes("7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa")),
        Span[UInt8, ...](hex_to_bytes("000000000000000000000000")),
        Span[UInt8, ...](hex_to_bytes("d46543bfb892f84ec124dcdfc847034c19363bf3fc2fa89b1267833a14856e52e60736918783f950b6f1dd8d40dc343247cd43ce054c2d68ef974f7ed0f3c60f"))
    ):
        ok_count += 1
    else:
        print("Test 6 FAILED")
        fail_count += 1

    # Test 7
    if ed25519_verify(
        Span[UInt8, ...](hex_to_bytes("7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa")),
        Span[UInt8, ...](hex_to_bytes("6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161")),
        Span[UInt8, ...](hex_to_bytes("879350045543bc14ed2c08939b68c30d22251d83e018cacbaf0c9d7a48db577e80bdf76ce99e5926762bc13b7b3483260a5ef63d07e34b58eb9c14621ac92f00"))
    ):
        ok_count += 1
    else:
        print("Test 7 FAILED")
        fail_count += 1

    # Test 8
    if ed25519_verify(
        Span[UInt8, ...](hex_to_bytes("7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa")),
        Span[UInt8, ...](hex_to_bytes("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60")),
        Span[UInt8, ...](hex_to_bytes("7bdc3f9919a05f1d5db4a3ada896094f6871c1f37afc75db82ec3147d84d6f237b7e5ecc26b59cfea0c7eaf1052dc427b0f724615be9c3d3e01356c65b9b5109"))
    ):
        ok_count += 1
    else:
        print("Test 8 FAILED")
        fail_count += 1

    # Test 9
    if ed25519_verify(
        Span[UInt8, ...](hex_to_bytes("7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa")),
        Span[UInt8, ...](hex_to_bytes("ffffffffffffffffffffffffffffffff")),
        Span[UInt8, ...](hex_to_bytes("5dbd7360e55aa38e855d6ad48c34bd35b7871628508906861a7c4776765ed7d1e13d910faabd689ec8618b78295c8ab8f0e19c8b4b43eb8685778499e943ae04"))
    ):
        ok_count += 1
    else:
        print("Test 9 FAILED")
        fail_count += 1

    # Test 71
    if ed25519_verify(
        Span[UInt8, ...](hex_to_bytes("a12c2beb77265f2aac953b5009349d94155a03ada416aad451319480e983ca4c")),
        Span[UInt8, ...](hex_to_bytes("")),
        Span[UInt8, ...](hex_to_bytes("5056325d2ab440bf30bbf0f7173199aa8b4e6fbc091cf3eb6bc6cf87cd73d992ffc216c85e4ab5b8a0bbc7e9a6e9f8d33b7f6e5ac0ffdc22d9fcaf784af84302"))
    ):
        ok_count += 1
    else:
        print("Test 71 FAILED")
        fail_count += 1

    print("Wycheproof results: ", ok_count, " OK, ", fail_count, " FAIL")
    if fail_count > 0:
        raise Error("Wycheproof tests failed")
