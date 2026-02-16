# Test ChaCha20 against Python-generated test vectors
# Run with: pixi run mojo run -I src tests/test_chacha20_vectors.mojo

from thistle.chacha20 import ChaCha20, chacha20_block
from testing import assert_equal
from collections import List
from memory import bitcast
from memory.unsafe_pointer import UnsafePointer
from builtin.type_aliases import MutExternalOrigin


fn hex_to_bytes(hex_str: String) -> List[UInt8]:
    """Convert hex string to list of bytes."""
    var result = List[UInt8]()
    var i = 0
    var s_bytes = hex_str.as_bytes()
    while i < len(hex_str):
        var high = s_bytes[i]
        var low = s_bytes[i + 1]
        var byte_val = 0
        if high >= 48 and high <= 57:  # '0'-'9'
            byte_val = (Int(high) - 48) << 4
        elif high >= 97 and high <= 102:  # 'a'-'f'
            byte_val = (Int(high) - 97 + 10) << 4
        elif high >= 65 and high <= 70:  # 'A'-'F'
            byte_val = (Int(high) - 65 + 10) << 4

        if low >= 48 and low <= 57:
            byte_val = byte_val + (Int(low) - 48)
        elif low >= 97 and low <= 102:
            byte_val = byte_val + (Int(low) - 97 + 10)
        elif low >= 65 and low <= 70:
            byte_val = byte_val + (Int(low) - 65 + 10)

        result.append(UInt8(byte_val))
        i += 2
    return result^


fn list_to_simd32(lst: List[UInt8]) -> SIMD[DType.uint8, 32]:
    """Convert list to SIMD[uint8, 32]."""
    var result = SIMD[DType.uint8, 32](0)
    for i in range(min(len(lst), 32)):
        result[i] = lst[i]
    return result


fn list_to_simd12(lst: List[UInt8]) -> SIMD[DType.uint8, 12]:
    """Convert list to SIMD[uint8, 12]."""
    var result = SIMD[DType.uint8, 12](0)
    for i in range(min(len(lst), 12)):
        result[i] = lst[i]
    return result


fn test_vector(
    name: String,
    key_hex: String,
    nonce_hex: String,
    counter: UInt32,
    plaintext_hex: String,
    ciphertext_hex: String,
) -> Bool:
    """Test a single ChaCha20 test vector."""
    print("Testing: ", name)

    # Parse hex strings
    var key_bytes = hex_to_bytes(key_hex)
    var nonce_bytes = hex_to_bytes(nonce_hex)
    var plaintext_bytes = hex_to_bytes(plaintext_hex)
    var expected_ciphertext = hex_to_bytes(ciphertext_hex)

    # Convert to SIMD
    var key = list_to_simd32(key_bytes)
    var nonce = list_to_simd12(nonce_bytes)

    # Create cipher
    var cipher = ChaCha20(key, nonce, counter)

    var pt_len = len(plaintext_bytes)

    if pt_len == 0:
        # Empty plaintext
        var null_ptr: UnsafePointer[UInt8, MutExternalOrigin] = {}
        var result_ptr = cipher.encrypt(
            Span[UInt8](ptr=null_ptr, length=0)
        )
        # Result should be null pointer
        var null_check: UnsafePointer[UInt8, MutExternalOrigin] = {}
        if result_ptr != null_check:
            print("  FAIL: Empty plaintext should produce null pointer")
            # result_ptr.free()
            return False

        if len(expected_ciphertext) != 0:
            print("  FAIL: Expected ciphertext mismatch for empty plaintext")
            return False

        print("  PASS")
        return True

    # Create a mutable buffer for plaintext to pass to encrypt
    var ciphertext_ptr = cipher.encrypt(Span(plaintext_bytes))

    # Verify length (implicitly, comparing bytes up to expected length)
    # We assume ciphertext length == plaintext length.
    if pt_len != len(expected_ciphertext):
        print(
            "  FAIL: Length mismatch. Expected ",
            len(expected_ciphertext),
            " got ",
            pt_len,
        )
        ciphertext_ptr.free()
        return False

    # Verify each byte
    var passed = True
    for i in range(pt_len):
        if ciphertext_ptr[i] != expected_ciphertext[i]:
            print(
                "  FAIL: Byte ",
                i,
                " mismatch. Expected ",
                hex(expected_ciphertext[i]),
                " got ",
                hex(ciphertext_ptr[i]),
            )
            passed = False

    ciphertext_ptr.free()

    if passed:
        print("  PASS")
    return passed


def test_rfc_7539_block():
    """Test RFC 7539 block test vector."""
    print("\nBlock Test")

    # Key: 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f
    var key = SIMD[DType.uint8, 32](0)
    for i in range(32):
        key[i] = UInt8(i)

    # Nonce: 00:00:00:09:00:00:00:4a:00:00:00:00
    var nonce = SIMD[DType.uint8, 12](0)
    nonce[3] = 0x09
    nonce[7] = 0x4A

    var counter = UInt32(1)

    var keystream = chacha20_block(key, counter, nonce)

    # Expected first 16 bytes: 10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4
    assert_equal(keystream[0], 0x10)
    assert_equal(keystream[1], 0xF1)
    assert_equal(keystream[2], 0xE7)
    assert_equal(keystream[15], 0xC4)

    print("RFC 7539 block test passed!")


def test_rfc_7539_sunscreen():
    """Test RFC 7539 sunscreen test vector."""
    print("\nSunscreen Test")

    var key = SIMD[DType.uint8, 32](0)
    for i in range(32):
        key[i] = UInt8(i)

    var nonce = SIMD[DType.uint8, 12](0)
    nonce[7] = 0x4A

    var counter = UInt32(1)
    var cipher = ChaCha20(key, nonce, counter)

    var plaintext_str = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    var plaintext = List[UInt8]()
    var plaintext_bytes = plaintext_str.as_bytes()
    for i in range(len(plaintext_bytes)):
        plaintext.append(plaintext_bytes[i])

    var ciphertext_ptr = cipher.encrypt(Span(plaintext))

    # Expected first 16 bytes: 6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81
    assert_equal(ciphertext_ptr[0], 0x6E)
    assert_equal(ciphertext_ptr[1], 0x2E)
    assert_equal(ciphertext_ptr[2], 0x35)
    assert_equal(ciphertext_ptr[15], 0x81)

    if len(plaintext) > 0:
        ciphertext_ptr.free()

    print("RFC 7539 sunscreen test passed!")


def test_random_vectors() -> Bool:
    """Test against Python-generated random test vectors."""
    print("\nRandom Test Vectors")

    var all_passed = True
    var test_count = 0

    # random_test_1
    test_count += 1
    if not test_vector(
        "random_test_1",
        "390c8c7d7247342cd8100f2f6f770d65d670e58e0351d8ae8e4f6eac342fc231",
        "b7b08716eb3fc12896b96223",
        433797840,
        "e8ba53bdb56b8824577d53ecc28a70a61c7510a1cd89216ca16cffcaea4987477e86dbccb97046fc2e18384e51d820c5c3ef80053a88ae3996de50e801865b3698",
        "dbf3a8f80f83b070a6aa601d2404aed68c68252fdd84bb9fb99aa8e5d3443662a7fa5d2f49648cd24332b74c9f6151e2cb15eb9cfc6b1eef9a10d3e7bde524af76",
    ):
        all_passed = False

    # random_test_2
    test_count += 1
    if not test_vector(
        "random_test_2",
        "654ebf5200a5fa0939b99d7a1d7b282bf8234041f35487d86c669fccbfe0e73d",
        "7e7320ad0a757003241e7522",
        3888749350,
        "24798ef86d43f27cf2d0613031dcb5d8d2ef1b321fcead377f6261e547d85d8eec7f26e23219072f7955d0f8f66dcd1e54c201c787e892d8f94f61976f1d1fa01d19f4501d295f232278ce3d7e1429d6a18568a07a87ca4399eaa12504ea33256d8743b2237dbd9150e09a04993544873b364f8b906baf6887fa801a2fd88d16",
        "b884ebe8a70ce6978fb2a7b9733d5f6f5d36993490bcbff7def205ae70f79b235ec5d7a09608cc867893ed31fe482a56c43508dbb495f108decb633fe09308e6131473686a689a2be23d5d650c2a4044d3e6324d62de60b1f9e0eb76407bb1aa68b34377c47f4ade6a759b579f6756f36ea125088898e835acbb280dca173e91",
    ):
        all_passed = False

    # random_test_3
    test_count += 1
    if not test_vector(
        "random_test_3",
        "01aa428652e2da0439264c12bd4bdc41159dba14b76b7f34b5d04f79535ad30c",
        "5baad27f885137c313f07166",
        1976987348,
        "74720c62cca88e238eb3cca90e3b855b871337deb0a0df3bc5618216df0064badc23a9a03f999ed1a7ce974162d7c2599acf009b926bdca4eee2e26df2562b91ab2f789e73654b0c177df325e9d463c4fdcc7c4b0236d9705aed197f3ee944eda2e2dae451f3e6847e8df87a8ce12792788baba329464d76c44e6d20d4d0a9",
        "aabe7c9d9b7f6a884860b709d564aca5025dfc31adf1c67ff60aea21bdfd72b1668a36da44cdc223f402359f8c45e60c9211b5bdf77652e9ed64a14879e66994767d51528ff3ac2a6d36f3b482c14feb11835cbb2f8be919366b091de2cde5933a084c3cf35cef4973f0bf7ea14cc32cfe97a7a786e76beac78cc69bdde777",
    ):
        all_passed = False

    # random_test_4 (short)
    test_count += 1
    if not test_vector(
        "random_test_4_short",
        "eed41f69d7c70ac2f403b498c7d670f9708bdff80ec7accf54ef410dc90d2adb",
        "45ec5d1985c2a76ce8a7acc2",
        1810607153,
        "f0091ab3722314",
        "46479aa97abfaa",
    ):
        all_passed = False

    # random_test_5 (long)
    test_count += 1
    if not test_vector(
        "random_test_5_long",
        "0f7e660a4e7a40f23a6fee83bc553a539f370d9fc0cb65267c349a3d15b1dbbd",
        "23ae06d7fa36ddb9eb4ede5a",
        2076605983,
        "89a57d2c8ee67cedc2ac0efda65df96cb584ae8f8d05612b7bd0fa7bf3fbe5082f9671cf7c9cbcf2b0d9a9b4e88a9c80763d62a13d5e626ef78d9033639774b85b9a07408c171b9540fb340691f0f5e1ae5e1a81f43a21cdfb251b4d4c9b2b7f3cd573c2e6e298db9c1e326a6c8729507a58265001d1e6f09510769390e824778765d93a734c8848241e549d93e03fef9bce8bfce02914dda5800d2e750a891459f0e28e5cdffb2ef0b2d1aaa43552a8d2fd93cd12e82da181a53bce00ecd31b60b9ffe21a68884393e0f83e0e7a519f07d02f733aec3c4eff958bd4f7f17ce94ac46145238dd4ae88019098fa4ce4f7b0aac1e9a4607ac477d216a2f2c3c54d",
        "5eaa95845f5bc303521df4670463f91df0be7e88f9d831b5e63d4d13bfa6062c47cb006d55e4e5c4ccb4a66a3cd658b8e9b3cf796460f14389d8014c0eba0530c36adc28b029b3b889e35a59a8b32473b7796a8961ed170fabe1df9025e3c25dfa4c550c2993535dd5a159f022996593c3c1c1fdf626de5a62aecda3d5bf982c053deb408fc5bce601846ba6ce711a388fccaa377853f730a12739aa7560401d6ee7ada7a73b90691e2309fb58d4e2da5dc07313d1a2e8d5cf9bebe9cd7cc5d0a292a0b06964a73791027bfdcec99ac79694a3581f7bb813be4ec7035b79beed958e00ab1dee6f11aa38d5dd5043efce7fb5453a48e5faa0056a8656884500c9",
    ):
        all_passed = False

    # random_test_6
    test_count += 1
    if not test_vector(
        "random_test_6",
        "fd1240a933e133e90749d14f26f087adcb29a8c2a2f912237893742ede3233e3",
        "55990e17a61c96b7bfdc4a7d",
        2281341978,
        "575928c37bfe4976ec82eb8204ee935025",
        "58d1975f1564c4b1326a89c5bb2affbee0",
    ):
        all_passed = False

    # random_test_7
    test_count += 1
    if not test_vector(
        "random_test_7",
        "e2b099d980e99a65c4f73679c3b797970bca8c0419fe9275b47061804631149e",
        "e111ba432e97a7d4596643bb",
        3923396682,
        "83f697ad3aef264873cbbb2eca07873fe8",
        "4077a692d89ee0f16d64d1bb69b3138aea",
    ):
        all_passed = False

    # random_test_8
    test_count += 1
    if not test_vector(
        "random_test_8",
        "bc86c3be3777f10ca77120ed9ad13b4717139bfc3b317845c6e8bdd64fd432fa",
        "d08f10bd6fe3e378b932bcb7",
        260060661,
        "613ee82e6c0a19aa7c4069236a6e77a84b018d4a428059380d4307b779a50859871a40d73a20f3e5b937e771169aea0f1ff5cdda37fbe32529a44b21408ca6c396",
        "7d1354a55b78730947dd20226a62a232f6c74be46a165bc4082a49fc24a8d88b9b01e7d988941fa146f9ea457818fd6d76e13da525b29e53ab2af31011845e092b",
    ):
        all_passed = False

    # random_test_9
    test_count += 1
    if not test_vector(
        "random_test_9",
        "e8dc323a6edce774d3ade8ccd430a0daa082bf4ef2222e2b2fdd31be421ea83e",
        "d2b5d81a939fb4356c4ff672",
        3639017775,
        "bc3a8e73db0d880e5c8b9eadb3035c49cd23480f2e6ec0d6e8ae50bd9fa62b1a4f5019298be2d9f8e2d48b6e3ab0dc3891f99d1770ca1c03689a6c468294a73d03fedc5942c275b524cb15df09eb27a0dbcfd5943acf0aa657ebb92ddf367cdfcd28ca9ead71aa56273a63b2b34b78344a8365584e265afcede5a5a14de122f0e2",
        "9119db8d392eb86a446553afe31f66918f60790a9c78498e60993f55487d8f7f76be1201fee0a1458ecdf2b27d8087316ec0861eb28ace4d43b7275ba7218811b01dd80ab7309f1913c2126bf1163981871887e544486ed94fab3fc475810d6031ea8aef7e9431e0763d78c92042fac9177673784f1a9f83065b25e148394857b5",
    ):
        all_passed = False

    # random_test_10
    test_count += 1
    if not test_vector(
        "random_test_10",
        "9b8c1cb4259eece7131dbc92272ec4ec15e660a4f34d1fe634af2b58147ee0e0",
        "51babe90c6d1ad1aab21a830",
        1660280619,
        "4caa2948b39ec8422b9ec0a8412fd8b909b99e5c6daef86273464f27973313ac43c04e535c54e016d2ba79e391e5777a9ef063bce1ec90c3d6526646801af6be34",
        "a5fa24056bec54f3f34ef2b5599b80528e97eda1103e4d7cba07c36b9fdae98ef2062b81d9e9f13bbc9d6e552781b60cdf2cad364b4c3e84031110bb3bff20be07",
    ):
        all_passed = False

    # random_test_11 (single byte)
    test_count += 1
    if not test_vector(
        "random_test_11_single_byte",
        "3f912a528be64bdf2e71e6b20dd41bcabf78c529bf720ea332ab4a461392f147",
        "f0e5022809836e4cd8389379",
        1293434554,
        "7a",
        "1e",
    ):
        all_passed = False

    # random_test_12 (single byte)
    test_count += 1
    if not test_vector(
        "random_test_12_single_byte",
        "d6ea2038ff087b4995db00b47bd55f2bb8220ac7f016c6bf8108b622b07b35aa",
        "4416b4ad59edf55d4520ea12",
        1260326267,
        "66",
        "fb",
    ):
        all_passed = False

    # random_test_18 (empty)
    test_count += 1
    if not test_vector(
        "random_test_18_empty",
        "e78b77266745374f3654e6eea0d03db76ae79ded873d2e509b146ea74b2e7fb6",
        "ca199985590fcfe77f30ec34",
        600406558,
        "",
        "",
    ):
        all_passed = False

    # random_test_21 (empty)
    test_count += 1
    if not test_vector(
        "random_test_21_empty",
        "14a4c33ac583900cbfe4f9169762a42a315503216b6dd93569de244e0ceba913",
        "2c251b5b80247484d0c6e6cf",
        1859828364,
        "",
        "",
    ):
        all_passed = False

    # random_test_24 (single byte)
    test_count += 1
    if not test_vector(
        "random_test_24_single_byte",
        "153e81f69865b81a6f3978dea607558d3dca7c0415f34fbe2d7f50ff2ead1e1e",
        "b64e3640f977a2b1e0620ac1",
        578670284,
        "f8",
        "1e",
    ):
        all_passed = False

    # random_test_27 (single byte)
    test_count += 1
    if not test_vector(
        "random_test_27_single_byte",
        "51c1c21657ab4c534a5b1ad69d9ee4935c3c4367018106eafeff02fc796ff3e8",
        "d1e228037d8e6a195e4b1cb2",
        157715720,
        "98",
        "4a",
    ):
        all_passed = False

    print("\nRan ", test_count, " random test vectors")
    if all_passed:
        print("All random test vectors pass!")
    else:
        print("Some tests failed.")

    return all_passed


def main():
    print("=" * 60)
    print("ChaCha20 Test Suite - Python Cross-Validation")
    print("=" * 60)

    test_rfc_7539_block()
    test_rfc_7539_sunscreen()

    var all_passed = test_random_vectors()

    print("\n" + "=" * 60)
    if all_passed:
        print("All tests passed!")
    else:
        print("Some tests failed.")
    print("=" * 60)
