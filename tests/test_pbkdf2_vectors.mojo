#!/usr/bin/env mojo

from collections import List
from thistle.pbkdf2 import pbkdf2_hmac_sha256, pbkdf2_hmac_sha512
from thistle.sha2 import bytes_to_hex


fn check_test(name: String, got: String, expected: String) -> Bool:
    if got == expected:
        print("  [pass] " + name)
        return True
    else:
        print("  [failure] " + name)
        print("    Expected: " + expected)
        print("    Got:      " + got)
        return False


def main():
    print("Running PBKDF2 Tests...")
    var all_passed = True

    print("\nPBKDF2-HMAC-SHA256:")
    
    all_passed &= check_test(
        'PBKDF2-SHA256("password", "salt", 1, 20)',
        bytes_to_hex(pbkdf2_hmac_sha256("password".as_bytes(), "salt".as_bytes(), 1, 20)),
        "120fb6cffcf8b32c43e7225256c4f837a86548c9",
    )
    
    all_passed &= check_test(
        'PBKDF2-SHA256("password", "salt", 2, 20)',
        bytes_to_hex(pbkdf2_hmac_sha256("password".as_bytes(), "salt".as_bytes(), 2, 20)),
        "ae4d0c95af6b46d32d0adff928f06dd02a303f8e",
    )
    
    all_passed &= check_test(
        'PBKDF2-SHA256("password", "salt", 4096, 20)',
        bytes_to_hex(pbkdf2_hmac_sha256("password".as_bytes(), "salt".as_bytes(), 4096, 20)),
        "c5e478d59288c841aa530db6845c4c8d962893a0",
    )
    
    all_passed &= check_test(
        'PBKDF2-SHA256("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25)',
        bytes_to_hex(pbkdf2_hmac_sha256("passwordPASSWORDpassword".as_bytes(), "saltSALTsaltSALTsaltSALTsaltSALTsalt".as_bytes(), 4096, 25)),
        "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c",
    )
    
    all_passed &= check_test(
        'PBKDF2-SHA256("password", "salt", 1, 32)',
        bytes_to_hex(pbkdf2_hmac_sha256("password".as_bytes(), "salt".as_bytes(), 1, 32)),
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
    )
    
    all_passed &= check_test(
        'PBKDF2-SHA256("test", "test", 1000, 32)',
        bytes_to_hex(pbkdf2_hmac_sha256("test".as_bytes(), "test".as_bytes(), 1000, 32)),
        "57e319295437f00dc9de1a93eaa34b74b7b98725cba7cea5925eda66c262a380",
    )

    print("\nPBKDF2-HMAC-SHA512:")
    
    all_passed &= check_test(
        'PBKDF2-SHA512("password", "salt", 1, 64)',
        bytes_to_hex(pbkdf2_hmac_sha512("password".as_bytes(), "salt".as_bytes(), 1, 64)),
        "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce",
    )
    
    all_passed &= check_test(
        'PBKDF2-SHA512("password", "salt", 2, 64)',
        bytes_to_hex(pbkdf2_hmac_sha512("password".as_bytes(), "salt".as_bytes(), 2, 64)),
        "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e",
    )
    
    all_passed &= check_test(
        'PBKDF2-SHA512("test", "test", 1000, 64)',
        bytes_to_hex(pbkdf2_hmac_sha512("test".as_bytes(), "test".as_bytes(), 1000, 64)),
        "dc449e96c930ca46653ec867c448719fab39dd85c4b91c1643d2faad140f24e711da13133e34ee4da0d3a5a2ca154edd4bfaeb9cf80cb9af57bce4d7ea1b94ce",
    )

    if all_passed:
        print("\nAll PBKDF2 tests passed!")
    else:
        print("\nSome PBKDF2 tests failed.")
