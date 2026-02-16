from thistle.camellia import CamelliaCipher
from thistle.sha2 import bytes_to_hex
from collections import List
from python import Python

fn hex_char_to_val(c: Int) -> UInt8:
    if c >= 48 and c <= 57:  # '0'-'9'
        return UInt8(c - 48)
    if c >= 97 and c <= 102:  # 'a'-'f'
        return UInt8(c - 97 + 10)
    if c >= 65 and c <= 70:  # 'A'-'F'
        return UInt8(c - 65 + 10)
    return 0

fn hex_str_to_bytes(s: String) -> List[UInt8]:
    var res = List[UInt8]()
    var char_list = s.as_bytes()
    var i = 0
    var clean_hex = List[UInt8]()
    while i < len(char_list):
        var c = Int(char_list[i])
        if (
            (c >= 48 and c <= 57)
            or (c >= 97 and c <= 102)
            or (c >= 65 and c <= 70)
        ):
            clean_hex.append(UInt8(c))
        i += 1

    i = 0
    while i < len(clean_hex):
        var high = hex_char_to_val(Int(clean_hex[i]))
        var low: UInt8 = 0
        if i + 1 < len(clean_hex):
            low = hex_char_to_val(Int(clean_hex[i + 1]))
        res.append((high << 4) | low)
        i += 2
    return res^

fn check_test(name: String, got: String, expected: String) -> Bool:
    if got == expected:
        print("  [PASS] " + name)
        return True
    else:
        print("  [FAIL] " + name)
        print("    Expected: " + expected)
        print("    Got:      " + got)
        return False

fn main() raises:
    print("Running Camellia Vector Tests...")
    
    var py = Python.import_module("json")
    var f = Python.import_module("builtins").open("tests/camellia_vectors/camellia_test_vectors", "r")
    var data_str = f.read()
    f.close()
    var vectors = py.loads(data_str)
    
    var all_passed = True
    var count = Int(vectors.__len__())
    
    for i in range(count):
        var v = vectors[i]
        var name = String(v["name"])
        var key_hex = String(v["key"])
        var pt_hex = String(v["plaintext"])
        var ct_hex = String(v["ciphertext"])
        
        var key = hex_str_to_bytes(key_hex)
        var pt = hex_str_to_bytes(pt_hex)
        
        var cipher = CamelliaCipher(Span[UInt8](key))
        var got_ct = bytes_to_hex(cipher.encrypt(Span[UInt8](pt)))
        
        all_passed &= check_test(name, got_ct, ct_hex)
        
        var ct = hex_str_to_bytes(ct_hex)
        var got_pt = bytes_to_hex(cipher.decrypt(Span[UInt8](ct)))
        all_passed &= check_test(name + " (Dec)", got_pt, pt_hex)

    if all_passed:
        print("Canellia tests pass!")
    else:
        print("Canellia tests failed")
