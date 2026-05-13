from std.collections import List
from std.python import Python
from thistle.ed25519 import (
    ed25519_verify,
    edwards_decode_verify_compatible,
    ed25519_d,
    edwards_encode,
    fe_from_bytes,
    fe_to_bytes,
    sqrt_ratio_checked,
    FieldElement51,
    EdwardsPoint,
    _scalar_mult,
    ed25519_base_point,
    _edwards_double_standalone,
    edwards_add,
    edwards_negate,
    _s_lt_l,
    Scalar
)
from thistle.sha2 import sha512_hash

def bytes_to_hex(bytes: List[UInt8]) -> String:
    var r = String(capacity=len(bytes)*2)
    for i in range(len(bytes)):
        var hi = Int(bytes[i] >> 4)
        var lo = Int(bytes[i] & 15)
        r += chr(hi + 48 if hi < 10 else hi - 10 + 97)
        r += chr(lo + 48 if lo < 10 else lo - 10 + 97)
    return r

def edwards_decode_decision_trace(data: Span[UInt8, ...]) -> String:
    var y_bytes = List[UInt8](capacity=32)
    for i in range(32):
        y_bytes.append(data[i])
    var sign = (y_bytes[31] >> 7) & 1
    y_bytes[31] = y_bytes[31] & 0x7F
    var y = fe_from_bytes(Span[UInt8, ...](y_bytes))
    var y_round = fe_to_bytes(y)

    var y2 = y.square()
    var u = y2 - FieldElement51.ONE()
    var v = y2 * ed25519_d() + FieldElement51.ONE()
    var x_opt = sqrt_ratio_checked(u, v)

    var out = String()
    out += "sign=" + String(Int(sign)) + "\n"
    out += "y_round=" + bytes_to_hex(y_round) + "\n"
    if not x_opt:
        out += "x_opt=none\n"
        out += "ok=0\n"
        return out

    var x = x_opt.value()
    out += "x_opt=some\n"
    out += "x_parity_raw=" + String(Int(x.to_bytes()[0] & 1)) + "\n"

    var x_try = x
    var flipped = False
    if (x_try.to_bytes()[0] & 1) != sign:
        x_try = FieldElement51.ZERO() - x_try
        flipped = True
    out += "flipped=" + ( "1" if flipped else "0" ) + "\n"
    out += "x_parity_try=" + String(Int(x_try.to_bytes()[0] & 1)) + "\n"

    var chk = x_try.square() * v - u
    var chk_bytes = chk.to_bytes()
    var ok = True
    for i in range(32):
        if chk_bytes[i] != 0:
            ok = False
    out += "chk_try_zero=" + ( "1" if ok else "0" ) + "\n"

    var x_final = x_try
    if not ok:
        var x_alt = FieldElement51.ZERO() - x_try
        var chk2 = x_alt.square() * v - u
        var chk2_bytes = chk2.to_bytes()
        var ok2 = True
        for i in range(32):
            if chk2_bytes[i] != 0:
                ok2 = False
        out += "chk_alt_zero=" + ( "1" if ok2 else "0" ) + "\n"
        if ok2:
            x_final = x_alt
            ok = True
        else:
            ok = False
    else:
        out += "chk_alt_zero=na\n"

    if not ok:
        out += "ok=0\n"
        return out

    var p = EdwardsPoint(x_final, y, FieldElement51.ONE(), x_final * y)
    var enc = edwards_encode(p)
    out += "x_final_parity=" + String(Int(x_final.to_bytes()[0] & 1)) + "\n"
    out += "enc_round=" + bytes_to_hex(enc) + "\n"
    out += "ok=1\n"
    return out

def edwards_decode_diagnostics(data: Span[UInt8, ...]) -> String:
    var y_bytes = List[UInt8](capacity=32)
    for i in range(32):
        y_bytes.append(data[i])
    var sign = (y_bytes[31] >> 7) & 1
    y_bytes[31] = y_bytes[31] & 0x7F
    var y = fe_from_bytes(Span[UInt8, ...](y_bytes))

    var y2 = y.square()
    var u = y2 - FieldElement51.ONE()
    var v = y2 * ed25519_d() + FieldElement51.ONE()

    var x_opt = sqrt_ratio_checked(u, v)
    var out = String()
    out += "sign=" + String(Int(sign)) + "\n"
    out += "u=" + bytes_to_hex(u.to_bytes()) + "\n"
    out += "v=" + bytes_to_hex(v.to_bytes()) + "\n"
    if not x_opt:
        out += "sqrt_ok=0\n"
        return out

    var x = x_opt.value()
    var vx2 = x.square() * v
    var d1 = vx2 - u
    var d2 = vx2 + u
    out += "sqrt_ok=1\n"
    out += "x=" + bytes_to_hex(x.to_bytes()) + "\n"
    out += "vx2-u=" + bytes_to_hex(d1.to_bytes()) + "\n"
    out += "vx2+u=" + bytes_to_hex(d2.to_bytes()) + "\n"
    out += "x_parity_before=" + String(Int(x.to_bytes()[0] & 1)) + "\n"
    if (x.to_bytes()[0] & 1) != sign:
        out += "parity_flip=1\n"
    else:
        out += "parity_flip=0\n"
    return out

def ed25519_verify_debug(public_key: Span[UInt8, ...], message: Span[UInt8, ...], signature: Span[UInt8, ...]) -> String:
    if len(public_key) != 32 or len(signature) != 64:
        return "len"
    var A_res = edwards_decode_verify_compatible(public_key)
    if not A_res.ok:
        return "decode-a"
    var A = A_res.p

    var R_enc = List[UInt8](capacity=32)
    for i in range(32): R_enc.append(signature[i])

    var S_bytes = List[UInt8](capacity=32)
    for i in range(32): S_bytes.append(signature[32 + i])
    var S_bytes_span = Span[UInt8, ...](S_bytes)
    if not _s_lt_l(S_bytes_span):
        return "s-range"

    var k_in = List[UInt8](capacity=64 + len(message))
    for i in range(32): k_in.append(R_enc[i])
    for i in range(32): k_in.append(public_key[i])
    for i in range(len(message)): k_in.append(message[i])
    var k_hash = sha512_hash(Span[UInt8, ...](k_in))

    var k_scalar = Scalar.from_bytes_wide(Span[UInt8, ...](k_hash))

    var SB = _scalar_mult(S_bytes_span, ed25519_base_point())
    var kA = _scalar_mult(Span[UInt8, ...](k_scalar.to_bytes()), A)

    var P = edwards_add(SB, edwards_negate(kA))
    for _ in range(3):
        P = _edwards_double_standalone(P)
    var P_enc = edwards_encode(P)
    var R_res = edwards_decode_verify_compatible(Span[UInt8, ...](R_enc))
    if not R_res.ok:
        return "decode-r"
    var R_point = R_res.p
    for _ in range(3):
        R_point = _edwards_double_standalone(R_point)
    var R8_enc = edwards_encode(R_point)
    for i in range(32):
        if P_enc[i] != R8_enc[i]:
            return "eq"
    return "ok"

def ed25519_verify_equation_diagnostics(public_key: Span[UInt8, ...], message: Span[UInt8, ...], signature: Span[UInt8, ...]) -> String:
    if len(public_key) != 32 or len(signature) != 64:
        return "len"
    var A_res = edwards_decode_verify_compatible(public_key)
    if not A_res.ok:
        return "decode-a"
    var A = A_res.p

    var R_enc = List[UInt8](capacity=32)
    for i in range(32): R_enc.append(signature[i])

    var S_bytes = List[UInt8](capacity=32)
    for i in range(32): S_bytes.append(signature[32 + i])
    var S_bytes_span = Span[UInt8, ...](S_bytes)
    if not _s_lt_l(S_bytes_span):
        return "s-range"

    var k_in = List[UInt8](capacity=64 + len(message))
    for i in range(32): k_in.append(R_enc[i])
    for i in range(32): k_in.append(public_key[i])
    for i in range(len(message)): k_in.append(message[i])
    var k_hash = sha512_hash(Span[UInt8, ...](k_in))
    var k_scalar = Scalar.from_bytes_wide(Span[UInt8, ...](k_hash))

    var SB = _scalar_mult(S_bytes_span, ed25519_base_point())
    var kA = _scalar_mult(Span[UInt8, ...](k_scalar.to_bytes()), A)

    var P = edwards_add(SB, edwards_negate(kA))
    for _ in range(3):
        P = _edwards_double_standalone(P)
    var P_enc = edwards_encode(P)

    var R_res = edwards_decode_verify_compatible(Span[UInt8, ...](R_enc))
    if not R_res.ok:
        return "decode-r"
    var R_point = R_res.p
    for _ in range(3):
        R_point = _edwards_double_standalone(R_point)
    var R8_enc = edwards_encode(R_point)

    var out = String()
    out += "P8=" + bytes_to_hex(P_enc) + "\n"
    out += "R8=" + bytes_to_hex(R8_enc) + "\n"
    var first_diff = -1
    for i in range(32):
        if P_enc[i] != R8_enc[i]:
            first_diff = i
            break
    out += "first_diff=" + String(first_diff) + "\n"
    return out


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


def run_case(tc_id: String, pk_hex: String, msg_hex: String, sig_hex: String, expected_valid: Bool) -> Bool:
    var pk = hex_to_bytes(pk_hex)
    var msg = hex_to_bytes(msg_hex)
    var sig = hex_to_bytes(sig_hex)
    var got = ed25519_verify(Span[UInt8, ...](pk), Span[UInt8, ...](msg), Span[UInt8, ...](sig))
    if got != expected_valid:
        print("Test ", tc_id, " mismatch: expected=", expected_valid, " got=", got)
        if tc_id == "1" or tc_id == "71" or tc_id == "85":
            var reason = ed25519_verify_debug(Span[UInt8, ...](pk), Span[UInt8, ...](msg), Span[UInt8, ...](sig))
            print("  debug stage: ", reason)
            if reason == "decode-a":
                print("  decode-a diagnostics:")
                print(edwards_decode_diagnostics(Span[UInt8, ...](pk)))
            if reason == "eq":
                print("  equation diagnostics:")
                print(ed25519_verify_equation_diagnostics(Span[UInt8, ...](pk), Span[UInt8, ...](msg), Span[UInt8, ...](sig)))
        return False
    return True


def main() raises:
    print("Wycheproof Ed25519")
    var py = Python.import_module("json")
    var builtins = Python.import_module("builtins")

    var fh = builtins.open("tests/Wycheproof/ed25519_test.json", "r")
    var root = py.load(fh)
    fh.close()

    var groups = root["testGroups"]
    var ok_count = 0
    var fail_count = 0

    for g in groups:
        var pk_hex = String(g["publicKey"]["pk"])
        for t in g["tests"]:
            var tc_id = String(t["tcId"])
            var msg_hex = String(t["msg"])
            var sig_hex = String(t["sig"])
            var result = String(t["result"])
            var expected_valid = result == "valid"

            if run_case(tc_id, pk_hex, msg_hex, sig_hex, expected_valid):
                ok_count += 1
            else:
                fail_count += 1

    print("Wycheproof results: ", ok_count, " OK, ", fail_count, " FAIL")
    if fail_count > 0:
        raise Error("Wycheproof tests failed")