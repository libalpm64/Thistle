# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Libalpm64, Lostlab Technologies.

from .curve25519 import FieldElement51

# Edwards d value (-121665/121666 mod p).
comptime EDWARDS_D = FieldElement51(
    929955233495203,
    466365720129213,
    1662059464998953,
    2033849074728123,
    1442794654840575,
)
# Edwards 2*d value.
comptime EDWARDS_D2 = FieldElement51(
    1859910466990425,
    932731440258426,
    1072319116312658,
    1815898335770999,
    633789495995903,
)

# sqrt(-1) mod p.
comptime SQRT_M1 = FieldElement51(
    1718705420411056,
    234908883556509,
    2233514472574048,
    2117202627021982,
    765476049583133,
)
# (A-2)/4 for Montgomery ladder, RFC 7748 a24 = 121665
comptime APLUS2_OVER_FOUR = FieldElement51(121665, 0, 0, 0, 0)
