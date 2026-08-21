from std.collections import List

from thistle.sha3 import shake256_into
from thistle.utils import StackBuffer


def main():
    var input = List[UInt8]()
    var output = StackBuffer[UInt8, 32]()
    shake256_into(output, Span[UInt8, ...](input), 33)
