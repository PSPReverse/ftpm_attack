#!/usr/bin/env python3

import sys
import re
from hashlib import sha256
import binascii

"""
Takes some xxd-style output from stdin and return hex string for easier transportation.

Use `-r` to reverse the byte order.

stdin:
00000000: 4415 f833 4a48 5304 dc68 9616 f8b0 7743  D..3JHS..h....wC
00000010: e836 f969 8b1f fb0c 6b4d 6268 22aa 2afb  .6.i....kMbh".*.

stdout:
b'4415f8334a485304dc689616f8b07743e836f9698b1ffb0c6b4d626822aa2afb'
"""

def rev_xxd(s):
    i_hex_str = re.compile(r"[0-9]+: ([0-9a-f ]+)  ").findall(s)
    i_bin = list(map(lambda i: binascii.a2b_hex(i.replace(" ", "")), i_hex_str))
    return b"".join(i_bin)

if __name__ == '__main__':
    stdin = sys.stdin.read()
    bytes_ = rev_xxd(stdin)
    if len(sys.argv) > 1 and sys.argv[1] == '-r':
        bytes_ = bytes_[::-1]

    print(binascii.hexlify(bytes_))
