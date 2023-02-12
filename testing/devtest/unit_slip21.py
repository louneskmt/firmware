# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# work thru examples given in SLIP-19
# in simulator
#
#   execfile('../../testing/devtest/unit_slip19.py')
#
import bip39
import ownership
from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex

cases = [
(   "m",
    "dbf12b44133eaab506a740f6565cc117228cbf1dd70635cfa8ddfdc9af734756",
),
(   'm/"SLIP-0021"',
    "1d065e3ac1bbe5c7fad32cf2305f7d709dc070d672044a19e610c77cdf33de0d",
),
(   'm/"SLIP-0021"/"Master encryption key"',
    "ea163130e35bbafdf5ddee97a17b39cef2be4b4f390180d65b54cf05c6a82fde",
),
(   'm/"SLIP-0021"/"Authentication key"',
    "47194e938ab24cc82bfa25f6486ed54bebe79c40ae2a5a32ea6db294d81861a6",
),
]

mnemonic = "all all all all all all all all all all all all"
seed = bip39.master_secret(mnemonic)

for path, key in cases:
    got_key = ownership.slip21_key_from_bip32_master_seed(seed, path)
    got_key = b2a_hex(got_key).decode('utf-8')

    assert got_key == key