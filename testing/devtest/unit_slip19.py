# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# work thru examples given in SLIP-19
# in simulator
#
#   execfile('../../testing/devtest/unit_slip21.py')
#
import bip39
import ownership
from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex

"""
(
    "BIP39 seed",
    "Passphrase",
    "Ownership Key",
    "Path",
    "scriptPubKey",
    "User confirmation",
    "commitmentData",
    "sighash",
    "proof of ownership",
)
"""
cases = [
(
    "all all all all all all all all all all all all",
    "",
    "0a115a171e30f8a740bae6c4144bec5dc1099ffa79b83dfb8aa3501d094de585",
    "m/84'/0'/0'/1/0",
    "0014b2f771c370ccf219cd3059cda92bdf7f00cf2103",
    False,
    "",
    "850dd556283b49d80fa5501035b4775e62f0c80bf36f62d1adf2f2f9f108c884",
    "534c00190001a122407efc198211c81af4450f40b235d54775efd934d16b9e31c6ce9bad57070002483045022100c0dc28bb563fc5fea76cacff75dba9cb4122412faae01937cdebccfb065f9a7002202e980bfbd8a434a7fc4cd2ca49da476ce98ca097437f8159b1a386b41fcdfac50121032ef68318c8f6aaa0adec0199c69901f0db7d3485eb38d9ad235221dc3d61154b"
)
]

for seed, passphrase, ownership_key, path, script_pubkey, user_confirmation, commitment_data, sighash, proof_of_ownership in cases:
    master_seed = bip39.master_secret(seed, passphrase)

    got_ownership_key = ownership.slip19_ownership_key(master_seed)

    got_ownership_key_str = b2a_hex(got_ownership_key).decode('utf-8')
    assert got_ownership_key_str == ownership_key

    ownership_id = ownership.slip19_ownership_id(got_ownership_key, a2b_hex(script_pubkey))
    ownership_ids = [ownership_id]

    proof_body = ownership.slip19_compile_proof_body(ownership_ids, user_confirmation)
    proof_footer = ownership.slip19_compile_proof_footer(a2b_hex(script_pubkey), a2b_hex(b2a_hex(commitment_data)))
    got_sighash = ownership.slip19_compile_sighash(proof_body, proof_footer)

    got_sighash_str = b2a_hex(got_sighash).decode('utf-8')
    assert got_sighash_str == sighash
