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
import stash, seed
from chains import AF_P2WPKH, AF_P2WPKH_P2SH, AF_CLASSIC, AF_P2WSH

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
    AF_P2WPKH,
    "m/84'/0'/0'/1/0",
    "0014b2f771c370ccf219cd3059cda92bdf7f00cf2103",
    False,
    "",
    "850dd556283b49d80fa5501035b4775e62f0c80bf36f62d1adf2f2f9f108c884",
    "534c00190001a122407efc198211c81af4450f40b235d54775efd934d16b9e31c6ce9bad57070002483045022100c0dc28bb563fc5fea76cacff75dba9cb4122412faae01937cdebccfb065f9a7002202e980bfbd8a434a7fc4cd2ca49da476ce98ca097437f8159b1a386b41fcdfac50121032ef68318c8f6aaa0adec0199c69901f0db7d3485eb38d9ad235221dc3d61154b"
),
(
    "all all all all all all all all all all all all",
    "",
    "0a115a171e30f8a740bae6c4144bec5dc1099ffa79b83dfb8aa3501d094de585",
    AF_P2WPKH_P2SH,
    "m/49'/0'/0'/1/0",
    "a914b9ddc52a7d95ad46d474bfc7186d0150e15a499187",
    True,
    "TREZOR",
    "709fa3a60709cecefbd7aaaf551ff23421d65d1c046e6a9390abf73cbcd2fc83",
    "534c0019010192caf0b8daf78f1d388dbbceaec34bd2dabc31b217e32343663667f6694a3f4617160014e0cffbee1925a411844f44c3b8d81365ab51d0360247304402207f1003c59661ddf564af2e10d19ad8d6a1a47ad30e7052197d95fd65d186a67802205f0a804509980fec1b063554aadd8fb871d7c9fe934087cba2da09cbeff8531c012103a961687895a78da9aef98eed8e1f2a3e91cfb69d2f3cf11cbd0bb1773d951928"
),
(
    "all all all all all all all all all all all all",
    "TREZOR",
    "2d773852e0959b3c1bac15bd3a8ad410e2c6720befb4f7f428d74bdd5d6e4f1d",
    AF_CLASSIC,
    "m/44'/0'/0'/1/0",
    "76a9145a4deff88ada6705ed70835bc0db56a124b9cdcd88ac",
    False,
    "",
    "abf12242bc87f457126373a08775fbeb67ccd5e09c4acbc1d8b310be68a3ac33",
    "534c00190001ccc49ac5fede0efc80725fbda8b763d4e62a221c51cc5425076cffa7722c0bda6b483045022100e818002d0a85438a7f2140503a6aa0a6af6002fa956d0101fd3db24e776e546f0220430fd59dc1498bc96ab6e71a4829b60224828cf1fc35edc98e0973db203ca3f0012102f63159e21fbcb54221ec993def967ad2183a9c243c8bff6e7d60f4d5ed3b386500"
# ),
# (
#     "all all all all all all all all all all all all",
#     "",
#     "0a115a171e30f8a740bae6c4144bec5dc1099ffa79b83dfb8aa3501d094de585",
#     "m/86'/0'/0'/1/0",
#     "51204102897557de0cafea0a8401ea5b59668eccb753e4b100aebe6a19609f3cc79f",
#     False,
#     "",
#     "331a936e0a94d8ec7a105507dbdd445d6cd6a516d53c0bfd83769bdac1950483",
#     "534c00190001dc18066224b9e30e306303436dc18ab881c7266c13790350a3fe415e438135ec000140647d6af883107a870417e808abe424882bd28ee04a28ba85a7e99400e1b9485075733695964c2a0fa02d4439ab80830e9566ccbd10f2597f5513eff9f03a0497"
)
]

multisig_cases = [
(
    [
        "all all all all all all all all all all all all",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    ],
    [
        "",
        "",
        "",
    ],
    [
        "0a115a171e30f8a740bae6c4144bec5dc1099ffa79b83dfb8aa3501d094de585",
        "cd50559c65666fd381e823b82fff04763465062c1ff4c93d3e147a306f884130",
        "64b3e4f003fd7dea4168dd19f85410ac3b1844abd1d7f9f3a74254a7852af725",
    ],
    AF_P2WSH,
    "m/84'/0'/0'/1/0",
    "00209149b5bcaae8c876f1997ef6b60ec197475217fd3e736d4c54fcf49fe4f5213a",
    False,
    "TREZOR",
    "d2cca14e9ea31a5e4bb36e6e5813adf31f8744bc6da09680e3a0d69e5c8dddb1",
    "534c00190003309c4ffec5c228cc836b51d572c0a730dbabd39df9f01862502ac9eabcdeb94a46307177b959c48bf2eb516e0463bb651aad388c7f8f597320df7854212fa3443892f9573e08cedff9160b243759520733a980fed45b131a8bba171317ae5d940004004830450221009d8cd2d792633732b3a406ea86072e94c72c0d1ffb5ddde466993ee2142eeef502206fa9c6273ab35400ebf689028ebcf8d2031edb3326106339e92d499652dc43030147304402205fae1218bc4600ad6c28b6093e8f3757603681b024e60f1d92fca579bfce210b022011d6f1c6ef1c7f7601f635ed237dafc774386dd9f4be0aef85e3af3f095d8a9201695221032ef68318c8f6aaa0adec0199c69901f0db7d3485eb38d9ad235221dc3d61154b2103025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a621033057150eb57e2b21d69866747f3d377e928f864fa88ecc5ddb1c0e501cce3f8153ae",
    "5221032ef68318c8f6aaa0adec0199c69901f0db7d3485eb38d9ad235221dc3d61154b2103025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a621033057150eb57e2b21d69866747f3d377e928f864fa88ecc5ddb1c0e501cce3f8153ae",
    [0,2]
)
]

print('----')
i = 0
for words, passphrase, ownership_key, addr_fmt, path, script_pubkey, user_confirmation, commitment_data, sighash, proof_of_ownership in cases:
    print("Test case #%d" % (i))
    i += 1
    seed.set_seed_value(words)
    seed.set_bip39_passphrase(passphrase)

    master_seed = bip39.master_secret(words, passphrase)

    got_ownership_key = ownership.slip19_ownership_key(master_seed)

    got_ownership_key_str = b2a_hex(got_ownership_key).decode('utf-8')
    assert got_ownership_key_str == ownership_key

    ownership_id = ownership.slip19_ownership_id(got_ownership_key, a2b_hex(script_pubkey))
    ownership_ids = [ownership_id]

    proof_body = ownership.slip19_compile_proof_body(ownership_ids, user_confirmation)
    proof_footer = ownership.slip19_compile_proof_footer(a2b_hex(script_pubkey), a2b_hex(b2a_hex(commitment_data)))
    got_sighash = ownership.slip19_compile_sighash(proof_body, proof_footer)

    got_sighash_str = b2a_hex(got_sighash).decode('utf-8')
    assert got_sighash_str == sighash, "got_sighash_str: %s, expected: %s" % (got_sighash_str, sighash)

    with stash.SensitiveValues() as sv:
        node = sv.derive_path(path)
        proof_signature = ownership.slip19_sign_proof(node, addr_fmt, got_sighash)
        got_full_body = proof_body + proof_signature

        got_proof_of_ownership = b2a_hex(got_full_body).decode('utf-8')
        assert got_proof_of_ownership == proof_of_ownership, "got_proof_of_ownership: %s, expected: %s" % (got_proof_of_ownership, proof_of_ownership)

print('----')
i = 0
for words, passphrase, ownership_key, addr_fmt, path, script_pubkey, user_confirmation, commitment_data, sighash, proof_of_ownership, witness_script, signers in multisig_cases:
    print("Multisig Test case #%d" % (i))
    i += 1
    
    # compute all ownership_ids
    ownership_ids = []
    for i in range(len(words)):
        master_seed = bip39.master_secret(words[i], passphrase[i])

        got_ownership_key = ownership.slip19_ownership_key(master_seed)

        got_ownership_key_str = b2a_hex(got_ownership_key).decode('utf-8')
        assert got_ownership_key_str == ownership_key[i]

        ownership_id = ownership.slip19_ownership_id(got_ownership_key, a2b_hex(script_pubkey))
        # print(b2a_hex(ownership_id).decode('utf-8'))
        ownership_ids.append(ownership_id)

    proof_body = ownership.slip19_compile_proof_body(ownership_ids, user_confirmation)
    proof_footer = ownership.slip19_compile_proof_footer(a2b_hex(script_pubkey), a2b_hex(b2a_hex(commitment_data)))
    got_sighash = ownership.slip19_compile_sighash(proof_body, proof_footer)

    got_sighash_str = b2a_hex(got_sighash).decode('utf-8')
    assert got_sighash_str == sighash, "got_sighash_str: %s, expected: %s" % (got_sighash_str, sighash)

    # we only sign with keys in signers
    signatures = []
    for i in signers:
        seed.set_seed_value(words[i])
        seed.set_bip39_passphrase(passphrase[i])
        with stash.SensitiveValues() as sv:
            node = sv.derive_path(path)
            signatures.append(ownership.slip19_sign_proof_multisig(node, got_sighash))

    got_full_body = ownership.slip19_create_multisig_proof(proof_body, signatures, a2b_hex(witness_script)) 

    got_proof_of_ownership = b2a_hex(got_full_body).decode('utf-8')
    assert got_proof_of_ownership == proof_of_ownership, "got_proof_of_ownership: %s, expected: %s" % (got_proof_of_ownership, proof_of_ownership)
