#
# ownership.py - Proof of Ownership (SLIP-0019)
#
import ngu, stash, bip39
from serializations import CTxOut, ser_compact_size, deser_compact_size, ser_sig_der, deser_der_sig, ser_string, deser_string, hash160, sha256
from chains import verify_recover_pubkey, AF_P2WPKH, AF_CLASSIC, AF_P2WPKH_P2SH, AF_P2WSH
from uio import BytesIO
from utils import parse_addr_fmt_str

# SLIP-0021 - Symmetric Key Derivation for HD Wallets
# See https://github.com/satoshilabs/slips/blob/master/slip-0021.md

def slip21_parse_path(path):
    # Parse a SLIP-0021 path into a list of labels.
    # Example: m/"SLIP-0021"/"Master encryption key" -> ['SLIP-0021', 'Master encryption key']

    if(path == 'm'):
        return []

    if(path[0:2] != 'm/'):
        raise ValueError('Invalid SLIP-0021 path: %s' % path)

    # Remove m/ prefix ans split on /
    path = path[2:].split('/')

    # Remove quotes and return
    return [i[1:-1] for i in path]

def slip21_child_node(N, label):
    # Derive a SLIP-0021 child node from a parent node.
    return ngu.hmac.hmac_sha512(N[0:32], b'\x00' + label)

def slip21_node_key(N):
    # Returns the node key from a SLIP-0021 node.
    return N[32:64]

def slip21_master_node(master_seed):
    # Derive SLIP-0021 master node from a BIP-0032 master node.
    return ngu.hmac.hmac_sha512(b'Symmetric key seed', master_seed)

def slip21_key_from_bip32_master_seed(path):
    # Derive a SLIP-0021 key from a BIP-0032 master node and a label.

    with stash.SensitiveValues() as sv:
        words = bip39.b2a_words(sv.raw)
        master_seed = bip39.master_secret(words, stash.bip39_passphrase)
        N = slip21_master_node(master_seed)

        labels = slip21_parse_path(path)

        if labels:
            for label in labels:
                N = slip21_child_node(N, label)

        key = slip21_node_key(N)

        stash.blank_object(words)
        stash.blank_object(master_seed)
        stash.blank_object(N)

        return key

# SLIP-0019 - Proof of Ownership
# See https://github.com/satoshilabs/slips/blob/master/slip-0019.md

SLIP19_VERSION_MAGIC = b'\x53\x4c\x00\x19'
SLIP19_OWNERSHIP_ID_PATH = 'm/"SLIP-0019"/"Ownership identification key"'

def slip19_ownership_key():
    # Derive a SLIP-0019 ownership key from a BIP-0032 master seed
    return slip21_key_from_bip32_master_seed(SLIP19_OWNERSHIP_ID_PATH)

def slip19_ownership_id(ownership_key, script_pubkey):
    # Derive a SLIP-0019 ownership ID from a SLIP-0019 ownership key and a scriptPubKey.
    return ngu.hmac.hmac_sha256(ownership_key, script_pubkey)

def slip19_compute_sighash(proof_body, proof_footer):
    # Compile the sighash of a SLIP-0019 proof of ownership.
    return ngu.hash.sha256s(proof_body + proof_footer)

def slip19_serialize_body(ownership_ids, user_confirmation):
    # Compile the body of a SLIP-0019 proof of ownership.

    # Get flags bits
    uc_bit = 1 if user_confirmation else 0
    reserved_bits = [0] * 7 # Reserved bits must be 0 for now
    bits = [uc_bit] + reserved_bits

    # Convert bits array to byte, bit 0 (user confirmation) being the least significant bit
    flags_byte = 0
    for bit in reversed(bits):
        flags_byte = (flags_byte << 1) | bit
    flags_byte = bytes([flags_byte])

    # Serialize ownership IDs
    n = ser_compact_size(len(ownership_ids))
    ids = b''.join(ownership_ids)

    return SLIP19_VERSION_MAGIC + flags_byte + n + ids

def slip19_serialize_footer(script_pubkey, commitment_data = b''):
    # Compile the footer of a SLIP-0019 proof of ownership.
    return ser_string(script_pubkey) + ser_string(commitment_data)

def slip19_deserialize_body(body):
    # Parse the body of a SLIP-0019 proof of ownership.

    with BytesIO(body) as fd:
        if fd.read(4) != SLIP19_VERSION_MAGIC:
            raise ValueError('Invalid SLIP-0019 proof body: invalid version magic')

        flags_byte = fd.read(1)[0]
        flags_bits = [(flags_byte >> i) & 1 for i in range(8)]
        user_confirmation = flags_bits[0]
        reserved_bits = flags_bits[1:]

        # Other flags are not defined for now, raise Exception if one of them is true
        if any(reserved_bits):
            raise ValueError('Invalid flag set to true')

        n = deser_compact_size(fd)
        ownership_ids = []
        for _ in range(n):
            ownership_ids.append(fd.read(32))

    return 5 + len(ser_compact_size(n)) + n*32, user_confirmation, ownership_ids

def slip19_deserialize_footer(footer):
    # Parse the footer of a SLIP-0019 proof of ownership.

    with BytesIO(footer) as fd:
        script_pubkey = deser_string(fd)
        commitment_data = deser_string(fd)

    return script_pubkey, commitment_data

def slip19_deserialize_proof(proof):
    # Parse a SLIP-0019 proof of ownership.

    n, user_confirmation, ownership_ids = slip19_deserialize_body(proof)
    scriptsig, witness = slip19_deserialize_signature(proof[n:])

    return n, user_confirmation, ownership_ids, scriptsig, witness

def slip19_deserialize_signature(sig):
    # Parse the signature of a SLIP-0019 proof of ownership.

    with BytesIO(sig) as fd:
        # Parse the scriptSig
        scriptsig = deser_string(fd)

        # Parse the number of witness elements
        n = deser_compact_size(fd)

        # Parse the witness
        witness = fd.read()

        if len(scriptsig) == len(witness) == 0:
            raise ValueError("SLIP-0019 proof of ownership must be signed")

    return scriptsig, ser_compact_size(n) + witness

def slip19_sign_proof(node, sighash):
    # Sign a SLIP-0019 proof of ownership.
    return ngu.secp256k1.sign(node.privkey(), sighash, 0).to_bytes()

def slip19_signing_protocol(node, proof_body, proof_footer):
    # The signing protocol of a SLIP-0019 proof of ownership.

    # Parse the proof body.
    _, user_confirmation, ownership_ids = slip19_deserialize_body(proof_body)

    # Derive the ownership key.
    ownership_key = slip19_ownership_key()

    # Parse the proof footer.
    script_pubkey, _ = slip19_deserialize_footer(proof_footer)

    # Derive the ownership ID.
    ownership_id = slip19_ownership_id(ownership_key, script_pubkey)

    # Check that the ownership ID is in the proof body.
    if ownership_id not in ownership_ids:
        raise ValueError('Invalid SLIP-0019 proof body: ownership ID not found')

    # TODO: Implement user confirmation

    # Compute the sighash.
    sighash = slip19_compute_sighash(proof_body, proof_footer)

    # Sign the sighash.
    return slip19_sign_proof(node, sighash)

def slip19_produce_proof(node, sig, addr_fmt):
    der_sig, _ = ser_sig_der(sig)
    pubkey = node.pubkey()

    if addr_fmt == AF_CLASSIC:
        scriptsig = ser_string(der_sig) + ser_string(pubkey)
        witness = b'\x00'
    elif addr_fmt == AF_P2WPKH_P2SH:
        redeem_script = b'\x00\x14' + ngu.hash.hash160(pubkey)
        scriptsig = ser_string(redeem_script)
        witness = b'\x02' + ser_string(der_sig) + ser_string(pubkey)
    elif addr_fmt == AF_P2WPKH:
        scriptsig = b''
        witness = b'\x02' + ser_string(der_sig) + ser_string(pubkey)
    else:
        raise NotImplementedError('Insupported address format')

    return ser_string(scriptsig) + witness

def slip19_produce_multisig_proof(proof_body, signatures, witness_script):
    # Produce a SLIP-0019 proof of ownership for a multisig address.

    # Serialize the number of witness elements (OP_0 + number of signatures + witness_script)
    n = ser_compact_size(len(signatures) + 2)

    # Serialize each signature as a length-prefixed DER-encoded signature
    der_signatures =  b''.join(map(lambda s: ser_string(ser_sig_der(s)[0]), signatures))

    # The scriptSig is empty for P2WSH
    scriptsig = b''

    # Serialize the final proof signature
    proof_signature = ser_string(scriptsig) + n + b'\x00' + der_signatures + ser_string(witness_script)

    return proof_body + proof_signature

def slip19_verify_signature(spk, sighash, scriptsig=None, witness=None):
    # See https://github.com/bitcoin/bips/blob/f9e95849f337358cd89c83b948fbede3875481c3/bip-0322.mediawiki#user-content-Verifying
    def verify_all_recid(pubkey, sighash, der_sig):
        # As we can't recover the recid, we need to try all 4 possibilities.
        # If we recover a public key that matches the one we are expecting, return True.
        for recid in range(4):
            sig = deser_der_sig(der_sig, recid)
            try:
                _, r_pubkey = verify_recover_pubkey(sig, sighash)
            except ValueError: # it can happen with multisig, we don't care
                break
            if r_pubkey == pubkey:
                return True
        return False

    # We need a signature, scriptsig and witness cannot be both empty
    if len(scriptsig) == 0 and len(witness) == 0:
        raise ValueError('Invalid SLIP-0019 proof: no signature provided')

    # Determine the address format using the scriptPubKey.
    af, hash, is_segwit = CTxOut(0, spk).get_address()
    if af is 'p2pkh' and is_segwit:
        af = 'p2wpkh'
    if af is 'p2sh' and is_segwit:
        af = 'p2wsh'
    if af is 'p2sh' and scriptsig[0] == 22 and scriptsig[1] == 0:
        af = 'p2sh-p2wpkh'
    addr_fmt = parse_addr_fmt_str(af)

    # Verify the signature.
    if addr_fmt == AF_CLASSIC:
        # Check that the scriptSig is not empty and witness is empty
        if len(scriptsig) == 0:
            raise ValueError('Invalid SLIP-0019 proof: scriptsig is empty for p2pkh')
        if witness != b'\x00':
            raise ValueError('Invalid SLIP-0019 proof: witness is not empty for p2pkh')

        # Extract the DER signature and the public key from the scriptSig
        der_sig, pubkey = slip19_parse_scriptsig(scriptsig, addr_fmt)

        # Hash the public key and check that it matches the hash in the scriptPubKey
        if hash != hash160(pubkey):
            raise ValueError('Invalid SLIP-0019 proof: public key doesn\'t match the hash in the scriptPubKey')

        # Verify the signature
        if not verify_all_recid(pubkey, sighash, der_sig):
            raise ValueError('Invalid SLIP-0019 proof: invalid signature for p2pkh')

    elif addr_fmt == AF_P2WPKH_P2SH:
        # Check that both the scriptSig and the witness are not empty
        if len(scriptsig) == 0:
            raise ValueError('Invalid SLIP-0019 proof: scriptsig is empty for p2sh-p2wpkh')
        if witness == b'\x00':
            raise ValueError('Invalid SLIP-0019 proof: witness is empty for p2sh-p2wpkh')

        # Check that the hash of the redeemScript in the scriptSig matches the hash in the scriptPubKey
        if hash != hash160(scriptsig[1:]):
            raise ValueError('Invalid SLIP-0019 proof: redeem script doesn\'t match the hash in the scriptPubKey')

        # Extract the DER signature and the public key from the witness
        sigs, pubkeys, _ = slip19_parse_witness(witness)
        der_sig = sigs[0]
        pubkey = pubkeys[0]

        # Extract the pubkey_hash from the scriptsig
        pubkey_hash = slip19_parse_scriptsig(scriptsig, addr_fmt)

        # Hash the public key and check that it matches the hash in the scriptPubKey
        if pubkey_hash != hash160(pubkey):
            raise ValueError('Invalid SLIP-0019 proof: public key doesn\'t match the hash in the scriptPubKey')

        # Verify the signature
        if not verify_all_recid(pubkey, sighash, der_sig):
            raise ValueError('Invalid SLIP-0019 proof: invalid signature for p2sh-p2wpkh')

    elif addr_fmt == AF_P2WPKH:
        # Check that the scriptsig is empty and witness is not empty.
        if len(scriptsig) != 0:
            raise ValueError('Invalid SLIP-0019 proof: scriptsig is not empty for p2wpkh')
        if witness == b'\x00':
            raise ValueError('Invalid SLIP-0019 proof: witness is empty for p2wpkh')

        # Extract the DER signature and the public key from the witness
        sigs, pubkeys, _ = slip19_parse_witness(witness)
        der_sig = sigs[0]
        pubkey = pubkeys[0]

        # Hash the public key from the witness and check that it matches the hash in the scriptPubKey
        if hash != hash160(pubkey):
            raise ValueError('Invalid SLIP-0019 proof: public key doesn\'t match the hash in the scriptPubKey')

        # Verify the signature
        if not verify_all_recid(pubkey, sighash, der_sig):
            raise ValueError('Invalid SLIP-0019 proof: invalid signature for p2wpkh')

    elif addr_fmt == AF_P2WSH:
        # Check that the scriptsig is empty and witness is not empty.
        if len(scriptsig) != 0:
            raise ValueError('Invalid SLIP-0019 proof: scriptsig is not empty for p2wpkh')
        if witness == b'\x00':
            raise ValueError('Invalid SLIP-0019 proof: witness is empty for p2wpkh')

        # Extract the DER signature and the public key from the witness
        sigs, _, redeem_script = slip19_parse_witness(witness)

        # Check that the hash of the redeem script matches the hash in the scriptPubKey
        if hash != sha256(redeem_script):
            raise ValueError('Invalid SLIP-0019 proof: redeem script doesn\'t match the hash in the scriptPubKey')

        # Extract the pubkeys from the redeem script
        m, pubkeys = slip19_parse_redeem_script_multisig(redeem_script)

        # Verify the signatures and that there are enough of them
        valid_sigs_count = 0
        for s in sigs:
            for pk in pubkeys:
                if verify_all_recid(pk, sighash, s):
                    valid_sigs_count += 1
                    break
                continue
            if valid_sigs_count == m:
                break

        if valid_sigs_count < m:
            raise ValueError('Invalid SLIP-0019 proof: not enough valid signatures for p2wsh')

    else:
        raise ValueError('Invalid SLIP-0019 proof: unknown address format')

def slip19_check_ownership(proof, script_pubkey, commitment_data):
    # Given the proof and the footer, confirm the signature and tells if the UTXO is ours or not

    # Parse the proof_of_ownership
    n, _, ownership_ids, scriptsig, witness = slip19_deserialize_proof(proof)
    proof_body = proof[:n]

    # Serialize the footer
    footer = slip19_serialize_footer(script_pubkey, commitment_data)

    # Compute the sighash
    sighash = slip19_compute_sighash(proof_body, footer)

    # Verify the signature contained in the proof
    try:
        slip19_verify_signature(script_pubkey, sighash, scriptsig, witness)
    except ValueError as e:
        assert False, "Failed to verify signature: %s" % (e)

    # Compute our ownership id for the given script_pubkey
    validator_ownership_key = slip19_ownership_key()
    validator_ownership_id = slip19_ownership_id(validator_ownership_key, script_pubkey)

    # If our ownership id is in the list, then we own the UTXO
    return validator_ownership_id in ownership_ids

def slip19_parse_scriptsig(scriptsig, addr_fmt):
    with BytesIO(scriptsig) as fd:
        if addr_fmt == AF_CLASSIC:
            der_sig = deser_string(fd)
            pubkey = deser_string(fd)

            return der_sig, pubkey
        elif addr_fmt == AF_P2WPKH_P2SH:
            if deser_compact_size(fd) != 22:
                raise ValueError('Invalid SLIP-0019 proof: invalid scriptsig length for p2sh-p2wpkh')
            if fd.read(1) != b'\x00':
                raise ValueError('Invalid SLIP-0019 proof: invalid witness version for p2sh-p2wpkh')

            pubkey_hash = deser_string(fd)

            return pubkey_hash
        else:
            raise NotImplementedError('Invalid SLIP-0019 proof: unknown address format')

def slip19_parse_witness(witness):
    with BytesIO(witness) as fd:
        stack_size = deser_compact_size(fd)
        sigs = []
        pubkeys = []
        script = b''

        for i in range(stack_size):
            if stack_size > 2 and i == 0: # p2wsh, the first element is the witness version
                if fd.read(1) != b'\x00':
                    raise ValueError('Invalid SLIP-0019 proof: invalid witness version for p2wsh')
                continue

            stack_item = deser_string(fd)
            if stack_item[0] == 0x30:
                sigs.append(stack_item)
            elif stack_item[0] == 0x02 or stack_item[0] == 0x03:
                pubkeys.append(stack_item)
            else:
                script = stack_item

    return sigs, pubkeys, script

def slip19_parse_redeem_script_multisig(redeem_script):
    # Parse the redeem script of a p2wsh multisig
    # It should be of the form:
    # <m> <pubkey1> <pubkey2> ... <pubkeyn> <n> OP_CHECKMULTISIG

    with BytesIO(redeem_script) as fd:
        # Parse the minimum required signatures
        m = int.from_bytes(fd.read(1), 'little') - 80

        # Go back two bytes from the end and parse the total number of pubkeys
        fd.seek(-2, 2) # 2 = SEEK_END
        n = int.from_bytes(fd.read(1), 'little') - 80

        if m > n:
            raise ValueError('Invalid SLIP-0019 proof: invalid redeem script with m > n')

        # Go back to the beginning of the redeem script
        fd.seek(1)

        # We should find n pubkeys
        pubkeys = []
        while len(pubkeys) < n:
            p = deser_string(fd)

            if p[0] == 0x02 or p[0] == 0x03:
                pubkeys.append(p)
            else:
                raise ValueError('Invalid SLIP-0019 proof: Found non-public key in redeem script')

        # Now, we should find the n value then OP_CHECKMULTISIG
        if int.from_bytes(fd.read(1), 'little') - 80 != n:
            raise ValueError('Invalid SLIP-0019 proof: invalid redeem script (too many pubkeys?)')
        if fd.read(1) != b'\xae':
            raise ValueError('Invalid SLIP-0019 proof: invalid redeem script (no OP_CHECKMULTISIG))')
        if fd.read(1) != b'':
            raise ValueError('Invalid SLIP-0019 proof: invalid redeem script (something after OP_CHECKMULTISIG))')

    return m, pubkeys
