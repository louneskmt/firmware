#
# ownership.py - Proof of Ownership (SLIP-0019)
#
import ngu
from serializations import CTxOut, ser_compact_size, ser_sig_der, deser_compact_size, SIGHASH_ALL, ser_string, deser_string, hash160, sha256
from chains import verify_recover_pubkey, AF_P2WPKH, AF_CLASSIC, AF_P2WPKH_P2SH, AF_P2WSH
from uio import BytesIO
from utils import parse_addr_fmt_str

# SLIP-0021 - Symmetric Key Derivation for HD Wallets
# See https://github.com/satoshilabs/slips/blob/master/slip-0021.md

def slip21_child_node(N, label):
    # Derive a SLIP-0021 child node from a parent node.
    return ngu.hmac.hmac_sha512(N[0:32], b'\x00' + label)

def slip21_node_key(N):
    # Returns the node key from a SLIP-0021 node.
    return N[32:64]

def slip21_master_node(master_seed):
    # Derive SLIP-0021 master node from a BIP-0032 master node.
    return ngu.hmac.hmac_sha512(b'Symmetric key seed', master_seed)

def slip21_parse_path(path):
    if(path == 'm'):
        return []
    # remove m/ prefix
    path = path[2:]
    # split on /
    path = path.split('/')
    # remove quotes and return
    return [i[1:-1] for i in path]

def slip21_key_from_bip32_master_seed(master_seed, path):
    # Derive a SLIP-0021 key from a BIP-0032 master node and a label.

    N = slip21_master_node(master_seed)
    labels = slip21_parse_path(path)

    if labels:
        for label in labels:
          N = slip21_child_node(N, label)

    return slip21_node_key(N)

# SLIP-0019 - Proof of Ownership
# See https://github.com/satoshilabs/slips/blob/master/slip-0019.md

SLIP19_VERSION_MAGIC = b'\x53\x4c\x00\x19'
SLIP19_OWNERSHIP_ID_PATH ='m/"SLIP-0019"/"Ownership identification key"'

def slip19_ownership_key(master_seed):
    # Derive a SLIP-0019 ownership key from a BIP-0032 master seed
    return slip21_key_from_bip32_master_seed(master_seed, SLIP19_OWNERSHIP_ID_PATH)

def slip19_ownership_id(ownership_key, script_pubkey):
    # Derive a SLIP-0019 ownership ID from a SLIP-0019 ownership key and a scriptPubKey.
    return ngu.hmac.hmac_sha256(ownership_key, script_pubkey)

def slip19_compile_proof_body(ownership_ids, user_confirmation):
    # Compile the body of a SLIP-0019 proof of ownership.

    uc_bit = 1 if user_confirmation else 0
    reserved_bits = [0] * 7

    flags = (uc_bit << 0) | (reserved_bits[0] << 1) | (reserved_bits[1] << 2) | (reserved_bits[2] << 3) | (reserved_bits[3] << 4) | (reserved_bits[4] << 5) | (reserved_bits[5] << 6) | (reserved_bits[6] << 7)
    flag_byte = bytes([flags])

    n = ser_compact_size(len(ownership_ids))
    ids = b''.join(ownership_ids)

    return SLIP19_VERSION_MAGIC + flag_byte + n + ids

def slip19_compile_proof_footer(script_pubkey, commitment_data):
    # Compile the footer of a SLIP-0019 proof of ownership.
    return ser_string(script_pubkey) + ser_string(commitment_data)

def slip19_compile_sighash(proof_body, proof_footer):
    # Compile the sighash of a SLIP-0019 proof of ownership.
    return ngu.hash.sha256s(proof_body + proof_footer)

def slip19_parse_proof_signature(proof):
    # Parse the signature of a SLIP-0019 proof of ownership.
    scriptsig_len = deser_compact_size(BytesIO(proof[0:]))

    if scriptsig_len is not 0:
        scriptsig = deser_string(BytesIO(proof[0:]))
    else:
        scriptsig = b''

    offset = len(ser_compact_size(scriptsig_len)) + scriptsig_len
    witness_el = deser_compact_size(BytesIO(proof[offset:]))

    if witness_el is not 0:
        witness = proof[offset:]
    else:
        witness = b''

    if scriptsig_len == witness_el == 0:
        raise ValueError("SLIP-0019 proof of ownership must be signed")

    return scriptsig, witness

def slip19_parse_proof_body(proof_body):
    # Parse the body of a SLIP-0019 proof of ownership.
    if proof_body[0:4] != SLIP19_VERSION_MAGIC:
        raise ValueError('Invalid SLIP-0019 proof body: invalid version magic')

    flags = proof_body[4]
    user_confirmation = (flags & 0x01) != 0
    reserved_bits = [(flags & 0x02) != 0, (flags & 0x04) != 0, (flags & 0x08) != 0, (flags & 0x10) != 0, (flags & 0x20) != 0, (flags & 0x40) != 0, (flags & 0x80) != 0]
    # Other flags are not defined for now, raise Exception if one of them is true
    if any(reserved_bits):
        raise ValueError('Invalid flag set to true')

    n = deser_compact_size(BytesIO(proof_body[5:]))
    ownership_ids = []
    for i in range(n):
        ownership_ids.append(proof_body[5 + len(ser_compact_size(n)) + (i * 32):5 + len(ser_compact_size(n)) + (i * 32) + 32])

    return 5 + len(ser_compact_size(n)) + n*32, user_confirmation, ownership_ids

def slip19_parse_proof_ownership(proof: bytes) -> Tuple[bool, bytes, bytes, bytes]:
    n, user_confirmation, ownership_ids = slip19_parse_proof_body(proof)
    scriptsig, witness = slip19_parse_proof_signature(proof[n:])

    return n, user_confirmation, ownership_ids, scriptsig, witness

def slip19_parse_proof_footer(proof_footer):
    # Parse the footer of a SLIP-0019 proof of ownership.

    script_pubkey = deser_string(BytesIO(proof_footer))
    commitment_data = deser_string(BytesIO(proof_footer[len(ser_string(script_pubkey)):]))

    return script_pubkey, commitment_data

def slip19_signing_protocol(master_seed, node, proof_body, proof_footer):
    # The signing protocol of a SLIP-0019 proof of ownership.

    # Parse the proof body.
    _, user_confirmation, ownership_ids = slip19_parse_proof_body(proof_body)

    # Derive the ownership key.
    ownership_key = slip19_ownership_key(master_seed)

    # Parse the proof footer.
    script_pubkey, commitment_data = slip19_parse_proof_footer(proof_footer)

    # Derive the ownership ID.
    ownership_id = slip19_ownership_id(ownership_key, script_pubkey)

    # Check that the ownership ID is in the proof body.
    if ownership_id not in ownership_ids:
        raise ValueError('Invalid SLIP-0019 proof body: ownership ID not found')

    # Compute the sighash.
    sighash = slip19_compile_sighash(proof_body, proof_footer)

    # Sign the sighash.
    return slip19_sign_proof(node, sighash)


def slip19_sign_proof(node, sighash):
    # Sign a SLIP-0019 proof of ownership.
    return ngu.secp256k1.sign(node.privkey(), sighash, 0)

def slip19_produce_proof(node, addr_fmt, sig):
    der_sig, _ = recoverable_to_der(sig)
    if addr_fmt == AF_CLASSIC:
        scriptsig = ser_string(der_sig) + ser_string(node.pubkey())
        witness = b'\x00'
    elif addr_fmt == AF_P2WPKH_P2SH:
        redeem_script = b'\x00\x14' + ngu.hash.hash160(node.pubkey())
        scriptsig = ser_string(redeem_script)
        witness = b'\x02' + ser_string(der_sig) + ser_string(node.pubkey())
    elif addr_fmt == AF_P2WPKH:
        scriptsig = b''
        witness = b'\x02' + ser_string(der_sig) + ser_string(node.pubkey())

    return ser_string(scriptsig) + witness

def slip19_create_multisig_proof(proof_body: bytes, signatures: list, witness_script: bytes):
    nb_elements = (len(signatures) + 2).to_bytes(1, 'big')
    sigs = b'\x00'
    for s in signatures:
        sig, _ = recoverable_to_der(s)
        sigs += ser_string(sig)

    scriptsig = b'\x00'

    proof_signature = scriptsig + nb_elements + sigs + ser_string(witness_script)

    return proof_body + proof_signature

def slip19_verify_signature(spk, sighash, scriptsig=None, witness=None):
    # see https://github.com/bitcoin/bips/blob/f9e95849f337358cd89c83b948fbede3875481c3/bip-0322.mediawiki#user-content-Verifying
    def verify_all_recid(pubkey, sighash, der_sig):
        # As we can't recover the recid, we need to try all 4 possibilities
        # if one pubkey we recover matches the pubkey we expect, we return True
        for recid in range(4):
            sig = der_to_recoverable(der_sig, recid)
            try:
                _, r_pubkey = verify_recover_pubkey(sig, sighash)
            except ValueError: # it can happen with multisig, we don't care
                break
            if r_pubkey == pubkey:
                return True
        return False

    # We need a signature, scriptsig and witness can't be both empty
    if len(scriptsig) == 0 and len(witness) == 0:
        raise ValueError('Invalid SLIP-0019 proof: no signature provided')
    # Determine the address format using the scriptPubKey.
    txout = CTxOut(0, spk)
    af, hash, is_segwit = txout.get_address()
    if af is 'p2pkh' and is_segwit:
        af = 'p2wpkh'
    if af is 'p2sh' and is_segwit:
        af = 'p2wsh'
    if af is 'p2sh' and scriptsig[0] == 22 and scriptsig[1] == 0:
        af = 'p2sh-p2wpkh'
    addr_fmt = parse_addr_fmt_str(af)

    # Verify the signature.
    if addr_fmt == AF_CLASSIC:
        # Check that the scriptsig is not empty and witness is empty.
        if len(scriptsig) == 0:
            raise ValueError('Invalid SLIP-0019 proof: scriptsig is empty for p2pkh')
        if len(witness) != 0:
            raise ValueError('Invalid SLIP-0019 proof: witness is not empty for p2pkh')
        # extract the der signature and the pubkey from the scriptsig
        der_sig, pubkey = slip19_parse_scriptsig(scriptsig, addr_fmt)
        # hash the pubkey and check that it matches the hash in the scriptPubKey
        if hash != hash160(pubkey):
            raise ValueError('Invalid SLIP-0019 proof: pubkey doesn\'t match the hash in the scriptPubKey')
        if not verify_all_recid(pubkey, sighash, der_sig):
            raise ValueError('Invalid SLIP-0019 proof: invalid signature for p2pkh')
    elif addr_fmt == AF_P2WPKH_P2SH:
        # Check that both the scriptsig and the witness are not empty
        if len(scriptsig) == 0:
            raise ValueError('Invalid SLIP-0019 proof: scriptsig is empty for p2sh-p2wpkh')
        if len(witness) == 0:
            raise ValueError('Invalid SLIP-0019 proof: witness is empty for p2sh-p2wpkh')

        # check that the hash of the scriptsig matches the hash in the scriptPubKey
        if hash != hash160(scriptsig[1:]):
            raise ValueError('Invalid SLIP-0019 proof: redeem script doesn\'t match the hash in the scriptPubKey')
        # extract the der signature and the pubkey from the witness
        sigs, pubkeys, _ = slip19_parse_witness(witness)
        der_sig = sigs[0]
        pubkey = pubkeys[0]

        # extract the pubkey_hash from the scriptsig
        pubkey_hash = slip19_parse_scriptsig(scriptsig, addr_fmt)
        # hash the pubkey and check that it matches the hash in the scriptPubKey
        if pubkey_hash != hash160(pubkey):
            raise ValueError('Invalid SLIP-0019 proof: pubkey doesn\'t match the hash in the scriptPubKey')

        if not verify_all_recid(pubkey, sighash, der_sig):
            raise ValueError('Invalid SLIP-0019 proof: invalid signature for p2sh-p2wpkh')
    elif addr_fmt == AF_P2WPKH:
        # Check that the scriptsig is empty and witness is not empty.
        if len(scriptsig) != 0:
            raise ValueError('Invalid SLIP-0019 proof: scriptsig is not empty for p2wpkh')
        if len(witness) == 0:
            raise ValueError('Invalid SLIP-0019 proof: witness is empty for p2wpkh')
        # extract the der signature and the pubkey from the witness
        sigs, pubkeys, _ = slip19_parse_witness(witness)
        der_sig = sigs[0]
        pubkey = pubkeys[0]
        # hash the pubkey and check that it matches the hash in the scriptPubKey
        if hash != hash160(pubkey):
            raise ValueError('Invalid SLIP-0019 proof: pubkey doesn\'t match the hash in the scriptPubKey')
        if not verify_all_recid(pubkey, sighash, der_sig):
            raise ValueError('Invalid SLIP-0019 proof: invalid signature for p2wpkh')
    elif addr_fmt == AF_P2WSH:
        # Check that the scriptsig is empty and witness is not empty.
        if len(scriptsig) != 0:
            raise ValueError('Invalid SLIP-0019 proof: scriptsig is not empty for p2wpkh')
        if len(witness) == 0:
            raise ValueError('Invalid SLIP-0019 proof: witness is empty for p2wpkh')
        # extract the der signature and the pubkey from the witness
        sigs, _, redeem_script = slip19_parse_witness(witness)

        # check that the hash of the redeem script matches the hash in the scriptPubKey
        if hash != sha256(redeem_script):
            raise ValueError('Invalid SLIP-0019 proof: redeem script doesn\'t match the hash in the scriptPubKey')

        # extract the pubkeys from the redeem script
        n, pubkeys = slip19_parse_redeem_script(redeem_script)

        valid_sig = 0
        for s in sigs:
            for pk in pubkeys:
                if verify_all_recid(pk, sighash, s):
                    valid_sig += 1
                    break 
                continue
            if valid_sig == n:
                break
        
        if valid_sig < n:
            raise ValueError('Invalid SLIP-0019 proof: not enough valid signatures for p2wsh')

# Utils
def slip19_parse_scriptsig(scriptsig, addr_fmt):
    with BytesIO(scriptsig) as fd:
        if addr_fmt == AF_CLASSIC:
            der_sig = deser_string(fd)
            pubkey = deser_string(fd)
            return der_sig, pubkey
        elif addr_fmt == AF_P2WPKH_P2SH:
            total_len = deser_compact_size(fd)
            if total_len != 22:
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
            if stack_size > 2 and i == 0: # it's a p2wsh, the first element is the witness version
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

def slip19_parse_redeem_script(redeem_script):
    with BytesIO(redeem_script) as fd:
        n = int.from_bytes(fd.read(1), 'little') - 80
        # now go right to the end and look for the m value
        fd.seek(-2, 2)
        m = int.from_bytes(fd.read(1), 'little') - 80
        if n > m:
            raise ValueError('Invalid SLIP-0019 proof: invalid redeem script with n > m')
        fd.seek(1)
        pubkeys = []
        # we should find m pubkeys
        while len(pubkeys) < m:
            p = deser_string(fd)
            if p[0] == 0x02 or p[0] == 0x03:
                pubkeys.append(p)
            else:
                raise ValueError('Invalid SLIP-0019 proof: Found non-pubkey in redeem script')
        # now we should find the m value then OP_CHECKMULTISIG
        if int.from_bytes(fd.read(1), 'little') - 80 != m:
            raise ValueError('Invalid SLIP-0019 proof: invalid redeem script (too many pubkeys?)')
        if fd.read(1) != b'\xae':
            raise ValueError('Invalid SLIP-0019 proof: invalid redeem script (no OP_CHECKMULTISIG))')
        if fd.read(1) != b'':
            raise ValueError('Invalid SLIP-0019 proof: invalid redeem script (something after OP_CHECKMULTISIG))')
        return n, pubkeys 

def recoverable_to_der(recoverable: ngu.secp256k1.Sig) -> Tuple[bytes, int]:
    sig_bytes = recoverable.to_bytes()
    r = sig_bytes[1:33]
    s = sig_bytes[33:65]
    recid = int.from_bytes(sig_bytes[0:1], 'big') - 27 & 3
    return ser_sig_der(r, s, SIGHASH_ALL), recid

def der_to_recoverable(der_sig: bytes, recid: int = 0) -> bytes:
    with BytesIO(der_sig) as fd:
        try:
            assert fd.read(1) == b'\x30'
        except AssertionError:
            raise ValueError("Invalid der sig: invalid header byte")

        total_len = deser_compact_size(fd)

        count = 0

        try:
            assert fd.read(1) == b'\x02'
        except AssertionError:
            raise ValueError("Invalid der sig: invalid int marker")

        count += 1

        r = deser_string(fd)

        count += len(ser_compact_size(len(r))) + len(r)

        try:
            assert fd.read(1) == b'\x02'
        except AssertionError:
            raise ValueError("Invalid der sig: invalid int marker")

        count += 1

        s = deser_string(fd)

        count += len(ser_compact_size(len(s))) + len(s)

        try:
            assert count == total_len
        except AssertionError:
            raise ValueError("Invalid der sig: invalid length")

        try:
            assert fd.read(1) == b'\x01'
        except AssertionError:
            raise ValueError("Not Sighash_all")

        while len(r) > 32 and r[0] == 0:
            r = r[1:]
        while len(s) > 32 and s[0] == 0:
            s = s[1:]

        prefix = 27 + 4 + recid
        return prefix.to_bytes(1, 'big') + r + s
