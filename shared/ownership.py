#
# ownership.py - Proof of Ownership (SLIP-0019)
#
import ngu
from serializations import ser_compact_size, ser_sig_der, deser_compact_size, SIGHASH_ALL, ser_string, deser_string
from chains import AF_P2WPKH, AF_CLASSIC, AF_P2WPKH_P2SH
from uio import BytesIO

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
    if (n*32) < len(proof_body[5+len(ser_compact_size(n)):]):
        raise ValueError('Varint too low')
    if (n*32) > len(proof_body[5+len(ser_compact_size(n)):]):
        raise ValueError('Varint too high')
    ownership_ids = []
    for i in range(n):
        ownership_ids.append(proof_body[5 + len(ser_compact_size(n)) + (i * 32):5 + len(ser_compact_size(n)) + (i * 32) + 32])

    return user_confirmation, ownership_ids

def slip19_parse_proof_footer(proof_footer):
    # Parse the footer of a SLIP-0019 proof of ownership.

    script_pubkey = deser_string(BytesIO(proof_footer))
    commitment_data = deser_string(BytesIO(proof_footer[len(ser_string(script_pubkey)):]))

    return script_pubkey, commitment_data

def slip19_signing_protocol(master_seed, node, proof_body, proof_footer):
    # The signing protocol of a SLIP-0019 proof of ownership.

    # Parse the proof body.
    user_confirmation, ownership_ids = slip19_parse_proof_body(proof_body)

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
    der_sig = recoverable_to_der(sig)
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
        sigs += ser_string(recoverable_to_der(s))

    scriptsig = b'\x00'

    proof_signature = scriptsig + nb_elements + sigs + ser_string(witness_script)

    return proof_body + proof_signature

# Utils
def recoverable_to_der(recoverable):
    sig_bytes = recoverable.to_bytes()
    r = sig_bytes[1:33]
    s = sig_bytes[33:65]
    return ser_sig_der(r, s, SIGHASH_ALL)

def der_to_recoverable(der_sig):
    try:
        assert der_sig[0] == '\x30'
        der_sig = der_sig[1:]
    except AssertionError:
        raise

    total_len = deser_compact_size(der_sig[0])
    if total_len != len(der_sig):
        raise Exception("Truncated der sig")

    der_sig = der_sig[1:]

    try:
        assert der_sig[0] == '\x02'
        der_sig = der_sig[1:]
    except AssertionError:
        raise

    r_len = deser_compact_size(der_sig[0])
    der_sig = der_sig[1:]
    r = der_sig[0:r_len]
    der_sig = der_sig[r_len+1:]

    try:
        assert der_sig[0] == '\x02'
        der_sig = der_sig[1:]
    except AssertionError:
        raise

    s_len = deser_compact_size(der_sig[0])
    der_sig = der_sig[1:]
    s = der_sig[0:s_len]

    try:
        assert der_sig[0] == '\x01'
    except AssertionError:
        raise

    return r, s