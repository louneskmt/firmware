#
# ownership.py - Proof of Ownership (SLIP-0019)
#
import ngu
from serializations import ser_compact_size

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
    return length_prefixed_bytes(script_pubkey) + length_prefixed_bytes(commitment_data)

def slip19_compile_sighash(proof_body, proof_footer):
    # Compile the sighash of a SLIP-0019 proof of ownership.
    return ngu.hash.sha256s(proof_body + proof_footer)

# Utils
def length_prefixed_bytes(data):
    return ser_compact_size(len(data)) + data
