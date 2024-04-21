import hashlib
from utils import to_hash256


WITNESS_RESERVED_VALUE_HEX = '0000000000000000000000000000000000000000000000000000000000000000'


def hash256(hex):
    binary = bytes.fromhex(hex)
    hash1 = hashlib.sha256(binary).digest()
    hash2 = hashlib.sha256(hash1).digest()
    result = hash2.hex()
    return result


def generate_merkle_root(txids):
    if len(txids) == 0:
        return None

    # Reverse the txids
    level = [bytes.fromhex(txid)[::-1].hex() for txid in txids]

    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            if i + 1 == len(level):
                # In case of an odd number of elements, duplicate the last one
                pair_hash = hash256(level[i] + level[i])
            else:
                pair_hash = hash256(level[i] + level[i + 1])
            next_level.append(pair_hash)
        level = next_level
    return level[0]


def calculate_witness_commitment(wtxids):
    """
    Calculate the witness commitment of the transactions in the block.
    """
    witness_root = generate_merkle_root(wtxids)
    print(witness_root)
    # Convert the WITNESS_RESERVED_VALUE to hex string
    witness_reserved_value_hex = WITNESS_RESERVED_VALUE_HEX

    # Concatenate the witness root and the witness reserved value
    combined_data = witness_root + witness_reserved_value_hex

    # Calculate the hash (assuming hash256 is a function that hashes data with SHA-256 twice)
    witness_commitment = to_hash256(combined_data)

    return witness_commitment


s = " 0000000000000000000000000000000000000000000000000000000000000000 6440ffe0a58cbec4692d075bc74877cdf7554a25eee5a02fa6ff3bb55dbb0802 9e4fa066c9587e65845065a6b5ad02cbec6cfdad8b0158953dcee086ff420ffd 57661a181f4762861fc2bc5c6001c27b54e26992e845b4742a6f0f867609b2c2 "
print(calculate_witness_commitment(s.split()))
