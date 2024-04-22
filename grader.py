from block import generate_merkle_root
from utils import to_reverse_bytes_string, to_hash256
import json

WITNESS_RESERVED_VALUE_HEX = '0000000000000000000000000000000000000000000000000000000000000000'
WTXID_COINBASE = bytes(32).hex()


def calculate_witness_commitment(wtxids):
    """
    Calculate the witness commitment of the transactions in the block.
    """
    witness_root = generate_merkle_root(wtxids)

    # Convert the WITNESS_RESERVED_VALUE to hex string
    witness_reserved_value_hex = WITNESS_RESERVED_VALUE_HEX

    # Concatenate the witness root and the witness reserved value
    combined_data = witness_root + witness_reserved_value_hex

    # Calculate the hash (assuming hash256 is a function that hashes data with SHA-256 twice)
    witness_commitment = to_hash256(combined_data)

    return witness_commitment


with open('output.txt', 'r') as file:
    # Read the contents of the file and split it into lines
    lines = file.readlines()
    txids = lines[2:]

coinbase_less_txids = txids[1:]
wtxids = [WTXID_COINBASE]
for each in coinbase_less_txids:
    each = each.strip()
    with open(f'valid-mempool/{each}.json', 'r') as file:
        data = json.load(file)
        wtxids.append(to_reverse_bytes_string(to_hash256(data.get('hex'))))


print(calculate_witness_commitment(wtxids))
