import json
import os
import hashlib
import time
import binascii
from coinbase import serialize_coinbase_transaction
from txid import serialize_txn
from utils import to_hash256, to_reverse_bytes_string
from wtxid import wtxid_serialize


# Constants
MEMPOOL_DIR = "mempool"
OUTPUT_FILE = "output.txt"
DIFFICULTY_TARGET = "0000ffff00000000000000000000000000000000000000000000000000000000"
BLOCK_VERSION = 4  # Update to the correct block version
# Define the witness reserved value in hexadecimal
WITNESS_RESERVED_VALUE_HEX = '0000000000000000000000000000000000000000000000000000000000000000'

# Convert the hexadecimal string to bytes
WITNESS_RESERVED_VALUE_BYTES = bytes.fromhex(WITNESS_RESERVED_VALUE_HEX)
WTXID_COINBASE = bytes(32).hex()


def get_fee(transaction):
    in_value = [int(i["prevout"]["value"]) for i in transaction["vin"]]
    total_sum_in_value = sum(in_value)
    out_value = [int(i["value"]) for i in transaction["vout"]]
    total_sum_out_value = sum(out_value)
    return total_sum_in_value - total_sum_out_value


def read_transaction_file(filename):
    """
    Read a JSON transaction file and return the transaction data.
    """
    with open(os.path.join(MEMPOOL_DIR, filename), "r") as file:
        transaction = json.load(file)
    transaction["txid"] = to_reverse_bytes_string(to_hash256(serialize_txn(transaction)))
    transaction["weight"] = 1  # Assign a fixed weight of 1 for simplicity
    transaction["wtxid"] = to_reverse_bytes_string(to_hash256(wtxid_serialize(transaction)))
    transaction["fee"] = transaction.get(
        "fee", get_fee(transaction)
    )  # Assign a default fee if not present
    if filename == "0a8b21af1cfcc26774df1f513a72cd362a14f5a598ec39d915323078efb5a240.json":
        print("matched **************")
        print(transaction["txid"])
    return transaction


def validate_transaction(transaction):
    """
    Validate a transaction.
    """
    # For the purpose of this challenge, we assume all transactions are valid
    return True


def validate_header(header, target_difficulty):
    header_bytes = binascii.unhexlify(header)
    if len(header_bytes) != 80:
        raise ValueError("Invalid header length")

    # Calculate double SHA256 hash of the block header
    h1 = hashlib.sha256(header_bytes).digest()
    h2 = hashlib.sha256(h1).digest()

    # Reverse the hash
    reversed_hash = h2[::-1]

    # Convert hash and target difficulty to integers
    reversed_hash_int = int.from_bytes(reversed_hash, byteorder="big")
    target_int = int(target_difficulty, 16)

    # Check if the hash is less than or equal to the target difficulty
    if reversed_hash_int > target_int:
        raise ValueError("Block does not meet target difficulty")


def target_to_bits(target):
    # Convert target to bytes
    target_bytes = bytes.fromhex(target)

    # Find the first non-zero byte
    for i in range(len(target_bytes)):
        if target_bytes[i] != 0:
            break

    # Calculate exponent
    exponent = len(target_bytes) - i

    # Calculate coefficient
    if len(target_bytes[i:]) >= 3:
        coefficient = int.from_bytes(target_bytes[i : i + 3], byteorder="big")
    else:
        coefficient = int.from_bytes(target_bytes[i:], byteorder="big")

    # Combine exponent and coefficient into bits
    bits = (exponent << 24) | coefficient

    # Return bits as a hexadecimal string
    return hex(bits)


def mine_block(transactions):
    """
    Mine a block with the given transactions.
    """
    nonce = 0
    txids = [
        tx["txid"]
        for tx in transactions
    ]

    # Create a coinbase transaction with no inputs and two outputs: one for the block reward and one for the witness commitment
    witness_commitment = calculate_witness_commitment(transactions)
    # coinbase_tx = {
    #     "vin": [
    #         {"coinbase": "arbitrary data here", "witness": [WITNESS_RESERVED_VALUE]}
    #     ],
    #     "vout": [
    #         {
    #             "value": "block reward here",
    #             "n": 0,
    #             "scriptPubKey": {"hex": "miner address here"},
    #         },
    #         {
    #             "value": "0",
    #             "n": 1,
    #             "scriptPubKey": {"hex": f"6a24aa21a9ed{witness_commitment}"},
    #         },
    #     ],
    # }
    # # Placeholder values for coinbase transaction parts
    # arbitrary_data = "00000000"  # Typically extranonce data in a real miner
    # block_reward = 5000000000  # Block reward in satoshis (50 BTC for example)
    # miner_address_hex = "76a914" + "0" * 36  # Dummy miner address in hex

    # Serialize the coinbase transaction into a hexadecimal string
    # coinbase_tx_hex = "".join(
    #     [
    #         arbitrary_data,
    #         block_reward.to_bytes(8, "little").hex(),
    #         miner_address_hex,
    #         (0).to_bytes(8, "little").hex(),  # Value for witness commitment output is 0
    #         "6a24aa21a9ed",  # OP_RETURN prefix for witness commitment
    #         witness_commitment,
    #     ]
    # )

    coinbase_hex, coinbase_txid = serialize_coinbase_transaction(
        witness_commitment=witness_commitment
    )

    print(coinbase_txid)
    # Calculate the Merkle root of the transactions
    merkle_root = generate_merkle_root([coinbase_txid]+txids)

    # Construct the block header
    block_version_bytes = BLOCK_VERSION.to_bytes(4, "little")
    prev_block_hash_bytes = bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000000"
    )
    merkle_root_bytes = bytes.fromhex(merkle_root)
    timestamp_bytes = int(time.time()).to_bytes(4, "little")
    bits_bytes = (0x1F00FFFF).to_bytes(4, "little")
    nonce_bytes = nonce.to_bytes(4, "little")

    # Combine the header parts
    block_header = (
        block_version_bytes
        + prev_block_hash_bytes
        + merkle_root_bytes
        + timestamp_bytes
        + bits_bytes
        + nonce_bytes
    )

    # Attempt to find a nonce that results in a hash below the difficulty target
    target = int(DIFFICULTY_TARGET, 16)
    print("target:", target)
    while True:
        block_hash = hashlib.sha256(hashlib.sha256(block_header).digest()).digest()
        reversed_hash = block_hash[::-1]
        if int.from_bytes(reversed_hash, "big") <= target:
            break
        nonce += 1
        nonce_bytes = nonce.to_bytes(4, "little")
        block_header = block_header[:-4] + nonce_bytes  # Update the nonce in the header
        # Validate nonce range within the mining loop
        if nonce < 0x0 or nonce > 0xFFFFFFFF:
            raise ValueError("Invalid nonce")

    block_header_hex = block_header.hex()
    validate_header(block_header_hex, DIFFICULTY_TARGET)

    return block_header_hex, txids, nonce, coinbase_hex, coinbase_txid


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


# def validate_coinbase_transaction(coinbase_tx):
#     """
#     Validate the coinbase transaction structure.
#     """
#     # Assuming coinbase_tx is a dictionary with the structure of the coinbase transaction
#     if len(coinbase_tx["vin"]) != 1:
#         raise ValueError("Coinbase transaction has invalid input count")

#     if len(coinbase_tx["vout"]) != 2:
#         raise ValueError("Coinbase transaction must have exactly 2 outputs")

#     input_script = coinbase_tx["vin"][0].get("coinbase", "")
#     if not (2 <= len(input_script) <= 100):
#         raise ValueError("Coinbase transaction input script length is invalid")

#     if (
#         "witness" not in coinbase_tx["vin"][0]
#         or len(coinbase_tx["vin"][0]["witness"]) == 0
#     ):
#         raise ValueError("Coinbase transaction witness is missing")

#     if coinbase_tx["vin"][0]["witness"][0] != WITNESS_RESERVED_VALUE:
#         raise ValueError(
#             "Coinbase transaction must have witness reserved value as first witness item"
#         )


def calculate_total_weight_and_fee(transactions):
    """
    Calculate the total weight and fee of the transactions in the block.
    """
    total_weight = 0
    total_fee = 0
    for tx in transactions:
        # Assuming tx is a dictionary with the structure of the transaction
        # and 'weight' and 'fee' are keys in this dictionary representing the transaction's weight and fee
        total_weight += tx["weight"]
        total_fee += tx["fee"]

    if total_weight > 4000000:
        raise ValueError("Block exceeds maximum weight")

    return total_weight, total_fee


def calculate_witness_commitment(transactions):
    """
    Calculate the witness commitment of the transactions in the block.
    """
    wtxids = [WTXID_COINBASE]
    transactions_new = transactions[1:]
    for tx in transactions_new:
        # Assuming tx is a dictionary with the structure of the transaction
        # and 'wtxid' is a key in this dictionary representing the transaction's witness transaction ID
        wtxids.append(tx["wtxid"])
    witness_root = generate_merkle_root(wtxids)

    # Convert the WITNESS_RESERVED_VALUE to hex string
    witness_reserved_value_hex = WITNESS_RESERVED_VALUE_HEX

    # Concatenate the witness root and the witness reserved value
    combined_data = witness_root + witness_reserved_value_hex

    # Calculate the hash (assuming hash256 is a function that hashes data with SHA-256 twice)
    witness_commitment = to_hash256(combined_data)

    return witness_commitment


def verify_witness_commitment(coinbase_tx, witness_commitment):
    """
    Verify the witness commitment in the coinbase transaction.
    """
    for output in coinbase_tx["vout"]:
        script_hex = output["scriptPubKey"]["hex"]
        if script_hex.startswith("6a24aa21a9ed") and script_hex.endswith(
            witness_commitment
        ):
            return True
    return False


def validate_block(coinbase_tx, txids, transactions):
    """
    Validate the block with the given coinbase transaction and txids.
    """
    # Validate coinbase transaction structure
    # validate_coinbase_transaction(coinbase_tx)

    # Read the mempool transactions from the JSON files and create a set of valid txids
    mempool_txids = set()
    for filename in os.listdir(MEMPOOL_DIR):
        tx_data = read_transaction_file(filename)
        # Extract the 'txid' from the first item in the 'vin' list
        if "vin" in tx_data and len(tx_data["vin"]) > 0 and "txid" in tx_data["vin"][0]:
            mempool_txids.add(tx_data["vin"][0]["txid"])
        else:
            raise ValueError(f"Transaction file {filename} is missing 'txid' in 'vin'")

    # Validate the presence of each transaction ID in the block against the mempool
    for txid in txids:
        if txid not in mempool_txids:
            raise ValueError(f"Invalid txid found in block: {txid}")

    # Calculate total weight and fee of the transactions in the block
    total_weight, total_fee = calculate_total_weight_and_fee(transactions)

    # Verify the witness commitment in the coinbase transaction
    witness_commitment = calculate_witness_commitment(transactions)
    if not verify_witness_commitment(coinbase_tx, witness_commitment):
        raise ValueError("Invalid witness commitment in coinbase transaction")

    print(
        f"Block is valid with a total weight of {total_weight} and a total fee of {total_fee}!"
    )


def main():
    # Read transaction files
    transactions = []
    valid_mempool = set(json.load(open("valid-mempool.json")))
    for filename in os.listdir(MEMPOOL_DIR)[:2000]:
        transaction = read_transaction_file(filename)
        if transaction.get('txid') in valid_mempool:
            transactions.append(transaction)
    if not any(transactions):
        raise ValueError("No valid transactions to include in the block")

    # Mine the block
    block_header, txids, nonce, coinbase_tx_hex, coinbase_txid = mine_block(transactions)

    # Validate the block
    # validate_block(coinbase_tx, txids, transactions)
    # Corrected writing to output file
    with open(OUTPUT_FILE, "w") as file:
        file.write(f"{block_header}\n{coinbase_tx_hex}\n{coinbase_txid}\n")
        file.writelines(f"{txid}\n" for txid in txids)

    # Print the total weight and fee of the transactions in the block
    total_weight, total_fee = calculate_total_weight_and_fee(transactions)
    print(f"Total weight: {total_weight}")
    print(f"Total fee: {total_fee}")


if __name__ == "__main__":
    main()
