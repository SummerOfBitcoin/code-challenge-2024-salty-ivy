import json
import os
import hashlib
import time
import binascii


# Constants
MEMPOOL_DIR = "mempool"
OUTPUT_FILE = "output.txt"
DIFFICULTY_TARGET = "0000ffff00000000000000000000000000000000000000000000000000000000"
BLOCK_VERSION = 4  # Update to the correct block version
WITNESS_RESERVED_VALUE = (
    "0000000000000000000000000000000000000000000000000000000000000000"
)


def read_transaction_file(filename):
    """
    Read a JSON transaction file and return the transaction data.
    """
    with open(os.path.join(MEMPOOL_DIR, filename), "r") as file:
        transaction = json.load(file)
    transaction["weight"] = 1  # Assign a fixed weight of 1 for simplicity
    transaction["wtxid"] = hashlib.sha256(json.dumps(transaction).encode()).hexdigest()
    transaction["fee"] = transaction.get(
        "fee", 0
    )  # Assign a default fee if not present
    return transaction


def validate_transaction(transaction):
    """
    Validate a transaction.
    """
    # Placeholder for validation logic
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
        tx["vin"][0]["txid"]
        for tx in transactions
        if "vin" in tx and len(tx["vin"]) > 0 and "txid" in tx["vin"][0]
    ]

    # Create a coinbase transaction with no inputs and two outputs: one for the block reward and one for the witness commitment
    witness_commitment = calculate_witness_commitment(transactions)
    coinbase_tx = {
        "vin": [
            {"coinbase": "arbitrary data here", "witness": [WITNESS_RESERVED_VALUE]}
        ],
        "vout": [
            {
                "value": "block reward here",
                "n": 0,
                "scriptPubKey": {"hex": "miner address here"},
            },
            {
                "value": "0",
                "n": 1,
                "scriptPubKey": {"hex": f"6a24aa21a9ed{witness_commitment}"},
            },
        ],
    }
    # Placeholder values for coinbase transaction parts
    arbitrary_data = "00000000"  # Typically extranonce data in a real miner
    block_reward = 5000000000  # Block reward in satoshis (50 BTC for example)
    miner_address_hex = "76a914" + "0" * 36  # Dummy miner address in hex

    # Serialize the coinbase transaction into a hexadecimal string
    coinbase_tx_hex = "".join(
        [
            arbitrary_data,
            block_reward.to_bytes(8, "little").hex(),
            miner_address_hex,
            (0).to_bytes(8, "little").hex(),  # Value for witness commitment output is 0
            "6a24aa21a9ed",  # OP_RETURN prefix for witness commitment
            witness_commitment,
        ]
    )

    # Calculate the Merkle root of the transactions
    merkle_root = generate_merkle_root(txids)

    # Construct the block header
    block_version_bytes = BLOCK_VERSION.to_bytes(4, "little")
    prev_block_hash_bytes = bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000000"
    )
    merkle_root_bytes = bytes.fromhex(merkle_root)
    timestamp_bytes = int(time.time()).to_bytes(4, "little")
    bits_bytes = (0x1f00ffff).to_bytes(4, 'little')
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

    return block_header_hex, coinbase_tx, txids, nonce, coinbase_tx_hex


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


def validate_coinbase_transaction(coinbase_tx):
    """
    Validate the coinbase transaction structure.
    """
    # Assuming coinbase_tx is a dictionary with the structure of the coinbase transaction
    if len(coinbase_tx["vin"]) != 1:
        raise ValueError("Coinbase transaction has invalid input count")

    if len(coinbase_tx["vout"]) != 2:
        raise ValueError("Coinbase transaction must have exactly 2 outputs")

    input_script = coinbase_tx["vin"][0].get("coinbase", "")
    if not (2 <= len(input_script) <= 100):
        raise ValueError("Coinbase transaction input script length is invalid")

    if (
        "witness" not in coinbase_tx["vin"][0]
        or len(coinbase_tx["vin"][0]["witness"]) == 0
    ):
        raise ValueError("Coinbase transaction witness is missing")

    if coinbase_tx["vin"][0]["witness"][0] != WITNESS_RESERVED_VALUE:
        raise ValueError(
            "Coinbase transaction must have witness reserved value as first witness item"
        )


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
    wtxids = []
    for tx in transactions:
        # Assuming tx is a dictionary with the structure of the transaction
        # and 'wtxid' is a key in this dictionary representing the transaction's witness transaction ID
        wtxids.append(tx["wtxid"])

    # Calculate the witness root hash
    witness_root = generate_merkle_root(wtxids)
    # Concatenate the witness root with the witness reserved value and hash the result
    witness_commitment = hashlib.sha256(
        hashlib.sha256((witness_root + WITNESS_RESERVED_VALUE).encode()).digest()
    ).hexdigest()
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
    validate_coinbase_transaction(coinbase_tx)

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
    valid_mempool = set(json.load(open('valid-mempool.json')))
    print(len(valid_mempool))
    for filename in os.listdir(MEMPOOL_DIR):
        transaction = read_transaction_file(filename)
        if transaction.get('vin')[0].get('txid') in valid_mempool:
            transactions.append(transaction)

    if not any(transactions):
        raise ValueError("No valid transactions to include in the block")

    # Mine the block
    block_header, coinbase_tx, txids, nonce, coinbase_tx_hex = mine_block(transactions)

    # Validate the block
    validate_block(coinbase_tx, txids, transactions)
    coinbase_tx_hex = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804233fa04e028b12ffffffff0130490b2a010000004341047eda6bd04fb27cab6e7c28c99b94977f073e912f25d1ff7165d9c95cd9bbe6da7e7ad7f2acb09e0ced91705f7616af53bee51a238b7dc527f2be0aa60469d140ac00000000"
    # Corrected writing to output file
    with open(OUTPUT_FILE, "w") as file:
        file.write(f"{block_header}\n{coinbase_tx_hex}\n")
        file.writelines(f"{txid}\n" for txid in txids)

    # Print the total weight and fee of the transactions in the block
    total_weight, total_fee = calculate_total_weight_and_fee(transactions)
    print(f"Total weight: {total_weight}")
    print(f"Total fee: {total_fee}")


if __name__ == "__main__":
    main()
