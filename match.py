import os
import json
from utils import to_reverse_bytes_string, to_hash256
from wtxid import wtxid_serialize
from txid import serialize_txn

MEMPOOL_DIR = "mempool"

matched = 0
unmatched = 0
valid_transactions = []


def read_transaction_file(filename):
    """
    Read a JSON transaction file and return the transaction data.
    """
    global matched, unmatched
    with open(os.path.join(MEMPOOL_DIR, filename), "r") as file:
        transaction = json.load(file)
    wtxid = to_reverse_bytes_string(to_hash256(wtxid_serialize(transaction)))
    txid = to_reverse_bytes_string(to_hash256(serialize_txn(transaction)))

    with open(f"valid-mempool/{txid}.json", "r") as file:
        valid_txn = json.load(file)
        valid_wtxid = to_reverse_bytes_string(to_hash256(valid_txn.get("hex")))

    # print(True if transaction["wtxid"] == valid_wtxid else print("not match ******"))
    if wtxid == valid_wtxid:
        print("Matched", wtxid == valid_wtxid)
        matched += 1
        valid_transactions.append(transaction)
    else:
        print("Not Matched", filename, wtxid, valid_wtxid)
        unmatched += 1
    return transaction


def main():
    # Read transaction files
    transactions = []
    valid_mempool = set(json.load(open("valid-mempool.json")))
    counter = 0
    for filename in os.listdir(MEMPOOL_DIR):
        transaction = read_transaction_file(filename)
        if transaction.get('txid') in valid_mempool:
            transactions.append(transaction)
            print(tx)
            counter += 1
    print(f"Total transactions: {counter}")


if __name__ == "__main__":
    main()
    print(f"Matched: {matched}, Unmatched: {unmatched}")
    with open('valid-cache.json', 'w') as file:
        json.dump(valid_transactions, file, indent=4)
