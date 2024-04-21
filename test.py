import json

# Load JSON file with custom decoder
with open("mempool/ffffd30049f660eb4b4e3a6bddd758d0a2f19c8a194d640669baf31ada092525.json", "r") as f:
    tx_dict = json.load(f)


def serialize_tx(tx_dict):
    """
    Serialize a transaction dictionary into a hexadecimal string.
    """
    # Convert version to little-endian hex
    tx_hex = tx_dict["version"].to_bytes(4, byteorder="little").hex()

    # Add input count
    tx_hex += len(tx_dict["vin"]).to_bytes(1, byteorder="little").hex()

    # Serialize inputs
    for inp in tx_dict["vin"]:
        tx_hex += bytes.fromhex(inp["txid"])[::-1].hex()  # Reverse txid
        tx_hex += inp["vout"].to_bytes(4, byteorder="little").hex()
        tx_hex += format(len(inp["scriptsig"]) // 2, "x").zfill(2)  # scriptsig size
        tx_hex += inp["scriptsig"]
        tx_hex += format(len(inp["witness"]), "x").zfill(2)  # witness stack size
        for wit in inp["witness"]:
            tx_hex += format(len(wit) // 2, "x").zfill(2)  # witness item size
            tx_hex += wit
        tx_hex += inp["sequence"].to_bytes(4, byteorder="little").hex()

    # Add output count
    tx_hex += len(tx_dict["vout"]).to_bytes(1, byteorder="little").hex()

    # Serialize outputs
    for out in tx_dict["vout"]:
        tx_hex += out["value"].to_bytes(8, byteorder="little").hex()
        tx_hex += format(len(out["scriptpubkey"]) // 2, "x").zfill(2)  # scriptPubKey size
        tx_hex += out["scriptpubkey"]

    # Add locktime
    tx_hex += tx_dict["locktime"].to_bytes(4, byteorder="little").hex()

    return tx_hex


print(serialize_tx(tx_dict))
