from utils import to_little_endian, to_compact_size


def wtxid_serialize(txn_data):
    txn_hash = ""
    data = txn_data
    # Version
    txn_hash += f"{to_little_endian(data['version'], 4)}"
    # Marker+flags (if any `vin` has empty scriptsig)
    if any(i.get("scriptsig") == "" for i in data["vin"]):
        txn_hash += "0001"
    # No. of inputs:
    txn_hash += f"{str(to_compact_size(len(data['vin'])))}"
    # Inputs
    for iN in data["vin"]:
        txn_hash += f"{bytes.fromhex(iN['txid'])[::-1].hex()}"
        txn_hash += f"{to_little_endian(iN['vout'], 4)}"
        txn_hash += f"{to_compact_size(len(iN['scriptsig'])//2)}"
        txn_hash += f"{iN['scriptsig']}"
        txn_hash += f"{to_little_endian(iN['sequence'], 4)}"

    # No. of outputs
    txn_hash += f"{str(to_compact_size(len(data['vout'])))}"

    # Outputs
    for out in data["vout"]:
        txn_hash += f"{to_little_endian(out['value'], 8)}"
        txn_hash += f"{to_compact_size(len(out['scriptpubkey'])//2)}"
        txn_hash += f"{out['scriptpubkey']}"

    # witness
    for i in data["vin"]:
        if "witness" in i and i["witness"]:
            txn_hash += f"{to_compact_size(len(i['witness']))}"
            for j in i["witness"]:
                txn_hash += f"{to_compact_size(len(j) // 2)}"
                txn_hash += f"{j}"

    # Locktime
    txn_hash += f"{to_little_endian(data['locktime'], 4)}"
    return txn_hash
