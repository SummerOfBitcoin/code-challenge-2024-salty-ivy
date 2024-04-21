import os
import json
import p2pkh
import hashlib
import coincurve


def validate_signature(signature, message, publicKey):
    b_sig = bytes.fromhex(signature)
    b_msg = bytes.fromhex(message)
    b_pub = bytes.fromhex(publicKey)
    return coincurve.verify_signature(b_sig, b_msg, b_pub)


def _to_compact_size(value):
    if value < 0xFD:
        return value.to_bytes(1, byteorder="little").hex()
    elif value <= 0xFFFF:
        return (0xFD).to_bytes(1, byteorder="little").hex() + value.to_bytes(
            2, byteorder="little"
        ).hex()
    elif value <= 0xFFFFFFFF:
        return (0xFE).to_bytes(1, byteorder="little").hex() + value.to_bytes(
            4, byteorder="little"
        ).hex()
    else:
        return (0xFF).to_bytes(1, byteorder="little").hex() + value.to_bytes(
            8, byteorder="little"
        ).hex()


def _little_endian(num, size):
    return num.to_bytes(size, byteorder="little").hex()


def segwit_txn_data(txn_id):
    file_path = os.path.join("mempool", f"{txn_id}.json")
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            data = json.load(f)
            ## Version
            ver = f"{_little_endian(data['version'], 4)}"

            ## (txid + vout)
            serialized_txid_vout = ""
            for iN in data["vin"]:
                serialized_txid_vout += f"{bytes.fromhex(iN['txid'])[::-1].hex()}"
                serialized_txid_vout += f"{_little_endian(iN['vout'], 4)}"
            # HASH256 (txid + vout)
            hash256_in = (
                hashlib.sha256(
                    hashlib.sha256(bytes.fromhex(serialized_txid_vout)).digest()
                )
                .digest()
                .hex()
            )

            ## (sequense)
            serialized_sequense = ""
            for iN in data["vin"]:
                serialized_sequense += f"{_little_endian(iN['sequence'], 4)}"
            ## HASH256 (sequense)
            hash256_seq = (
                hashlib.sha256(
                    hashlib.sha256(bytes.fromhex(serialized_sequense)).digest()
                )
                .digest()
                .hex()
            )

            ###############################################################################
            # TXN Specific #
            ## TXID and VOUT for the REQUIRED_input
            ser_tx_vout_sp = f"{bytes.fromhex(data['vin'][0]['txid'])[::-1].hex()}{_little_endian(data['vin'][0]['vout'], 4)}"
            print(ser_tx_vout_sp)
            ## Scriptcode
            pkh = f"{data['vin'][0]['prevout']['scriptpubkey'][4:]}"
            scriptcode = f"1976a914{pkh}88ac"
            ## Input amount
            in_amt = f"{_little_endian(data['vin'][0]['prevout']['value'], 8)}"
            ## SEQUENCE for the REQUIRED_input
            sequence_txn = f"{_little_endian(data['vin'][0]['sequence'], 4)}"
            ###############################################################################

            # Outputs
            serialized_output = ""
            for out in data["vout"]:
                serialized_output += f"{_little_endian(out['value'], 8)}"
                serialized_output += f"{_to_compact_size(len(out['scriptpubkey'])//2)}"
                serialized_output += f"{out['scriptpubkey']}"
            ## HASH256 (output)
            hash256_out = (
                hashlib.sha256(
                    hashlib.sha256(bytes.fromhex(serialized_output)).digest()
                )
                .digest()
                .hex()
            )

            ## locktime
            locktime = f"{_little_endian(data['locktime'], 4)}"

            # preimage = version + hash256(inputs) + hash256(sequences) + input + scriptcode + amount + sequence + hash256(outputs) + locktime
            preimage = (
                ver
                + hash256_in
                + hash256_seq
                + ser_tx_vout_sp
                + scriptcode
                + in_amt
                + sequence_txn
                + hash256_out
                + locktime
            )
            # print(f"preimage 11111 ::> {preimage}")
    # return hashlib.sha256(bytes.fromhex(preimage)).digest().hex()
    return preimage


def validate_p2wpkh_txn(witness, wit_scriptpubkey_asm, txn_data):
    wit_sig, wit_pubkey = witness[0], witness[1]

    pkh = wit_scriptpubkey_asm.split(" ")[-1]
    print(wit_sig, wit_pubkey, pkh)
    print("\n")
    print(txn_data)
    scriptpubkey_asm = [
        "OP_DUP",
        "OP_HASH160",
        "OP_PUSHBYTES_20",
        pkh,
        "OP_EQUALVERIFY",
        "OP_CHECKSIG",
    ]

    return p2pkh.validate_p2pkh_txn(wit_sig, wit_pubkey, scriptpubkey_asm, txn_data)


# filename = "1ccd927e58ef5395ddef40eee347ded55d2e201034bc763bfb8a263d66b99e5e"
filename = "0a3fd98f8b3d89d2080489d75029ebaed0c8c631d061c2e9e90957a40e99eb4c"
file_path = os.path.join("mempool", f"{filename}.json")  # file path
if os.path.exists(file_path):
    with open(file_path, "r") as file:
        txn_data = json.load(file)

wit = txn_data["vin"][0]["witness"]
wit_asm = txn_data["vin"][0]["prevout"]["scriptpubkey_asm"]
txn_data = segwit_txn_data(filename)

print(f"p2wpkh::> {validate_p2wpkh_txn(wit, wit_asm, txn_data)}")

"""
CRITICAL COMMENTS::

presence of <OP_PUSHNUM_3>
"""
