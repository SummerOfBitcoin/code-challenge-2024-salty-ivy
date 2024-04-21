import os
import json
import hashlib
import coincurve
# import helper.converter as convert
# from mempool import *
# from src.helper import converter as convert
# from ..helper import converter as convert


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
            # Version
            ver = f"{_little_endian(data['version'], 4)}"

            # (txid + vout)
            serialized_txid_vout = ""
            for iN in data["vin"]:
                serialized_txid_vout += f"{bytes.fromhex(iN['txid'])[::-1].hex()}"
                serialized_txid_vout += f"{_little_endian(iN['vout'], 4)}"
            # HASH256 (txid + vout)
            # hash256_in = convert.to_hash256(serialized_txid_vout)
            hash256_in = (
                hashlib.sha256(
                    hashlib.sha256(bytes.fromhex(serialized_txid_vout)).digest()
                )
                .digest()
                .hex()
            )

            # (sequense)
            serialized_sequense = ""
            for iN in data["vin"]:
                serialized_sequense += f"{_little_endian(iN['sequence'], 4)}"
            # HASH256 (sequense)
            # hash256_seq = convert.to_hash256(serialized_sequense)
            hash256_seq = (
                hashlib.sha256(
                    hashlib.sha256(bytes.fromhex(serialized_sequense)).digest()
                )
                .digest()
                .hex()
            )

            ###############################################################################
            # TXN Specific #
            # TXID and VOUT for the REQUIRED_input
            ser_tx_vout_sp = f"{bytes.fromhex(data['vin'][0]['txid'])[::-1].hex()}{_little_endian(data['vin'][0]['vout'], 4)}"
            print(ser_tx_vout_sp)
            # Scriptcode
            pkh = f"{data['vin'][0]['prevout']['scriptpubkey'][6:-4]}"
            scriptcode = f"1976a914{pkh}88ac"
            # Input amount
            in_amt = f"{_little_endian(data['vin'][0]['prevout']['value'], 8)}"
            # SEQUENCE for the REQUIRED_input
            sequence_txn = f"{_little_endian(data['vin'][0]['sequence'], 4)}"
            ###############################################################################

            # Outputs
            serialized_output = ""
            for out in data["vout"]:
                serialized_output += f"{_little_endian(out['value'], 8)}"
                serialized_output += f"{_to_compact_size(len(out['scriptpubkey'])//2)}"
                serialized_output += f"{out['scriptpubkey']}"
            # HASH256 (output)
            # hash256_out = convert.to_hash256(serialized_output)
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
    return preimage


"""
def segwit_txn_data(txn_id):
    file_path = os.path.join("mempool", f"{txn_id}.json")
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            data = json.load(f)
            ## Version
            ver = f"{convert.to_little_endian(data['version'], 4)}"

            ## (txid + vout)
            serialized_txid_vout = ""
            for iN in data["vin"]:
                serialized_txid_vout += f"{bytes.fromhex(iN['txid'])[::-1].hex()}"
                serialized_txid_vout += f"{convert.to_little_endian(iN['vout'], 4)}"
            # HASH256 (txid + vout)
            hash256_in = convert.to_hash256(serialized_txid_vout)
            
            ## (sequense)
            serialized_sequense= ""
            for iN in data["vin"]:
                serialized_sequense += f"{convert.to_little_endian(iN['sequence'], 4)}"
            ## HASH256 (sequense)
            hash256_seq = convert.to_hash256(serialized_sequense)
            
            ###############################################################################
            # TXN Specific #
            ## TXID and VOUT for the REQUIRED_input
            ser_tx_vout_sp = f"{bytes.fromhex(data['vin'][0]['txid'])[::-1].hex()}{convert.to_little_endian(data['vin'][0]['vout'], 4)}"
            print(ser_tx_vout_sp)
            ## Scriptcode
            pkh = f"{data['vin'][0]['prevout']['scriptpubkey'][6:-4]}" 
            scriptcode = f"1976a914{pkh}88ac"
            ## Input amount
            in_amt = f"{convert.to_little_endian(data['vin'][0]['prevout']['value'], 8)}"
            ## SEQUENCE for the REQUIRED_input
            sequence_txn = f"{convert.to_little_endian(data['vin'][0]['sequence'], 4)}"
            ###############################################################################

            # Outputs
            serialized_output= ""
            for out in data["vout"]:
                serialized_output += f"{convert.to_little_endian(out['value'], 8)}"
                serialized_output += f"{convert.to_compact_size(len(out['scriptpubkey'])//2)}"
                serialized_output += f"{out['scriptpubkey']}"
            ## HASH256 (output)
            hash256_out = convert.to_hash256(serialized_output)

            ## locktime
            locktime = f"{convert.to_little_endian(data['locktime'], 4)}"

            # preimage = version + hash256(inputs) + hash256(sequences) + input + scriptcode + amount + sequence + hash256(outputs) + locktime
            preimage = ver + hash256_in + hash256_seq + ser_tx_vout_sp + scriptcode + in_amt + sequence_txn + hash256_out + locktime
    return preimage
"""
"""
ORG::> 02000000 cbfaca386d65ea7043aaac40302325d0dc7391a73b585571e28d3287d6b16203 3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044 ac4994014aa36b7f53375658ef595b3cb2891e1735fe5b441686f5e53338e76a:01000000 1976a914aa966f56de599b4094b61aa68a2b3df9e97e9c4888ac 3075000000000000 ffffffff 900a6c6ff6cd938bf863e50613a4ed5fb1661b78649fe354116edaf5d4abb952 00000000 01000000
NEW::> 02000000 f81369411d3fba4eb8575cc858ead8a859ef74b94e160a036b8c1c5b023a6fae 957879fdce4d8ab885e32ff307d54e75884da52522cc53d3c4fdb60edb69a098 659a6eaf8d943ad2ff01ec8c79aaa7cb4f57002d49d9b8cf3c9a7974c5bd3608:06000000 1976a9147db10cfe69dae5e67b85d7b59616056e68b3512288ac f1a2010000000000 fdffffff 0f38c28e7d8b977cd40352d825270bd20bcef66ceac3317f2b2274d26f973f0f 00000000 01000000
       02000000 f81369411d3fba4eb8575cc858ead8a859ef74b94e160a036b8c1c5b023a6fae 957879fdce4d8ab885e32ff307d54e75884da52522cc53d3c4fdb60edb69a098 2cbc395e5c16b1204f1ced9c0d1699abf5abbbb6b2eee64425c55252131df6c4:00000000 1976a9146dee3ed7e9a03ad379f2f78d13138f9141c794ed88ac f306020000000000 fdffffff 0f38c28e7d8b977cd40352d825270bd20bcef66ceac3317f2b2274d26f973f0f 00000000 01000000
"""

"""

    P2PKH (legacy) - Lock the output to the hash of a public key. To unlock you need to provide the original public key and a valid signature.
    Example: 76a914{publickeyhash}88ac
    P2SH (legacy) - Lock the output to the hash of a custom script. To unlock you need to provide the original script along with the script that satisfies it.
    Example: a914{scripthash}87
    P2WPKH - Lock the output to the hash of a public key. Works the same as a P2PKH, but the unlocking code goes in the witness field instead of the scriptsig field.
    Example: 0014{publickeyhash}
    P2WSH - Lock the output to the hash of a custom script. Works the same as a P2SH, but the unlocking code goes in the witness field instead of the scriptsig field.
    Example: 0020{scripthash}

"""


# print(segwit_txn_data("1ccd927e58ef5395ddef40eee347ded55d2e201034bc763bfb8a263d66b99e5e"))
def legacy_txn_data(txn_id):
    txn_hash = ""

    file_path = os.path.join("mempool", f"{txn_id}.json")
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            data = json.load(f)
            # Version
            txn_hash += f"{_little_endian(data['version'], 4)}"
            # No. of inputs:
            txn_hash += f"{str(_to_compact_size(len(data['vin'])))}"
            # Inputs
            for iN in data["vin"]:
                txn_hash += f"{bytes.fromhex(iN['txid'])[::-1].hex()}"
                txn_hash += f"{_little_endian(iN['vout'], 4)}"
                txn_hash += f"{_to_compact_size(len(iN['prevout']['scriptpubkey'])//2)}"  # FLAG@> maybe not divided by 2
                txn_hash += f"{iN['prevout']['scriptpubkey']}"
                txn_hash += f"{_little_endian(iN['sequence'], 4)}"

            # No. of outputs
            txn_hash += f"{str(_to_compact_size(len(data['vout'])))}"

            # Outputs
            for out in data["vout"]:
                txn_hash += f"{_little_endian(out['value'], 8)}"
                txn_hash += f"{_to_compact_size(len(out['scriptpubkey'])//2)}"
                txn_hash += f"{out['scriptpubkey']}"

            # Locktime
            txn_hash += f"{_little_endian(data['locktime'], 4)}"
    return txn_hash


##########
## MAIN ##
##########
def validate_p2pkh_txn(signature, pubkey, scriptpubkey_asm, txn_data):
    stack = []

    stack.append(signature)
    stack.append(pubkey)

    # print(stack)

    for i in scriptpubkey_asm:
        if i == "OP_DUP":
            stack.append(stack[-1])
            # print("===========")
            # print("OP_DUP")
            # print(stack)

        if i == "OP_HASH160":
            # print("===========")
            # print("OP_HASH160")
            # ripemd160_hash = convert.to_hash160(stack[-1])
            sha = hashlib.sha256(bytes.fromhex(stack[-1])).hexdigest()
            hash_160 = hashlib.new("ripemd160")
            hash_160.update(bytes.fromhex(sha))

            stack.pop(-1)
            # print(stack)
            stack.append(hash_160.hexdigest())
            # print(stack)

        if i == "OP_EQUALVERIFY":
            # print("===========")
            # print("OP_EQUALVERIFY")
            if stack[-1] != stack[-2]:
                return False
            else:
                stack.pop(-1)
                # print(stack)
                stack.pop(-1)
                # print(stack)

        if i == "OP_CHECKSIG":
            # print("===========")
            # print("OP_CHECKSIG")
            if signature[-2:] == "01":  # SIGHASH_ALL ONLY
                der_sig = signature[:-2]
                msg = txn_data + "01000000"
                msg_hash = hashlib.sha256(bytes.fromhex(msg)).digest().hex()
                # print(der_sig)
                # print(pubkey)
                print("============VALIDAREA=================")
                print(msg)
                print(msg_hash)
                return validate_signature(der_sig, msg_hash, pubkey)

        if i == "OP_PUSHBYTES_20":
            # print("===========")
            # print("OP_PUSHBYTES_20")
            stack.append(
                scriptpubkey_asm[scriptpubkey_asm.index("OP_PUSHBYTES_20") + 1]
            )
            # print(stack)


# filename = "0a8b21af1cfcc26774df1f513a72cd362a14f5a598ec39d915323078efb5a240"
# filename = "1ccd927e58ef5395ddef40eee347ded55d2e201034bc763bfb8a263d66b99e5e"
# file_path = os.path.join('mempool', f"{filename}.json") # file path
# if os.path.exists(file_path):
#     with open(file_path, 'r') as file:
#         txn_data = json.load(file)
#         # print(f"txn_data: {txn_data}")
# else:
#     print(f"file not found: {file_path}")
# signature = txn_data['vin'][0]["scriptsig_asm"].split(" ")[1]
# pubkey = txn_data['vin'][0]["scriptsig_asm"].split(" ")[3]
# scriptpubkey_asm = txn_data['vin'][0]["prevout"]["scriptpubkey_asm"].split(" ")
# # raw_txn_data = legacy_txn_data(filename)
# raw_txn_data = segwit_txn_data(filename)
# print(raw_txn_data)

# print(f"p2pkh::> {validate_p2pkh_txn(signature, pubkey, scriptpubkey_asm, raw_txn_data)}")


"""
02000000 f81369411d3fba4eb8575cc858ead8a859ef74b94e160a036b8c1c5b023a6fae957879fdce4d8ab885e32ff307d54e75884da52522cc53d3c4fdb60edb69a098659a6eaf8d943ad2ff01ec8c79aaa7cb4f57002d49d9b8cf3c9a7974c5bd3608060000001976a9147db10cfe69dae5e67b85d7b59616056e68b3512288acf1a2010000000000fdffffff0f38c28e7d8b977cd40352d825270bd20bcef66ceac3317f2b2274d26f973f0f0000000001000000
02000000 f81369411d3fba4eb8575cc858ead8a859ef74b94e160a036b8c1c5b023a6fae957879fdce4d8ab885e32ff307d54e75884da52522cc53d3c4fdb60edb69a098659a6eaf8d943ad2ff01ec8c79aaa7cb4f57002d49d9b8cf3c9a7974c5bd3608060000001976a914147db10cfe69dae5e67b85d7b59616056e68b3512288ac88acf1a2010000000000fdffffff0f38c28e7d8b977cd40352d825270bd20bcef66ceac3317f2b2274d26f973f0f0000000001000000

02000000 9a0c2ad742ec53644bda0e38b09b7546714540959016a1b457005d4368c0302118606b350cd8bf565266bc352f0caddcf01e8fa789dd8a15386327cf8cabe19828945f452bcb038a679fc33fb03d06561a59585d6f36090894471b17b615b5b9000000001976a914371e036c75b663254314287faa19c7b3f6c35e8a88ac4af07c1100000000feffffff188874c3c72a2fa0da3253b57b8f1403348c00d38c99e0af1d033b497683b6f34dbc0c0001000000
"""


# def rs(signature):
#     r, s = sigdecode_der(bytes.fromhex(signature), secp256k1_generator.order)
#     print(f"r: {r}, s: {s}")
#     return (r, s)


# def legacy_p2pkh_txn_validation(signature, pubkey, scriptpubkey_asm, )
###<INJECTION>###
# filename = "1ccd927e58ef5395ddef40eee347ded55d2e201034bc763bfb8a263d66b99e5e"
# filename = "0a8b21af1cfcc26774df1f513a72cd362a14f5a598ec39d915323078efb5a240"
# file_path = os.path.join('mempool', f"{filename}.json") # file path
# if os.path.exists(file_path):
#     with open(file_path, 'r') as file:
#         txn_data = json.load(file)
# scriptsig_asm = txn_data["vin"][0]["scriptsig_asm"].split(" ")
# scriptpubkey_asm = txn_data["vin"][0]["prevout"]["scriptpubkey_asm"].split(" ")
# print(legacy_txn_data(filename))
# print(f"p2pkh::> {validate_p2pkh_txn(scriptsig_asm[1], scriptsig_asm[3], scriptpubkey_asm, legacy_txn_data(filename))}")

"""
STEPS::>
* serialize the TXID+VOUT for the specific input we want to create a signature for.
* sequence field for the input we're creating the signature for.

02000000 f81369411d3fba4eb8575cc858ead8a859ef74b94e160a036b8c1c5b023a6fae 957879fdce4d8ab885e32ff307d54e75884da52522cc53d3c4fdb60edb69a098 659a6eaf8d943ad2ff01ec8c79aaa7cb4f57002d49d9b8cf3c9a7974c5bd3608:06000000 1976a9147db10cfe69dae5e67b85d7b59616056e68b3512288ac f1a2010000000000 fdffffff 0f38c28e7d8b977cd40352d825270bd20bcef66ceac3317f2b2274d26f973f0f 00000000 01000000

02000000 f81369411d3fba4eb8575cc858ead8a859ef74b94e160a036b8c1c5b023a6fae 957879fdce4d8ab885e32ff307d54e75884da52522cc53d3c4fdb60edb69a098 659a6eaf8d943ad2ff01ec8c79aaa7cb4f57002d49d9b8cf3c9a7974c5bd3608:06000000 1976a9147db10cfe69dae5e67b85d7b59616056e68b3512288ac f1a2010000000000 fdffffff 0f38c28e7d8b977cd40352d825270bd20bcef66ceac3317f2b2274d26f973f0f 00000000 01000000
"""
