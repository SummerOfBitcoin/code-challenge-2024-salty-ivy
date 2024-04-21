import hashlib
import json
import os


def to_hash160(hex_input):
    # print(hex_input)
    sha = hashlib.sha256(bytes.fromhex(hex_input)).hexdigest()
    hash_160 = hashlib.new("ripemd160")
    hash_160.update(bytes.fromhex(sha))

    return hash_160.hexdigest()


def to_compact_size(value):
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


def to_little_endian(num, size):
    return num.to_bytes(size, byteorder="little").hex()


def legacy_txn_data(txn_id):
    txn_hash = ""

    file_path = os.path.join("mempool", f"{txn_id}.json")
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            data = json.load(f)
            # Version
            txn_hash += f"{to_little_endian(data['version'], 4)}"
            # No. of inputs:
            txn_hash += f"{str(to_compact_size(len(data['vin'])))}"
            # Inputs
            for iN in data["vin"]:
                txn_hash += f"{bytes.fromhex(iN['txid'])[::-1].hex()}"
                txn_hash += f"{to_little_endian(iN['vout'], 4)}"
                txn_hash += f"{to_compact_size(len(iN['prevout']['scriptpubkey'])//2)}"  # FLAG@> maybe not divided by 2
                txn_hash += f"{iN['prevout']['scriptpubkey']}"
                txn_hash += f"{to_little_endian(iN['sequence'], 4)}"

            # No. of outputs
            txn_hash += f"{str(to_compact_size(len(data['vout'])))}"

            # Outputs
            for out in data["vout"]:
                txn_hash += f"{to_little_endian(out['value'], 8)}"
                txn_hash += f"{to_compact_size(len(out['scriptpubkey'])//2)}"
                txn_hash += f"{out['scriptpubkey']}"

            # Locktime
            txn_hash += f"{to_little_endian(data['locktime'], 4)}"
    return txn_hash


def validate_p2sh_txn_basic(inner_redeemscript_asm, scriptpubkey_asm):
    inner_script = inner_redeemscript_asm.split(" ")
    scriptpubkey = scriptpubkey_asm.split(" ")

    stack = []
    redeem_script = ""

    for i in inner_script:
        if i == "OP_0":
            redeem_script += "00"
        if i == "OP_PUSHNUM_2":
            redeem_script += "02"
        if i == "OP_PUSHBYTES_20":
            redeem_script += "14"  # COmpact representation of 20.
            redeem_script += inner_script[inner_script.index("OP_PUSHBYTES_20") + 1]
        if i == "OP_PUSHBYTES_33":
            redeem_script += "21"  # COmpact representation of 33
            redeem_script += inner_script[inner_script.index("OP_PUSHBYTES_33") + 1]

    stack.append(redeem_script)

    for i in scriptpubkey:
        if i == "OP_HASH160":
            print("===========")
            print("OP_HASH160")
            ripemd160_hash = to_hash160(stack[-1])
            stack.pop(-1)
            stack.append(ripemd160_hash)

        if i == "OP_PUSHBYTES_20":
            print("===========")
            print("OP_PUSHBYTES_20")
            stack.append(scriptpubkey[scriptpubkey.index("OP_PUSHBYTES_20") + 1])

        if i == "OP_EQUAL":
            return stack[-1] == stack[-2]


def validate_p2sh_txn_adv(
    inner_redeemscript_asm, scriptpubkey_asm, scriptsig_asm, txn_data
):
    inner_redeemscript = inner_redeemscript_asm.split(" ")
    scriptpubkey = scriptpubkey_asm.split(" ")
    scriptsig = scriptsig_asm.split(" ")

    redeem_stack = []
    signatures = []

    for item in scriptsig:
        if "OP_PUSHBYTES_" in item:
            print("")
            signatures.append(scriptsig[scriptsig.index(item) + 1])
            scriptsig[scriptsig.index(item)] = "DONE"
    print(signatures)
    for item in inner_redeemscript:
        if "OP_PUSHNUM_" in item:
            num = item[len("OP_PUSHNUM_") :]
            redeem_stack.append(int(num))

        if "OP_PUSHBYTES_" in item:
            print("")
            redeem_stack.append(inner_redeemscript[inner_redeemscript.index(item) + 1])
            inner_redeemscript[inner_redeemscript.index(item)] = "DONE"

        if "OP_CHECKMULTISIG" in item:
            msg = txn_data + "01000000"
            # msg_hash = hashlib.sha256(hashlib.sha256(bytes.fromhex(msg)).digest()).hexdigest()
            msg_hash = hashlib.sha256(bytes.fromhex(msg)).digest().hexdigest()

    print(redeem_stack)
    print(f"\nmsg::> {msg}")
    print(f"\nmsh_hash::> {msg_hash}")


# 0cd144c7db2aba75da0b9a09c949df35898ad277fbf24a9c6ef33a3424aedd3a ==> Simple
# 0dd03993f8318d968b7b6fdf843682e9fd89258c186187688511243345c2009f ==> Advanced
# ff0717b6f0d2b2518cfb85eed7ccea44c3a3822e2a0ce6e753feecf68df94a7f ==> Simple LOOOOONG

# ADVANCED Txn
filename = "0dd03993f8318d968b7b6fdf843682e9fd89258c186187688511243345c2009f"
file_path = os.path.join("mempool", f"{filename}.json")  # file path
if os.path.exists(file_path):
    with open(file_path, "r") as file:
        txn_data = json.load(file)

redeemscript_asm = txn_data["vin"][0]["inner_redeemscript_asm"]
scriptpubkey_asm = txn_data["vin"][0]["prevout"]["scriptpubkey_asm"]
scriptsig_asm = txn_data["vin"][0]["scriptsig_asm"]
txn_data = legacy_txn_data(filename)
print(f"txn_data: {txn_data}\n")
print(
    f"p2sh(adv)::> {validate_p2sh_txn_adv(redeemscript_asm, scriptpubkey_asm, scriptsig_asm, txn_data)}"
)


# BASIC Txn
# filename = "0cd144c7db2aba75da0b9a09c949df35898ad277fbf24a9c6ef33a3424aedd3a"
# file_path = os.path.join('mempool', f"{filename}.json") # file path
# if os.path.exists(file_path):
#     with open(file_path, 'r') as file:
#         txn_data = json.load(file)

# redeemscript_asm = txn_data["vin"][3]["inner_redeemscript_asm"]
# scriptpubkey_asm = txn_data["vin"][3]["scriptsig_asm"]

# print(f"p2sh(basic)::> {validate_p2sh_txn_basic(redeemscript_asm, scriptpubkey_asm), scriptsig_asm}")

"""
{
    "txid": "5032d895944fdb428e2aeeb022f32070c6db8b7421738bdee91444f3a8fa6465",
    "vout": 1,
    "prevout": {
      "scriptpubkey": "a914dfe791507cb5a44c9a527982f5a69ade6c5421c987",
      "scriptpubkey_asm": "OP_HASH160 OP_PUSHBYTES_20 dfe791507cb5a44c9a527982f5a69ade6c5421c9 OP_EQUAL",
      "scriptpubkey_type": "p2sh",
      "scriptpubkey_address": "3N6v1vW3gYLYttL2GmaJ28SDw6Y1ZNQX3e",
      "value": 179930847
    },
    "scriptsig": "00483045022100e1804c80eb6aecbb423d1a1223bedc3de5300ce32825a5fe979643727ebb56b00220351385c13fc79e7f8405e433bdd18c8630a446db06b693362f288a7615f7075701483045022100f4dda558ecfae6d2acb68a07f51d8314e6819afebc79fba2674f79320e60d3d002204e497fa8d610514e652939f07876589fa1f2ea36d4ae2570079251a46d4d2f600147522102fa3e97f867f6dd61c8f3870174a62212c568bbfa1d55fd57b8d355343d35a65c2103031d20b72222b1f6fe8217783c0adf898358afc24dee408e518e4af0dc899e7052ae",
    "scriptsig_asm": "OP_0 OP_PUSHBYTES_72 3045022100e1804c80eb6aecbb423d1a1223bedc3de5300ce32825a5fe979643727ebb56b00220351385c13fc79e7f8405e433bdd18c8630a446db06b693362f288a7615f7075701 OP_PUSHBYTES_72 3045022100f4dda558ecfae6d2acb68a07f51d8314e6819afebc79fba2674f79320e60d3d002204e497fa8d610514e652939f07876589fa1f2ea36d4ae2570079251a46d4d2f6001 OP_PUSHBYTES_71 522102fa3e97f867f6dd61c8f3870174a62212c568bbfa1d55fd57b8d355343d35a65c2103031d20b72222b1f6fe8217783c0adf898358afc24dee408e518e4af0dc899e7052ae",
    "is_coinbase": false,
    "sequence": 4294967295,
    "inner_redeemscript_asm": "OP_PUSHNUM_2 OP_PUSHBYTES_33 02fa3e97f867f6dd61c8f3870174a62212c568bbfa1d55fd57b8d355343d35a65c OP_PUSHBYTES_33 03031d20b72222b1f6fe8217783c0adf898358afc24dee408e518e4af0dc899e70 OP_PUSHNUM_2 OP_CHECKMULTISIG"
}
"""
