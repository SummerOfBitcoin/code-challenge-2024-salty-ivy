DIFFICULTY_TARGET = "0000ffff00000000000000000000000000000000000000000000000000000000"


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


print(target_to_bits(DIFFICULTY_TARGET[:8]))
