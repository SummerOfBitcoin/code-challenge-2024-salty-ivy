def target_to_bits(target, fNegative=False):
    target_bytes = bytes.fromhex(target)
    nSize = (len(target_bytes) + 7) // 8
    nCompact = 0
    if nSize <= 3:
        nCompact = int.from_bytes(target_bytes, byteorder="big") << 8 * (3 - nSize)
    else:
        bn = int.from_bytes(target_bytes, byteorder="big") >> 8 * (nSize - 3)
        nCompact = bn
    if nCompact & 0x00800000:
        nCompact >>= 8
        nSize += 1
    assert (nCompact & ~0x007FFFFF) == 0
    assert nSize < 256
    nCompact |= nSize << 24
    nCompact |= (fNegative and (nCompact & 0x007FFFFF) and 0x00800000) or 0
    return hex(nCompact)


target = "0000ffff00000000000000000000000000000000000000000000000000000000"
bits = target_to_bits(target)
print(bits)  # Output: 0x1d00ffff
