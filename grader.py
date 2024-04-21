from block import calculate_witness_commitment
from utils import to_reverse_bytes_string, to_hash256


WITNESS_RESERVED_VALUE_HEX = '0000000000000000000000000000000000000000000000000000000000000000'


with open('output.txt', 'r') as file:
    # Read the contents of the file and split it into lines
    lines = file.readlines()
    txns = []
