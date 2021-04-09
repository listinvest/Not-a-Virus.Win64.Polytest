from capstone import *
import bitstring as bs

while True:
    try:
        CODE = input("-> ")
        CODE = bytearray.fromhex(CODE)
    except ValueError:
        continue

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(CODE, 0x1000):
        binary = bs.BitArray(i.bytes).bin
        binary = ' '.join([binary[i:i+8] for i in range(0, len(binary), 8)])
        print(f"{binary}:\t{i.mnemonic}\t{i.op_str}")