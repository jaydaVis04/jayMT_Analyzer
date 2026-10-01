#!/usr/bin/env python3
"""Create a tiny, freely distributable mixed-MIPS analysis fixture."""
import argparse
import csv
from pathlib import Path
import struct


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    output = parser.parse_args().output
    output.mkdir(parents=True, exist_ok=True)
    rom = bytearray(b"\xff" * 768)
    rom[:8] = bytes.fromhex("0800e00300000000")  # MIPS32: jr ra; nop (delay slot)
    struct.pack_into("<HHH", rom, 0x10, 0x64c2, 0x6442, 0xe8a0)  # save; restore; jrc ra
    struct.pack_into("<IIII", rom, 0x30, 0x90000000, 0x90000011, 0x90000051, 0x90000091)
    struct.pack_into("<HH", rom, 0x40, 0x6500, 0xe8a0)  # nop; jrc ra, no prologue/mode hint
    struct.pack_into("<HH", rom, 0x50, 0x6500, 0xe8a0)  # inferred from tagged data reference
    rom[0x60:0x68] = rom[:8]
    rom[0x70:0x78] = rom[:8]
    struct.pack_into("<II", rom, 0x80, 0x08000000, 0)  # thunk: j 0x90000000; nop
    struct.pack_into("<HHH", rom, 0x90, 0xa440, 0x7201, 0xe8a0)  # lbu; slti; jrc ra, aliases a 32-bit SPECIAL2
    # Initialization routine with eight distinct memcpy/memset records at its end.
    # This catches the inherited cursor bug that mapped the same record eight times.
    rom[0x100:0x108] = rom[:8]
    for index in range(8):
        destination = 0x64000000 + index * 0x10
        struct.pack_into("<IIIII", rom, 0x108 + index * 20,
                         4, 0, destination, 4, destination + 4)
    (output / "md1rom").write_bytes(rom)
    with (output / "md1_dbginfo.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, delimiter=" ", lineterminator="\n")
        writer.writerow(("name", "addr", "size", "mode", "type"))
        writer.writerows([
            ("return_test", 0, 8, "MIPS32", "FUNC"),
            ("compact_test", 16, 6, "UNKNOWN", "FUNC"),
            ("unhinted_test", 64, 4, "UNKNOWN", "FUNC"),
            ("referenced_test", 80, 4, "UNKNOWN", "FUNC"),
            ("quoted function", 96, 8, "MIPS32", "FUNC"),
            ('quote"function', 112, 8, "MIPS32", "FUNC"),
            ("thunk_test", 128, 8, "MIPS32", "FUNC"),
            ("ambiguous_leaf", 144, 6, "UNKNOWN", "FUNC"),
            ("return_alias", 0, 8, "MIPS32", "FUNC"),
            ("INT_InitPerCoreRegion_C", 0x100, 8 + 8 * 20, "MIPS32", "FUNC"),
        ])
    print(output)


if __name__ == "__main__":
    main()
