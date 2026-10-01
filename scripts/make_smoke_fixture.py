#!/usr/bin/env python3
"""Create a tiny, freely distributable mixed-MIPS analysis fixture."""
import argparse
from pathlib import Path
import struct


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    output = parser.parse_args().output
    output.mkdir(parents=True, exist_ok=True)
    rom = bytearray(b"\xff" * 256)
    rom[:8] = bytes.fromhex("0800e00300000000")  # MIPS32: jr ra; nop (delay slot)
    struct.pack_into("<HHH", rom, 0x10, 0x64c2, 0x6442, 0xe8a0)  # save; restore; jrc ra
    struct.pack_into("<II", rom, 0x30, 0x90000000, 0x90000011)
    (output / "md1rom").write_bytes(rom)
    (output / "md1_dbginfo.csv").write_text(
        "name addr size mode type\n"
        "return_test 0 8 MIPS32 FUNC\n"
        "compact_test 16 6 UNKNOWN FUNC\n", encoding="ascii")
    print(output)


if __name__ == "__main__":
    main()
