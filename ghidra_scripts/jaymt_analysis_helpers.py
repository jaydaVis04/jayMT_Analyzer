# Shared helpers; imported by analyze_mtk_image.py.
# @category jayMT_Analyzer.Internal
# @runtime Jython
"""Pure Python 2.7/3 helpers shared by the Ghidra script and regression tests."""
from __future__ import division

import csv
import struct

BASE_ADDRESS = 0x90000000
ADDRESS_LIMIT = 0x100000000


def checked_range(start, length):
    if start < 0 or length <= 0 or start + length > ADDRESS_LIMIT:
        raise ValueError("invalid 32-bit range: start={:#x}, length={:#x}".format(start, length))
    return start, start + length


def rom_address(address, rom_size, base=BASE_ADDRESS):
    """Translate file-relative symbols while preserving runtime RAM addresses."""
    return base + address if 0 <= address < rom_size else address


def parse_symbols(lines, rom_size, base=BASE_ADDRESS):
    """Read the original space-delimited CSV, including quoted symbol names."""
    entries, modes, seen = [], {}, set()
    reader = csv.DictReader(lines, delimiter=" ", skipinitialspace=True)
    if not reader.fieldnames or not {"name", "addr", "size"}.issubset(reader.fieldnames):
        raise ValueError("symbol CSV needs name, addr and size columns")
    for line_number, row in enumerate(reader, 2):
        if not row.get("name"):
            continue
        try:
            raw_start = int(row["addr"], 16 if row["addr"].lower().startswith("0x") else 10)
            size = int(row["size"], 16 if row["size"].lower().startswith("0x") else 10)
            start = rom_address(raw_start & ~1, rom_size, base)
            if size < 0 or start < 0 or start + size > ADDRESS_LIMIT:
                raise ValueError("invalid symbol bounds")
            entry = (start, start + size, row["name"])
            if entry in seen:
                continue
            seen.add(entry)
            entries.append(entry)
            mode = (row.get("mode") or "").upper()
            if raw_start & 1 or mode in ("MIPS16", "MIPS16E", "MIPS16E2", "M16", "16"):
                modes[start] = True
            elif mode in ("MIPS32", "M32", "32"):
                modes[start] = False
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid symbol CSV row {}: {}".format(line_number, exc))
    if not entries:
        raise ValueError("symbol CSV contains no symbols")
    return entries, modes


def uncovered_ranges(start, end, occupied):
    """Subtract overlapping or nested occupied ranges from a half-open range."""
    if end <= start:
        return []
    cursor, gaps = start, []
    for left, right in sorted(occupied):
        if right <= cursor or left >= end:
            continue
        if left > cursor:
            gaps.append((cursor, min(left, end)))
        cursor = max(cursor, right)
        if cursor >= end:
            break
    if cursor < end:
        gaps.append((cursor, end))
    return gaps


def pointer_candidates(data, base, function_entries):
    """Filter little-endian words without one Ghidra call for every word."""
    for offset in range((-base) % 4, len(data) - 3, 4):
        target = struct.unpack_from("<I", data, offset)[0]
        if target & ~1 in function_entries:
            yield base + offset, target


def backwards_records(start, end, count, fields):
    width = fields * 4
    if end - start < count * width:
        raise ValueError("mapping symbol is shorter than its expected table")
    return [end - width * (index + 1) for index in range(count)]
