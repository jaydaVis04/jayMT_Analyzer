import importlib.util
import io
from pathlib import Path
import struct
import unittest

HELPER = Path(__file__).parents[1] / "ghidra_scripts" / "jaymt_analysis_helpers.py"
spec = importlib.util.spec_from_file_location("jaymt_analysis_helpers", HELPER)
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)


class AnalysisLogicTests(unittest.TestCase):
    def test_unoccupied_and_single_byte_holes(self):
        self.assertEqual(helpers.uncovered_ranges(10, 20, []), [(10, 20)])
        self.assertEqual(helpers.uncovered_ranges(10, 20, [(10, 19)]), [(19, 20)])

    def test_nested_overlaps_do_not_move_cursor_backwards(self):
        self.assertEqual(helpers.uncovered_ranges(10, 30, [(8, 20), (12, 15), (22, 25)]),
                         [(20, 22), (25, 30)])

    def test_percore_tables_use_eight_distinct_records(self):
        self.assertEqual(helpers.backwards_records(0, 200, 8, 5),
                         [180, 160, 140, 120, 100, 80, 60, 40])
        with self.assertRaises(ValueError):
            helpers.backwards_records(0, 100, 8, 5)

    def test_symbol_aliases_and_mode_bits(self):
        stream = io.StringIO('name addr size mode type\n"quoted function" 17 8 UNKNOWN FUNC\n'
                             'absolute 2415919136 16 MIPS32 FUNC\nram 1677721600 8 UNKNOWN FUNC\n')
        entries, modes = helpers.parse_symbols(stream, 1024)
        self.assertEqual(entries[0], (0x90000010, 0x90000018, "quoted function"))
        self.assertEqual(entries[1], (0x90000020, 0x90000030, "absolute"))
        self.assertEqual(entries[2][0], 0x64000000)
        self.assertEqual(modes, {0x90000010: True, 0x90000020: False})

    def test_invalid_symbol_table_is_not_silently_ignored(self):
        for source in ("garbage\n", "name addr size\nbad no 2\n", "name addr size\n", "name addr size\nbad 1 -2\n"):
            with self.subTest(source=source), self.assertRaises(ValueError):
                helpers.parse_symbols(io.StringIO(source), 1024)

    def test_pointer_filter_handles_tagged_functions_and_short_tail(self):
        data = struct.pack("<IIII", 0x90000000, 0x90000011, 0x12345678, 0x90000020) + b"\x01\x02"
        self.assertEqual(list(helpers.pointer_candidates(data, 0x90001000, {0x90000000, 0x90000010})),
                         [(0x90001000, 0x90000000), (0x90001004, 0x90000011)])

    def test_pointer_filter_uses_absolute_alignment(self):
        data = b"xxx" + struct.pack("<I", 0x90000011)
        self.assertEqual(list(helpers.pointer_candidates(data, 0x90001001, {0x90000010})),
                         [(0x90001004, 0x90000011)])

    def test_invalid_mapping_ranges(self):
        for start, size in ((-1, 1), (1, 0), (1, -1), (0xffffffff, 2)):
            with self.subTest(start=start, size=size), self.assertRaises(ValueError):
                helpers.checked_range(start, size)


if __name__ == "__main__":
    unittest.main()
