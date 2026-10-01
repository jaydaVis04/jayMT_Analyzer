"""Synthetic format fixtures; no proprietary firmware is distributed."""

import csv
import hashlib
import importlib.util
import io
import json
import lzma
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest

from jaymt.firmware import (
    FirmwareError, HEADER, MAGIC, MAGIC2, default_output_dir,
    extract_image, parse_debug_info, read_sections,
)


def debug_data(symbols=None, gap=0, *, compress=True, sentinel=b""):
    if symbols is None:
        symbols = [("entry", 0x90000000, 0x90000010),
                   ("worker", 0x90000010, 0x90000020)]
    prefix = b"\0" * 0x1c + b"MD1\0MT6768\0MOLY.TEST\0BUILD.TEST\0"
    records = b"".join(name.encode("utf-8") + b"\0" + struct.pack("<II", start, end)
                       for name, start, end in symbols)
    records += sentinel
    start = len(prefix) + 8 + gap
    data = prefix + struct.pack("<II", start - 0x10, start + len(records) - 0x10)
    data += b"\xff" * gap + records
    return lzma.compress(data) if compress else data


def image_data(sections=None, *, alignment=16, final_flag=True, trailer=b""):
    if sections is None:
        sections = [("md1rom", bytes(range(64))), ("md1_dbginfo", debug_data())]
    image = bytearray()
    for index, (name, payload) in enumerate(sections):
        header = HEADER.pack(MAGIC, len(payload), name.encode("utf-8"), 0, 0,
                             MAGIC2, 512, 1, 0,
                             int(final_flag and index == len(sections) - 1),
                             alignment, 0, 0)
        image.extend(header + b"\0" * (512 - len(header)))
        image.extend(payload)
        image.extend(b"\0" * (-len(image) % (alignment or 16)))
    return bytes(image) + trailer


class FirmwareTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.image = self.root / "arbitrarily-renamed-firmware"
        self.output = self.root / "prepared"

    def write_image(self, data=None):
        self.image.write_bytes(image_data() if data is None else data)
        return self.image

    def csv_rows(self):
        with (self.output / "md1_dbginfo.csv").open(encoding="utf-8", newline="") as source:
            return list(csv.DictReader(source, delimiter=" "))

    def test_raw_image_works_without_a_filename_extension(self):
        original = image_data()
        manifest = extract_image(self.write_image(original), self.output)
        self.assertEqual((self.output / "md1rom").read_bytes(), bytes(range(64)))
        self.assertEqual({p.name for p in self.output.iterdir()},
                         {"md1rom", "md1_dbginfo.csv", "manifest.json"})
        self.assertEqual(self.image.read_bytes(), original)
        self.assertEqual(manifest["source"]["sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(manifest["image"]["sha256"], manifest["source"]["sha256"])
        self.assertEqual(manifest["debug"]["metadata"]["hwplatform"], "MT6768")
        self.assertEqual(manifest["debug"]["symbol_count"], 2)
        self.assertEqual(self.csv_rows()[0]["addr"], str(0x90000000))
        self.assertEqual(json.loads((self.output / "manifest.json").read_text()), manifest)

    def test_all_sections_preserves_exact_payloads(self):
        payloads = [("md1rom", b"CODE"), ("md1_dbginfo", debug_data()),
                    ("md1dsp", b"DSP BYTES"), ("cert1", b"CERT")]
        manifest = extract_image(self.write_image(image_data(payloads)), self.output,
                                 all_sections=True)
        for section, (name, payload) in zip(manifest["sections"], payloads):
            self.assertEqual((self.output / name).read_bytes(), payload)
            self.assertEqual(section["sha256"], hashlib.sha256(payload).hexdigest())

    def test_repeated_certificates_are_preserved_in_separate_files(self):
        payloads = [("md1rom", b"CODE"), ("cert1md", b"FIRST"),
                    ("cert1md", b"SECOND"), ("cert1md", b"THIRD")]
        manifest = extract_image(self.write_image(image_data(payloads)), self.output,
                                 all_sections=True)
        self.assertEqual((self.output / "cert1md").read_bytes(), b"FIRST")
        self.assertEqual((self.output / "cert1md.2").read_bytes(), b"SECOND")
        self.assertEqual((self.output / "cert1md.3").read_bytes(), b"THIRD")
        self.assertEqual([section["name"] for section in manifest["sections"]],
                         [name for name, _ in payloads])

    def test_real_format_nul_sentinel_does_not_become_a_function(self):
        payload = debug_data(sentinel=b"\0", compress=False) + b"/scratch/source.c\0"
        self.write_image(image_data([("md1rom", b"CODE"),
                                    ("md1_dbginfo", lzma.compress(payload))]))
        manifest = extract_image(self.image, self.output)
        self.assertEqual(manifest["debug"]["symbol_count"], 2)
        self.assertEqual([row["name"] for row in self.csv_rows()], ["entry", "worker"])

    def test_debug_function_offset_gap_is_honored(self):
        self.write_image(image_data([("md1rom", b"CODE"),
                                    ("md1_dbginfo", debug_data(gap=37))]))
        extract_image(self.image, self.output)
        self.assertEqual([row["name"] for row in self.csv_rows()], ["entry", "worker"])

    def test_duplicate_and_quoted_symbols_survive_csv(self):
        symbols = [(name, index * 4, index * 4 + 4)
                   for index, name in enumerate(["duplicate", "duplicate", "duplicate_",
                                                  "duplicate", "name with spaces", 'name"quote'])]
        self.write_image(image_data([("md1rom", b"CODE"),
                                    ("md1_dbginfo", debug_data(symbols))]))
        extract_image(self.image, self.output)
        rows = self.csv_rows()
        self.assertEqual(len({row["name"] for row in rows}), len(symbols))
        self.assertEqual([row["name"] for row in rows[-2:]], ["name with spaces", 'name"quote'])

    def test_empty_function_table_is_valid(self):
        self.write_image(image_data([("md1rom", b"CODE"), ("md1_dbginfo", debug_data([]))]))
        manifest = extract_image(self.image, self.output)
        self.assertEqual(self.csv_rows(), [])
        self.assertEqual(manifest["debug"]["symbol_count"], 0)

    def test_images_without_debug_info_can_still_be_extracted(self):
        manifest = extract_image(self.write_image(image_data([("md1rom", b"CODE")])), self.output)
        self.assertFalse(manifest["debug"]["available"])
        self.assertFalse((self.output / "md1_dbginfo.csv").exists())
        self.assertEqual((self.output / "md1rom").read_bytes(), b"CODE")

    def test_full_32_byte_section_name_is_not_truncated(self):
        name = "a" * 32
        manifest = extract_image(self.write_image(image_data([("md1rom", b"CODE"),
                                                              (name, b"X")])), self.output,
                                 all_sections=True)
        self.assertEqual(manifest["sections"][1]["name"], name)
        self.assertTrue((self.output / name).is_file())

    def test_header_alignment_and_load_address_are_preserved(self):
        data = bytearray(image_data(alignment=4096))
        struct.pack_into("<I", data, 40, 0x90000000)
        self.write_image(data)
        sections = read_sections(self.image)
        self.assertEqual(sections[1]["header_offset"], 4096)
        self.assertEqual(sections[0]["load_address"], 0x90000000)
        extract_image(self.image, self.output)

    def test_zero_alignment_uses_legacy_16_byte_alignment(self):
        self.write_image(image_data(alignment=0))
        self.assertEqual(len(read_sections(self.image)), 2)

    def test_extended_size_does_not_silently_truncate(self):
        data = bytearray(image_data())
        struct.pack_into("<I", data, 72, 1)
        self.write_image(data)
        with self.assertRaisesRegex(FirmwareError, "extends outside"):
            read_sections(self.image)

    def test_legacy_samsung_signature_is_accepted(self):
        self.write_image(image_data(final_flag=False, trailer=b"SignerVer123"))
        self.assertEqual(len(read_sections(self.image)), 2)

    def test_invalid_headers_and_ranges_are_rejected(self):
        cases = [(0, 0, "magic"), (48, 0, "magic"), (52, 20, "outside"),
                 (4, 0xffffffff, "outside"), (68, 7, "alignment"), (64, 3, "end flag")]
        for offset, value, message in cases:
            with self.subTest(offset=offset):
                data = bytearray(image_data())
                struct.pack_into("<I", data, offset, value)
                self.write_image(data)
                with self.assertRaisesRegex(FirmwareError, message):
                    read_sections(self.image)

    def test_short_header_and_missing_or_empty_rom_are_rejected(self):
        for data in (b"", struct.pack("<I", MAGIC),
                     image_data([("other", b"X")]), image_data([("md1rom", b"")])):
            with self.subTest(data=data[:10]):
                self.write_image(data)
                with self.assertRaises(FirmwareError):
                    read_sections(self.image)

    def test_unsafe_and_duplicate_section_names_are_rejected(self):
        for name in ("../escape", "nested/escape", "a\\b", "manifest.json", "md1_dbginfo.csv",
                     "MD1ROM", "CON", "", "file."):
            with self.subTest(name=name):
                self.write_image(image_data([("md1rom", b"CODE"), (name, b"BAD")]))
                with self.assertRaises(FirmwareError):
                    extract_image(self.image, self.output, all_sections=True)
                self.assertFalse(self.output.exists())

    def test_existing_output_is_never_overwritten(self):
        self.write_image()
        self.output.mkdir()
        marker = self.output / "keep"
        marker.write_text("original")
        with self.assertRaisesRegex(FirmwareError, "already exists"):
            extract_image(self.image, self.output)
        self.assertEqual(marker.read_text(), "original")

    def test_malformed_debug_does_not_publish_partial_output(self):
        self.write_image(image_data([("md1rom", b"CODE"), ("md1_dbginfo", b"broken")]))
        with self.assertRaisesRegex(FirmwareError, "LZMA"):
            extract_image(self.image, self.output)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".jaymt-*")), [])

    def test_truncated_lzma_is_rejected(self):
        self.write_image(image_data([("md1rom", b"CODE"), ("md1_dbginfo", debug_data()[:-8])]))
        with self.assertRaisesRegex(FirmwareError, "Truncated LZMA"):
            extract_image(self.image, self.output)

    def test_unterminated_debug_string_raises_instead_of_hanging(self):
        payload = lzma.compress(b"\xff" * 100)
        self.write_image(image_data([("md1rom", b"CODE"), ("md1_dbginfo", payload)]))
        with self.assertRaisesRegex(FirmwareError, "Unterminated"):
            extract_image(self.image, self.output)

    def test_invalid_debug_offsets_are_rejected(self):
        payload = bytearray(debug_data(compress=False))
        offset = len(b"\0" * 0x1c + b"MD1\0MT6768\0MOLY.TEST\0BUILD.TEST\0")
        struct.pack_into("<I", payload, offset, len(payload) + 100)
        self.write_image(image_data([("md1rom", b"CODE"), ("md1_dbginfo", lzma.compress(payload))]))
        with self.assertRaisesRegex(FirmwareError, "offsets"):
            extract_image(self.image, self.output)

    def test_negative_function_sizes_are_rejected(self):
        self.write_image(image_data([("md1rom", b"CODE"),
                                    ("md1_dbginfo", debug_data([("bad", 100, 1)]))]))
        with self.assertRaisesRegex(FirmwareError, "Negative function size"):
            extract_image(self.image, self.output)

    def test_debug_decompression_is_bounded(self):
        payload = lzma.compress(b"A" * (2 * 1024 * 1024), preset=0)
        self.write_image(image_data([("md1rom", b"CODE"), ("md1_dbginfo", payload)]))
        with self.assertRaisesRegex(FirmwareError, "exceeds"):
            extract_image(self.image, self.output, max_debug_size=1024 * 1024)

    def write_tar(self, members):
        archive_path = self.root / "CP_firmware.tar.md5"
        with tarfile.open(archive_path, "w") as archive:
            for name, content in members:
                member = tarfile.TarInfo(name)
                if content is None:
                    member.type = tarfile.SYMTYPE
                    member.linkname = "/elsewhere"
                    archive.addfile(member)
                else:
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
        # Samsung tar.md5 files append a checksum after the tar end blocks.
        with archive_path.open("ab") as archive:
            archive.write(b"0123456789abcdef0123456789abcdef  CP_firmware.tar\n")
        return archive_path

    def test_legacy_cp_tar_extracts_only_selected_image(self):
        archive = self.write_tar([("nested/md1img.img", image_data()),
                                  ("../../should-never-be-extracted", b"IGNORE"),
                                  ("unrelated.bin", b"LARGE UNRELATED FILE")])
        manifest = extract_image(archive, self.output)
        self.assertEqual(manifest["debug"]["symbol_count"], 2)
        self.assertEqual({p.name for p in self.output.iterdir()},
                         {"md1rom", "md1_dbginfo.csv", "manifest.json"})
        self.assertEqual(manifest["source"]["sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())

    def test_archive_ambiguity_links_and_traversal_are_rejected(self):
        cases = [[], [("md1img.img", image_data()), ("nested/md1img.img", image_data())],
                 [("../md1img.img", image_data())], [("/md1img.img", image_data())],
                 [("md1img.img", None)]]
        for members in cases:
            with self.subTest(members=[name for name, _ in members]):
                archive = self.write_tar(members)
                with self.assertRaises(FirmwareError):
                    extract_image(archive, self.output)
                self.assertFalse(self.output.exists())

    def test_truncated_archive_is_a_clean_firmware_error(self):
        archive = self.write_tar([("md1img.img", image_data())])
        archive.write_bytes(archive.read_bytes()[:600])
        with self.assertRaises(FirmwareError):
            extract_image(archive, self.output)
        self.assertFalse(self.output.exists())

    def test_lz4_dependency_is_only_needed_for_lz4_inputs(self):
        # This process blocks any lz4 import while running the raw extraction CLI.
        self.write_image()
        root = Path(__file__).resolve().parents[1]
        script = (
            "import sys\n"
            "class BlockLz4:\n"
            " def find_spec(self, fullname, *args):\n"
            "  if fullname == 'lz4' or fullname.startswith('lz4.'):\n"
            "   raise ImportError('blocked for regression test')\n"
            "sys.meta_path.insert(0, BlockLz4())\n"
            "from jaymt.firmware import main\n"
            "raise SystemExit(main(sys.argv[1:]))\n"
        )
        result = subprocess.run([sys.executable, "-c", script, str(self.image),
                                 "-o", str(self.output)], cwd=root,
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        lz4_input = self.root / "image.lz4"
        lz4_input.write_bytes(b"\x04\x22\x4d\x18bogus")
        result = subprocess.run([sys.executable, "-c", script, str(lz4_input),
                                 "-o", str(self.root / "lz4out")], cwd=root,
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("optional dependency", result.stderr)

    @unittest.skipUnless(importlib.util.find_spec("lz4"), "optional lz4 package is not installed")
    def test_raw_and_archived_lz4_inputs(self):
        import lz4.frame
        compressed = lz4.frame.compress(image_data())
        self.image.write_bytes(compressed)
        extract_image(self.image, self.output)
        archive = self.write_tar([("md1img.img.lz4", compressed)])
        archived_output = self.root / "archived"
        extract_image(archive, archived_output)
        self.assertEqual((self.output / "md1rom").read_bytes(),
                         (archived_output / "md1rom").read_bytes())
        self.assertEqual((self.output / "md1_dbginfo.csv").read_bytes(),
                         (archived_output / "md1_dbginfo.csv").read_bytes())

    def test_cli_compatibility_wrapper_accepts_md1img(self):
        root = Path(__file__).resolve().parents[1]
        self.write_image()
        result = subprocess.run([sys.executable, str(root / "unpack_mtk_cp_update.py"),
                                 str(self.image), "-o", str(self.output)],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Ready in", result.stdout)

    def test_default_directory_names_and_progress(self):
        self.assertEqual(default_output_dir("md1img.img.lz4"), Path("md1img_extracted"))
        self.assertEqual(default_output_dir("CP_sample.tar.md5"), Path("CP_sample_extracted"))
        messages = []
        manifest = extract_image(self.write_image(), progress=messages.append)
        self.assertTrue(Path(manifest["output_dir"]).is_dir())
        self.assertGreater(len(messages), 3)


if __name__ == "__main__":
    unittest.main()
