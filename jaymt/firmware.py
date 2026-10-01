"""Bounded, streaming extraction of MediaTek md1img containers.

The container and debug layout follow FirmWire's MediaTek extraction workflow.
This module does not infer an instruction set from a container filename.
"""

import argparse
import csv
import hashlib
import json
import lzma
from pathlib import Path, PurePosixPath
import shutil
import struct
import sys
import tarfile
import tempfile
import time


MAGIC = 0x58881688
MAGIC2 = 0x58891689
HEADER = struct.Struct("<II32sIIIIIIIIII")
LZ4_MAGIC = b"\x04\x22\x4d\x18"
CHUNK_SIZE = 1024 * 1024
MAX_DEBUG_SIZE = 256 * 1024 * 1024
MAIN_IMG_NAME = "md1rom"
DBG_INFO_NAME = "md1_dbginfo"


class FirmwareError(ValueError):
    """The image is malformed or uses an unsupported format."""


def _digest(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_range(source, destination, size):
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        chunk = source.read(min(CHUNK_SIZE, remaining))
        if not chunk:
            raise FirmwareError("Truncated image payload")
        destination.write(chunk)
        digest.update(chunk)
        remaining -= len(chunk)
    return digest.hexdigest()


def _safe_name(name):
    # Section names become filenames on Windows as well as Unix.
    if (not name or name in (".", "..") or
            any(ord(c) < 32 or c in '/\\:*?"<>|' for c in name) or
            name.endswith((".", " "))):
        raise FirmwareError("Unsafe section name: {!r}".format(name))
    if name.split(".")[0].upper() in {
        "CON", "PRN", "AUX", "NUL",
        *["COM{}".format(n) for n in range(1, 10)],
        *["LPT{}".format(n) for n in range(1, 10)],
    }:
        raise FirmwareError("Reserved section name: {!r}".format(name))
    return name


def read_sections(path):
    """Return validated section records without loading their payloads."""
    file_size = Path(path).stat().st_size
    sections = []
    names = set()
    output_names = set()
    offset = 0
    with open(path, "rb") as source:
        while offset < file_size:
            source.seek(offset)
            header = source.read(HEADER.size)
            if sections and header.startswith(b"SignerVer"):
                break
            if len(header) != HEADER.size:
                raise FirmwareError("Truncated section header at 0x{:x}".format(offset))
            fields = HEADER.unpack(header)
            if fields[0] != MAGIC or fields[5] != MAGIC2:
                raise FirmwareError("Invalid md1img section magic at 0x{:x}".format(offset))
            try:
                name = _safe_name(fields[2].split(b"\0", 1)[0].decode("utf-8"))
            except UnicodeDecodeError as exc:
                raise FirmwareError("Invalid UTF-8 section name") from exc
            if (name.casefold() in ("manifest.json", "md1_dbginfo.csv") or
                    name.casefold() in names and name.casefold() in (MAIN_IMG_NAME, DBG_INFO_NAME)):
                raise FirmwareError("Duplicate or reserved output name: {}".format(name))
            names.add(name.casefold())
            output_name = name
            occurrence = 1
            while output_name.casefold() in output_names:
                occurrence += 1
                output_name = "{}.{}".format(name, occurrence)
            output_names.add(output_name.casefold())
            size = fields[1] | (fields[11] << 32)
            address = fields[3] | (fields[12] << 32)
            header_size = fields[6]
            alignment = fields[10] or 16
            if alignment & (alignment - 1) or alignment > CHUNK_SIZE:
                raise FirmwareError("Invalid section alignment for {}".format(name))
            data_offset = offset + header_size
            if header_size < HEADER.size or data_offset > file_size or size > file_size - data_offset:
                raise FirmwareError("Section {} extends outside the image".format(name))
            if fields[9] not in (0, 1):
                raise FirmwareError("Invalid image-list end flag for {}".format(name))
            sections.append({
                "name": name, "output_name": output_name, "offset": data_offset, "size": size,
                "header_offset": offset, "header_size": header_size,
                "load_address": address, "mode": fields[4],
                "header_version": fields[7], "image_type": fields[8],
                "alignment": alignment,
            })
            if fields[9] == 1:
                break
            end = data_offset + size
            offset = (end + alignment - 1) & ~(alignment - 1)
    if not sections:
        raise FirmwareError("Empty md1img image")
    if MAIN_IMG_NAME not in {section["name"] for section in sections}:
        raise FirmwareError("Image does not contain the required md1rom section")
    if not next(section["size"] for section in sections if section["name"] == MAIN_IMG_NAME):
        raise FirmwareError("The md1rom section is empty")
    return sections


def _decompress_debug(path, section, max_size):
    decoder = lzma.LZMADecompressor(memlimit=max_size)
    output = bytearray()
    with open(path, "rb") as source:
        source.seek(section["offset"])
        remaining = section["size"]
        try:
            while remaining and not decoder.eof:
                chunk = source.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise FirmwareError("Truncated md1_dbginfo section")
                remaining -= len(chunk)
                while True:
                    output.extend(decoder.decompress(chunk, max_length=max_size - len(output) + 1))
                    if len(output) > max_size:
                        raise FirmwareError("Debug info exceeds the {} MiB limit".format(max_size // CHUNK_SIZE))
                    if decoder.eof or decoder.needs_input:
                        break
                    chunk = b""
        except lzma.LZMAError as exc:
            raise FirmwareError("Invalid LZMA debug info: {}".format(exc)) from exc
    if not decoder.eof:
        raise FirmwareError("Truncated LZMA debug info")
    return output


def parse_debug_info(path, section, max_size=MAX_DEBUG_SIZE):
    """Parse metadata and (name, address, size) records exactly once."""
    data = _decompress_debug(path, section, max_size)
    cursor = 0x1c

    def string_at(offset, limit):
        end = data.find(b"\0", offset, min(limit, offset + CHUNK_SIZE))
        if end < 0:
            raise FirmwareError("Unterminated debug string at 0x{:x}".format(offset))
        return data[offset:end].decode("utf-8", errors="replace"), end + 1

    metadata = {}
    for field in ("target", "hwplatform", "moly_version", "build_time"):
        metadata[field], cursor = string_at(cursor, len(data))
    if cursor + 8 > len(data):
        raise FirmwareError("Truncated debug table offsets")
    function_offset, file_offset = struct.unpack_from("<II", data, cursor)
    function_offset += 0x10
    file_offset += 0x10
    if not cursor + 8 <= function_offset <= file_offset <= len(data):
        raise FirmwareError("Debug symbol table offsets are outside the debug data")
    cursor = function_offset
    symbols = []
    names = set()
    suffixes = {}
    while cursor < file_offset:
        name, cursor = string_at(cursor, file_offset)
        # Shipping A41 images end the function table with a NUL sentinel.
        # It is not a function record and must not consume the source-file table.
        if not name and not any(data[cursor:file_offset]):
            break
        if not name or "\n" in name or "\r" in name:
            raise FirmwareError("Invalid function symbol name")
        if cursor + 8 > file_offset:
            raise FirmwareError("Truncated function symbol {}".format(name))
        start, end = struct.unpack_from("<II", data, cursor)
        cursor += 8
        if end < start:
            raise FirmwareError("Negative function size for {}".format(name))
        base_name = name
        suffix = suffixes.get(base_name, 0)
        while name in names:
            suffix += 1
            name = base_name + "_" * suffix
        suffixes[base_name] = suffix
        names.add(name)
        symbols.append((name, start, end - start))
    return metadata, symbols


def _unpack_lz4(source_path, destination):
    try:
        import lz4.frame
    except ImportError as exc:
        raise FirmwareError("LZ4 input requires the optional dependency: python3 -m pip install lz4") from exc
    try:
        with lz4.frame.open(source_path, "rb") as source, open(destination, "wb") as target:
            shutil.copyfileobj(source, target, CHUNK_SIZE)
    except (RuntimeError, EOFError) as exc:
        raise FirmwareError("Invalid LZ4 image: {}".format(exc)) from exc


def _prepare_input(path, scratch, progress):
    with path.open("rb") as source:
        magic = source.read(4)
    if magic == struct.pack("<I", MAGIC):
        return path
    if magic == LZ4_MAGIC:
        progress("Decompressing LZ4 image")
        image = scratch / "image.raw"
        _unpack_lz4(path, image)
        return image
    try:
        archive = tarfile.open(path, "r:*")
    except tarfile.TarError as exc:
        raise FirmwareError("Input is not an md1img image, LZ4 frame, or CP tar archive") from exc
    with archive:
        candidates = []
        allowed = {"md1img", "md1img.img", "md1image", "md1image.img"}
        allowed |= {name + ".lz4" for name in allowed}
        for member in archive:
            member_path = PurePosixPath(member.name)
            if member_path.name.lower() not in allowed:
                continue
            if not member.isfile() or member_path.is_absolute() or ".." in member_path.parts or "\\" in member.name:
                raise FirmwareError("Unsafe md1img archive member: {}".format(member.name))
            candidates.append(member)
        if len(candidates) != 1:
            raise FirmwareError("CP archive must contain exactly one md1img image; found {}".format(len(candidates)))
        member = candidates[0]
        progress("Reading {} from CP archive".format(member.name))
        packed = scratch / "archive-image"
        with archive.extractfile(member) as source, packed.open("wb") as target:
            _copy_range(source, target, member.size)
    with packed.open("rb") as source:
        magic = source.read(4)
    if magic == LZ4_MAGIC:
        progress("Decompressing archived LZ4 image")
        image = scratch / "image.raw"
        _unpack_lz4(packed, image)
        return image
    if magic != struct.pack("<I", MAGIC):
        raise FirmwareError("Selected archive member is not an md1img image")
    return packed


def default_output_dir(input_path):
    path = Path(input_path)
    name = path.name
    for suffix in (".lz4", ".md5", ".tar", ".img"):
        if name.lower().endswith(suffix):
            name = name[:-len(suffix)]
    return path.parent / (name + "_extracted")


def extract_image(input_path, output_dir=None, *, all_sections=False,
                  progress=None, max_debug_size=MAX_DEBUG_SIZE):
    """Extract an image, publishing a new directory only after validation.

    By default write md1rom, md1_dbginfo.csv when present, and manifest.json.
    all_sections=True additionally preserves every container section verbatim.
    Existing directories are never overwritten. Returns the manifest dictionary.
    """
    started = time.monotonic()
    progress = progress or (lambda message: None)
    source_path = Path(input_path).expanduser().resolve()
    if not source_path.is_file():
        raise FirmwareError("Input file not found: {}".format(source_path))
    if max_debug_size <= 0:
        raise FirmwareError("max_debug_size must be positive")
    output_path = Path(output_dir or default_output_dir(source_path)).expanduser().absolute()
    if output_path.exists() or output_path.is_symlink():
        raise FirmwareError("Output already exists: {} (choose a new directory)".format(output_path))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".jaymt-", dir=output_path.parent) as temporary:
        scratch = Path(temporary)
        publish = scratch / "output"
        publish.mkdir()
        try:
            image = _prepare_input(source_path, scratch, progress)
        except (tarfile.TarError, EOFError) as exc:
            raise FirmwareError("Invalid or truncated CP archive: {}".format(exc)) from exc
        sections = read_sections(image)
        progress("Validated {} sections".format(len(sections)))
        debug_section = next((s for s in sections if s["name"] == DBG_INFO_NAME), None)
        metadata, symbols = {}, []
        if debug_section:
            progress("Decoding debug symbols")
            metadata, symbols = parse_debug_info(image, debug_section, max_debug_size)
            with (publish / "md1_dbginfo.csv").open("w", encoding="utf-8", newline="") as target:
                writer = csv.writer(target, delimiter=" ", lineterminator="\n")
                writer.writerow(("name", "addr", "size", "mode", "type"))
                writer.writerows((name, addr, size, "UNKNOWN", "FUNC") for name, addr, size in symbols)
            progress("Decoded {:,} symbols".format(len(symbols)))
        else:
            progress("No md1_dbginfo section; extracting ROM without symbols")
        with image.open("rb") as source:
            for section in sections:
                if not all_sections and section["name"] != MAIN_IMG_NAME:
                    continue
                progress("Extracting {} ({:,} bytes)".format(section["name"], section["size"]))
                source.seek(section["offset"])
                with (publish / section["output_name"]).open("wb") as target:
                    section["sha256"] = _copy_range(source, target, section["size"])
                section["extracted"] = True
        progress("Hashing input for provenance")
        image_hash = _digest(image)
        manifest = {
            "schema_version": 1,
            "tool": "jayMT_Analyzer",
            "source": {"name": source_path.name, "size": source_path.stat().st_size,
                       "sha256": image_hash if image == source_path else _digest(source_path)},
            "image": {"size": image.stat().st_size, "sha256": image_hash},
            "sections": sections,
            "debug": {"available": debug_section is not None,
                      "symbol_count": len(symbols), "metadata": metadata},
            "output_dir": str(output_path),
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
        with (publish / "manifest.json").open("w", encoding="utf-8") as target:
            json.dump(manifest, target, indent=2, ensure_ascii=False)
            target.write("\n")
        # A second check avoids replacing a directory created during extraction.
        if output_path.exists() or output_path.is_symlink():
            raise FirmwareError("Output appeared during extraction: {}".format(output_path))
        publish.rename(output_path)
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description="jayMT_Analyzer: prepare md1img firmware for Ghidra")
    parser.add_argument("image", help="raw md1img, md1img.img.lz4, or legacy CP tar archive")
    parser.add_argument("-o", "--output", help="new output directory (default: <image>_extracted)")
    parser.add_argument("--all-sections", action="store_true", help="also extract DSP, logs, certificates, and other sections")
    arguments = parser.parse_args(argv)
    prefix = "\033[32m[jayMT]\033[0m" if sys.stdout.isatty() else "[jayMT]"
    progress = lambda message: print("{} {}".format(prefix, message), flush=True)
    try:
        result = extract_image(arguments.image, arguments.output,
                               all_sections=arguments.all_sections, progress=progress)
    except (FirmwareError, OSError, tarfile.TarError) as exc:
        print("[jayMT] ERROR: {}".format(exc), file=sys.stderr)
        return 1
    progress("Ready in {:.2f}s: {}".format(result["elapsed_seconds"], result["output_dir"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
