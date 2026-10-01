# Analyze MediaTek MIPS32/MIPS16e2 md1rom with its exported debug symbols.
# @category jayMT_Analyzer
# @runtime Jython
# @menupath Tools.jayMT_Analyzer.Analyze MediaTek image
#
# Derived from FirmWire's Apache-2.0 analyze_mtk_image.py.
# SPDX-License-Identifier: Apache-2.0
"""Ghidra Jython script. Decline automatic analysis before running this script.

Arguments: SYMBOLS.csv [REPORT.json] [--no-bruteforce] [--verbose]
           [--max-emulation-steps=1000000] [--allow-stock-language]
All three original discovery stages run by default. Reported timings measure
this run; they are not estimates of speedup over an unmeasured baseline.
"""
from __future__ import division, print_function

import array
import json
import os
import struct
import sys
import time

sys.path.insert(0, str(getSourceFile().getParentFile()))
from jaymt_analysis_helpers import (BASE_ADDRESS, backwards_records, checked_range,
                                    parse_symbols, pointer_candidates, rom_address,
                                    uncovered_ranges)

from java.math import BigInteger
from ghidra.app.cmd.disassemble import MipsDisassembleCommand
from ghidra.app.emulator import EmulatorHelper
from ghidra.app.util import PseudoDisassembler, PseudoDisassemblerContext
from ghidra.program.model.address import AddressSet
from ghidra.program.model.lang import (InsufficientBytesException, UnknownContextException,
                                       UnknownInstructionException)
from ghidra.program.model.listing import BookmarkType
from ghidra.program.model.symbol import RefType, SourceType, SymbolUtilities
from ghidra.util.exception import CancelledException


class Analyzer(object):
    def __init__(self, options):
        self.options = options
        self.program = getCurrentProgram()
        if self.program is None:
            raise ValueError("Import md1rom before running jayMT_Analyzer")
        self.memory = self.program.getMemory()
        self.listing = self.program.getListing()
        self.functions = self.program.getFunctionManager()
        self.bookmarks = self.program.getBookmarkManager()
        self.pseudo = PseudoDisassembler(self.program)
        self.mode_cache = {}
        self.hints = {}
        self.report = {"tool": "jayMT_Analyzer", "status": "running", "warnings": [],
                       "stages": [], "unresolved_symbols": [], "mapping_blocks": [],
                       "heuristic_functions": [], "pointer_count": 0, "pointers_created": 0}

    def info(self, message):
        println("[jayMT] " + message)
        monitor.setMessage("jayMT: " + message)

    def detail(self, message):
        if self.options["verbose"]:
            println("[jayMT] " + message)

    def warn(self, message):
        self.report["warnings"].append(message)
        println("[jayMT] WARNING: " + message)

    def timed(self, name, operation):
        monitor.checkCanceled()
        self.info(name)
        started = time.time()
        result = operation()
        elapsed = time.time() - started
        self.report["stages"].append({"name": name, "seconds": round(elapsed, 3)})
        self.info("{}: {:.2f}s".format(name, elapsed))
        return result

    def address(self, value):
        return toAddr(value)

    def bytes(self, address, size):
        values = array.array("b", b"\0" * size)
        count = self.memory.getBytes(toAddr(address), values)
        if count != size:
            raise ValueError("short memory read at {:#x}: {}/{}".format(address, count, size))
        return values.tostring()

    def dword(self, address):
        address = rom_address(address, self.rom_size)
        return struct.unpack("<I", self.bytes(address, 4))[0]

    def mapped(self, start, end):
        if end <= start:
            return False
        return self.memory.getLoadedAndInitializedAddressSet().contains(toAddr(start), toAddr(end - 1))

    def disassemble(self, start, end=None, mode16=False):
        monitor.checkCanceled()
        restricted = AddressSet(toAddr(start), toAddr(end - 1)) if end is not None else None
        command = MipsDisassembleCommand(toAddr(start), restricted, mode16)
        # Queue events for the explicit stage boundaries, not a full analysis per function.
        command.enableCodeAnalysis(False)
        command.applyTo(self.program, monitor)
        monitor.checkCanceled()
        return command.getDisassembledAddressSet()

    def detect_mode(self, start):
        if start in self.hints:
            return self.hints[start]
        if start in self.mode_cache:
            return self.mode_cache[start]
        result = None
        context = self.program.getProgramContext()
        register = context.getRegister("ISA_MODE")
        for mode16, mnemonics in ((True, ("save",)), (False, ("special2", "save"))):
            if not mode16 and start % 4:
                continue
            probe_context = PseudoDisassemblerContext(context)
            probe_context.flowStart(toAddr(start))
            probe_context.setValue(register, BigInteger.ONE if mode16 else BigInteger.ZERO)
            try:
                instruction = self.pseudo.disassemble(toAddr(start), probe_context, False)
            except (InsufficientBytesException, UnknownContextException, UnknownInstructionException):
                instruction = None
            if instruction is not None and instruction.getMnemonicString().lower() in mnemonics:
                result = mode16
                break
        self.mode_cache[start] = result
        return result

    def function(self, start, end, name):
        name = SymbolUtilities.replaceInvalidChars(name, True)
        existing = self.functions.getFunctionAt(toAddr(start))
        if existing is not None:
            if existing.getName() != name:
                existing.setName(name, SourceType.IMPORTED)
            return True
        if self.listing.getInstructionAt(toAddr(start)) is None:
            return False
        created = createFunction(toAddr(start), name)
        # Keep Ghidra's flow-derived body: debug extents can include literal pools.
        # The old func.body.add(...) mutated only a temporary AddressSet.
        return created is not None

    def handle_function(self, entry, stage):
        start, end, name = entry
        monitor.checkCanceled()
        if not self.mapped(start, end):
            return False
        if self.functions.getFunctionAt(toAddr(start)) is not None:
            return self.function(start, end, name)
        if self.listing.getInstructionAt(toAddr(start)) is not None:
            return self.function(start, end, name)
        mode = self.detect_mode(start)
        if mode is not None:
            self.disassemble(start, mode16=mode)
            return self.function(start, end, name)
        if stage == 0:
            return False
        refs32 = any(ref.getReferenceType() != RefType.EXTERNAL_REF
                     for ref in getReferencesTo(toAddr(start)))
        refs16 = any(ref.getReferenceType() != RefType.EXTERNAL_REF
                     for ref in getReferencesTo(toAddr(start + 1)))
        if refs32 != refs16:
            self.disassemble(start, mode16=refs16)
            return self.function(start, end, name)
        if stage != 2:
            return False
        # Only trial-decode completely undefined ranges. Never clear existing user code/data.
        if not self.listing.isUndefined(toAddr(start), toAddr(end - 1)):
            return False
        for mode16 in (True, False):
            if not mode16 and start % 4:
                continue
            decoded = self.disassemble(start, end, mode16)
            valid = decoded is not None and not decoded.isEmpty()
            if valid and mode16:
                valid = decoded.getNumAddresses() >= (end - start) / 4
            if valid and self.function(start, end, name):
                self.report["heuristic_functions"].append({"name": name, "address": start,
                                                            "mode": "MIPS16" if mode16 else "MIPS32"})
                return True
            if decoded is not None and not decoded.isEmpty():
                clearListing(decoded)
        return False

    def discover_functions(self, entries):
        remaining = []
        for entry in entries:
            start, end, name = entry
            monitor.checkCanceled()
            if self.mapped(start, end):
                addEntryPoint(toAddr(start))
                remaining.append(entry)
            else:
                self.report["unresolved_symbols"].append({"name": name, "address": start,
                                                           "reason": "unmapped or empty extent"})
        stages = (0, 1) if self.options["no_bruteforce"] else (0, 1, 2)
        for stage in stages:
            if stage == 1:
                self.timed("Full automatic analysis", lambda: analyzeAll(self.program))
            started = time.time()
            count_before = len(remaining)
            while remaining:
                monitor.initialize(len(remaining))
                survivors = []
                for index, entry in enumerate(remaining):
                    if not self.handle_function(entry, stage):
                        survivors.append(entry)
                    if index % 1000 == 0:
                        self.info("Stage {}: {}/{} symbols".format(stage + 1, index, len(remaining)))
                    monitor.setProgress(index + 1)
                changed = len(survivors) != len(remaining)
                remaining = survivors
                analyzeChanges(self.program)
                monitor.checkCanceled()
                if not changed:
                    break
            elapsed = time.time() - started
            self.report["stages"].append({"name": "Function discovery {}".format(stage + 1),
                                           "seconds": round(elapsed, 3),
                                           "resolved": count_before - len(remaining),
                                           "remaining": len(remaining)})
            self.info("Stage {}: {} resolved, {} pending in {:.2f}s".format(
                stage + 1, count_before - len(remaining), len(remaining), elapsed))
        for start, end, name in remaining:
            createLabel(toAddr(start), SymbolUtilities.replaceInvalidChars(name, True), False)
            self.report["unresolved_symbols"].append({"name": name, "address": start,
                                                       "reason": "no confident function; label retained"})

    def add_map(self, name, address, length, source=None, executable=False, writable=True):
        monitor.checkCanceled()
        if length == 0:
            return
        checked_range(address, length)
        existing = self.memory.getBlock(toAddr(address))
        if existing is not None:
            if existing.getStart().getOffset() <= address and existing.getEnd().getOffset() >= address + length - 1:
                self.detail("Mapping {} already covered by {}".format(name, existing.getName()))
                return
            raise ValueError("{} partially overlaps existing block {}".format(name, existing.getName()))
        proposed = AddressSet(toAddr(address), toAddr(address + length - 1))
        if self.memory.intersects(proposed):
            raise ValueError("{} overlaps an existing memory block".format(name))
        if source is not None:
            source = rom_address(source, self.rom_size)
            checked_range(source, length)
            if not self.mapped(source, source + length):
                raise ValueError("{} source {:#x}+{:#x} is not initialized".format(name, source, length))
            block = self.memory.createInitializedBlock(name, toAddr(address), length, 0, monitor, False)
            for offset in range(0, length, 1024 * 1024):
                monitor.checkCanceled()
                size = min(1024 * 1024, length - offset)
                values = array.array("b", self.bytes(source + offset, size))
                block.putBytes(toAddr(address + offset), values)
        else:
            block = self.memory.createUninitializedBlock(name, toAddr(address), length, False)
        block.setPermissions(True, writable, executable)
        self.report["mapping_blocks"].append({"name": name, "start": address, "size": length,
                                               "source": source, "executable": executable})

    def add_holes(self, ranges):
        if any(block.getName().startswith("sys_mem_") for block in self.memory.getBlocks()):
            return
        for start, end in ranges:
            checked_range(start, end - start)
            occupied = [(block.getStart().getOffset(), block.getEnd().getOffset() + 1)
                        for block in self.memory.getBlocks() if not block.isOverlay()]
            for left, right in uncovered_ranges(start, end, occupied):
                self.add_map("uninit_{:08x}_{:08x}".format(left, right), left, right - left)

    def spram(self, symbols, prefix, executable):
        family = ("custom_get_{}_Load_Base".format(prefix),
                  "custom_get_{}_{}_Base".format(prefix, "CODE" if executable else "DATA"),
                  "custom_get_{}_{}_End".format(prefix, "CODE" if executable else "DATA"))
        if not all(name in symbols for name in family):
            self.warn("{} mapping symbols missing; layout was not guessed".format(prefix))
            return
        tables = []
        for name in family:
            start, end = symbols[name]
            if end - start < 4:
                raise ValueError("mapping symbol {} is too short".format(name))
            table = self.dword(end - 4)
            tables.append((self.dword(table), self.dword(table + 4)))
        for cpu in range(2):
            source, destination, end = [table[cpu] for table in tables]
            self.add_map("{}_cpu{}".format(prefix.lower(), cpu), destination, end - destination,
                         source, executable=executable)

    def map_regions(self, symbols):
        self.spram(symbols, "ISPRAM", True)
        self.spram(symbols, "DSPRAM", False)
        if "INT_InitPerCoreRegion_C" in symbols:
            start, end = symbols["INT_InitPerCoreRegion_C"]
            # Two cores, four records each, walked backwards exactly once.
            for index, cursor in enumerate(backwards_records(start, end, 8, 5)):
                size, source, destination, bss_size, bss = [self.dword(cursor + i * 4) for i in range(5)]
                name = "cpu_{}_percore_region_{}".format(index // 4, 4 - index % 4)
                self.add_map(name, destination, size, source)
                self.add_map(name + "_bss", bss, bss_size)
        if "INT_InitL2cacheLockRegion_C" in symbols:
            start, end = symbols["INT_InitL2cacheLockRegion_C"]
            cursor = backwards_records(start, end, 1, 7)[0]
            size, destination, source, bss_size, bss = [self.dword(cursor + i * 4) for i in range(5)]
            self.add_map("L2CacheRegion", destination, size, source, executable=True, writable=False)
            self.add_map("L2CacheRegion_bss", bss, bss_size)
        if "INT_InitRegions_C" in symbols:
            names = ("CACHED_EXTSRAM_NVRAM_LTABLE", "Image_DYNAMIC_CACHEABLE_EXTSRAM_DEFAULT_NONCACHEABLE_RW",
                     "DYNAMIC_CACHEABLE_EXTSRAM_DEFAULT_CACHEABLE_RW", "DYNAMIC_CACHEABLE_EXTSRAM_DEFAULT_NONCACHEABLE_RW",
                     "DYNAMIC_CACHEABLE_EXTSRAM_DEFAULT_NONCACHEABLE_MCURW_HWRW", "DYNAMIC_CACHEABLE_EXTSRAM_DEFAULT_CACHEABLE_MCURW_HWRW",
                     "CACHED_EXTSRAM_IOCU2_MCURW_HWRW", "CACHED_EXTSRAM_IOCU3_READ_ALLOC_MCURW_HWRW", "EXTSRAM_MCURW_HWRW",
                     "CACHED_EXTSRAM_MCURW_HWRW", "EXTSRAM_DSP_TX", "EXTSRAM_DSP_RX", "CACHED_EXTSRAM")
            start, cursor = symbols["INT_InitRegions_C"]
            backwards_records(start, cursor, len(names), 5)
            for index in range(len(names) - 1, -1, -1):
                cursor -= 20
                if cursor < start:
                    raise ValueError("INT_InitRegions_C table extends beyond its symbol")
                size, source, destination, bss_size, bss = [self.dword(cursor + i * 4) for i in range(5)]
                if index == len(names) - 1:
                    # Last record stores [BSS start, BSS end], unlike the preceding sizes.
                    bss_size, bss = bss - bss_size, bss_size
                elif bss_size > destination:
                    cursor -= 4
                    if cursor < start:
                        raise ValueError("extended initialization record is out of bounds")
                    size, source, destination, skip, total, bss = [self.dword(cursor + i * 4) for i in range(6)]
                    # memset uses a skipped prefix and an overall length.
                    if skip > total:
                        raise ValueError("initialization record skip exceeds total BSS size")
                    bss, bss_size = bss + skip, total - skip
                self.add_map(names[index], destination, size, source)
                self.add_map(names[index] + "_bss", bss, bss_size)
        else:
            self.warn("INT_InitRegions_C absent; only supported discovered memory regions were mapped")
        if "custom_mk_ram_info" in symbols:
            start, end = symbols["custom_mk_ram_info"]
            if self.handle_function((start, end, "custom_mk_ram_info"), 0):
                self.add_holes(self.emulate_ram_info(start))
            else:
                self.warn("custom_mk_ram_info mode unresolved; emulation skipped")

    def emulate_ram_info(self, entry):
        helper = EmulatorHelper(self.program)
        try:
            helper.enableMemoryWriteTracking(True)
            helper.writeRegister(helper.getPCRegister(), entry)
            helper.writeRegister("ra", 0)
            helper.writeRegister("sp", 0xff000000)
            completed = False
            for step in range(self.options["max_emulation_steps"]):
                monitor.checkCanceled()
                if helper.getExecutionAddress().getOffset() == 0:
                    completed = True
                    break
                if not helper.step(monitor):
                    monitor.checkCanceled()
                    self.warn("RAM-info emulation failed: {}".format(helper.getLastError()))
                    return []
            if not completed:
                self.warn("RAM-info emulation reached {} instructions; partial output ignored".format(
                    self.options["max_emulation_steps"]))
                return []
            candidates = []
            for interval in helper.getTrackedMemoryWriteSet():
                # Intersect ranges rather than iterating every tracked byte.
                left = max(interval.getMinAddress().getOffset(), 0x64000000)
                right = min(interval.getMaxAddress().getOffset() + 1, 0x65000000)
                aligned = (left + 3) & ~3
                if aligned < right:
                    candidates.append(aligned)
            if not candidates:
                self.warn("RAM-info emulation wrote no recognizable output table")
                return []
            data = array.array("b", helper.readMemory(toAddr(min(candidates)), 0x400)).tostring()
            ranges = []
            for offset in range(0, len(data), 8):
                address, size = struct.unpack_from("<II", data, offset)
                if size:
                    ranges.append(checked_range(address, size))
            return ranges
        finally:
            helper.dispose()

    def create_pointers(self):
        entries = set(function.getEntryPoint().getOffset() for function in self.functions.getFunctions(True))
        datatype = self.program.getDataTypeManager().getPointer(None)
        blocks = [self.main_block]
        for name in ("L2CacheRegion", "dspram_cpu0", "ispram_cpu0", "CACHED_EXTSRAM"):
            block = self.memory.getBlock(name)
            if block is not None and block not in blocks and block.isInitialized():
                blocks.append(block)
        for block in blocks:
            start, size = block.getStart().getOffset(), block.getSize()
            # Align chunks to absolute word boundaries; never read a trailing partial word.
            first = (-start) % 4
            monitor.initialize(size)
            for offset in range(first, size, 1024 * 1024):
                monitor.checkCanceled()
                length = min(1024 * 1024, size - offset)
                data = self.bytes(start + offset, length)
                for location, target in pointer_candidates(data, start + offset, entries):
                    address, end = toAddr(location), toAddr(location + 3)
                    if self.functions.getFunctionContaining(address) is not None:
                        continue
                    existing = self.listing.getDataAt(address)
                    if existing is not None and existing.isPointer():
                        self.report["pointer_count"] += 1
                        continue
                    if not self.listing.isUndefined(address, end):
                        continue
                    createData(address, datatype)
                    self.report["pointer_count"] += 1
                    self.report["pointers_created"] += 1
                monitor.setProgress(offset + length)

    def cleanup_delay_slots(self):
        for function in self.functions.getFunctions(True):
            monitor.checkCanceled()
            last = self.listing.getInstructionContaining(function.getBody().getMaxAddress())
            if last is None or last.getDelaySlotDepth() <= 0:
                continue
            after = last.getMaxAddress().getOffset() + 1
            value = self.program.getProgramContext().getValue(
                self.program.getProgramContext().getRegister("ISA_MODE"), last.getAddress(), False)
            mode16 = value is not None and value.intValue() == 1
            width = 2 if mode16 else 4
            if self.mapped(after, after + width) and self.listing.isUndefined(toAddr(after), toAddr(after + width - 1)):
                self.disassemble(after, after + width, mode16)

    def cleanup_bookmarks(self):
        obsolete = []
        for bookmark in self.bookmarks.getBookmarksIterator(BookmarkType.ERROR):
            monitor.checkCanceled()
            if bookmark.getCategory() == "Bad Instruction" and self.listing.getInstructionAt(bookmark.getAddress()) is not None:
                obsolete.append(bookmark)
        for bookmark in obsolete:
            self.bookmarks.removeBookmark(bookmark)
        self.report["stale_error_bookmarks_removed"] = len(obsolete)

    def run(self):
        language = str(self.program.getLanguageID())
        self.report["language"] = language
        if language != "MIPS:LE:32:jaymt":
            if not self.options["allow_stock_language"] or language != "MIPS:LE:32:default":
                raise ValueError("Use the bundled MIPS:LE:32:jaymt language, got {}".format(language))
            self.warn("Stock language explicitly allowed; custom MediaTek instructions may be missing")
        if self.program.getProgramContext().getRegister("ISA_MODE") is None:
            raise ValueError("language lacks ISA_MODE context register")
        main = self.memory.getBlock(toAddr(BASE_ADDRESS))
        if main is None:
            main = self.memory.getBlock(toAddr(0))
            if main is None or main.getStart().getOffset() != 0:
                raise ValueError("md1rom must be imported at 0 or 0x90000000")
            self.program.setImageBase(toAddr(BASE_ADDRESS), True)
        self.main_block = self.memory.getBlock(toAddr(BASE_ADDRESS))
        if self.main_block.getStart().getOffset() != BASE_ADDRESS or not self.main_block.isInitialized():
            raise ValueError("expected initialized md1rom block starting at 0x90000000")
        self.main_block.setWrite(False)
        self.main_block.setExecute(True)
        self.rom_size = self.main_block.getSize()
        self.report["rom_bytes"] = self.rom_size
        with open(self.options["symbols"], "r") as stream:
            entries, self.hints = parse_symbols(stream, self.rom_size)
        self.report["symbol_count"] = len(entries)
        symbols = dict((name, (start, end)) for start, end, name in entries)
        if language == "MIPS:LE:32:jaymt":
            options = getCurrentAnalysisOptionsAndValues(self.program)
            if "jayMT MIPS Instruction Fix" not in options:
                raise ValueError("jayMT processor analyzer missing; install the complete extension")
            setAnalysisOption(self.program, "MIPS UnAlligned Instruction Fix", "false")
            setAnalysisOption(self.program, "jayMT MIPS Instruction Fix", "true")
        self.timed("Memory mapping", lambda: self.map_regions(symbols))
        self.discover_functions(entries)
        self.timed("Function pointers", self.create_pointers)
        self.timed("Delay-slot completion", self.cleanup_delay_slots)
        self.timed("Final incremental analysis", lambda: analyzeChanges(self.program))
        self.cleanup_bookmarks()
        self.report["function_count"] = self.functions.getFunctionCount()
        self.report["status"] = "completed_with_warnings" if (
            self.report["warnings"] or self.report["unresolved_symbols"] or self.report["heuristic_functions"]
        ) else "completed"
        self.info("{}: {} functions, {} pointers, {} unresolved, {} heuristic choices".format(
            self.report["status"], self.report["function_count"], self.report["pointer_count"],
            len(self.report["unresolved_symbols"]), len(self.report["heuristic_functions"])))


def script_options():
    result = {"symbols": None, "report": None, "no_bruteforce": False, "verbose": False,
              "max_emulation_steps": 1000000, "allow_stock_language": False}
    positional = []
    for argument in getScriptArgs():
        if argument in ("--no-bruteforce", "--verbose", "--allow-stock-language"):
            result[argument[2:].replace("-", "_")] = True
        elif argument.startswith("--max-emulation-steps="):
            result["max_emulation_steps"] = int(argument.split("=", 1)[1])
            if result["max_emulation_steps"] <= 0:
                raise ValueError("emulation instruction limit must be positive")
        elif argument.startswith("--"):
            raise ValueError("unknown script option: {}".format(argument))
        else:
            positional.append(argument)
    if len(positional) > 2:
        raise ValueError("expected SYMBOLS.csv [REPORT.json] followed by optional flags")
    if positional:
        result["symbols"] = positional[0]
        if len(positional) == 2:
            result["report"] = positional[1]
    elif isRunningHeadless():
        raise ValueError("headless analysis requires an explicit md1_dbginfo.csv path")
    else:
        adjacent = os.path.join(os.path.dirname(str(getProgramFile())), "md1_dbginfo.csv")
        result["symbols"] = adjacent if os.path.isfile(adjacent) else str(askFile("Choose md1_dbginfo.csv", "Choose"))
    if not os.path.isfile(result["symbols"]):
        raise ValueError("symbol file not found: {}".format(result["symbols"]))
    if result["report"] is None:
        result["report"] = os.path.join(os.path.dirname(os.path.abspath(result["symbols"])), "analysis-report.json")
    return result


def main():
    options = script_options()
    analyzer = None
    started = time.time()
    report = {"tool": "jayMT_Analyzer", "status": "failed"}
    try:
        analyzer = Analyzer(options)
        report = analyzer.report
        analyzer.run()
    except CancelledException:
        report["status"] = "cancelled"
        raise
    except Exception as error:
        report["status"] = "failed"
        report["error"] = str(error)
        raise
    finally:
        report["elapsed_seconds"] = round(time.time() - started, 3)
        with open(options["report"], "w") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
        println("[jayMT] Report: {}".format(options["report"]))


if __name__ == "__main__":
    main()
