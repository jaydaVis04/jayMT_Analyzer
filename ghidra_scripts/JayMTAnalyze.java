// Analyze MediaTek MIPS32/MIPS16e2 md1rom using its exported debug symbols.
// @category jayMT_Analyzer
// @menupath Tools.jayMT_Analyzer.Analyze MediaTek image
// SPDX-License-Identifier: Apache-2.0
// Derived from FirmWire's Apache-2.0 MediaTek analysis script.

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

import com.google.gson.GsonBuilder;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.MipsDisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoDisassemblerContext;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;

/** Native Ghidra analysis; all three discovery stages run unless explicitly disabled. */
public class JayMTAnalyze extends GhidraScript {
    private static final long BASE = 0x90000000L;
    private static final long LIMIT = 0x100000000L;
    private static final int CHUNK = 1024 * 1024;
    private static final String LANGUAGE = "MIPS:LE:32:jaymt";

    private Memory memory;
    private Listing listing;
    private FunctionManager functions;
    private BookmarkManager bookmarks;
    private PseudoDisassembler pseudo;
    private MemoryBlock mainBlock;
    private long romSize;
    private Path csvPath;
    private Path reportPath;
    private boolean verbose;
    private boolean noBruteforce;
    private boolean allowStock;
    private Integer stackThreads;
    private int maxEmulationSteps = 1_000_000;
    private long pointersCreated;
    private long pointerCount;
    private long aliasLabelsCreated;
    private long unresolvedLabelsCreated;
    private final Map<Long, Boolean> hints = new HashMap<>();
    private final Map<Long, Boolean> modeCache = new HashMap<>();
    private final Set<Long> modeConflicts = new HashSet<>();
    private final Set<Long> importedFunctions = new HashSet<>();
    private final Map<String, Object> report = new LinkedHashMap<>();
    private final List<String> warnings = new ArrayList<>();
    private final List<Map<String, Object>> stages = new ArrayList<>();
    private final List<Map<String, Object>> unresolved = new ArrayList<>();
    private final List<Map<String, Object>> heuristic = new ArrayList<>();
    private final List<Map<String, Object>> mappings = new ArrayList<>();

    private static class Symbol {
        final long start, end;
        final String name;
        Symbol(long start, long end, String name) {
            this.start = start;
            this.end = end;
            this.name = name;
        }
    }

    @FunctionalInterface
    private interface Operation {
        void run() throws Exception;
    }

    private static Map<String, Object> record(Object... pairs) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) result.put((String) pairs[i], pairs[i + 1]);
        return result;
    }

    private static double seconds(long start) {
        return Math.round((System.nanoTime() - start) / 1_000_000.0) / 1000.0;
    }

    private void info(String message) {
        println("[jayMT] " + message);
        monitor.setMessage("jayMT: " + message);
    }

    private void warn(String message) {
        warnings.add(message);
        println("[jayMT] WARNING: " + message);
    }

    private void timed(String name, Operation operation) throws Exception {
        monitor.checkCancelled();
        info(name);
        long start = System.nanoTime();
        operation.run();
        double elapsed = seconds(start);
        stages.add(record("name", name, "seconds", elapsed));
        info(String.format(Locale.ROOT, "%s: %.2fs", name, elapsed));
    }

    @Override
    protected void run() throws Exception {
        long start = System.nanoTime();
        report.putAll(record("tool", "jayMT_Analyzer", "engine", "Java", "status", "failed",
            "ghidra_version", ghidra.framework.Application.getApplicationVersion(),
            "warnings", warnings, "stages", stages, "unresolved_symbols", unresolved,
            "heuristic_functions", heuristic, "mapping_blocks", mappings));
        try {
            options();
            initialize();
            analyzeImage();
        }
        catch (CancelledException error) {
            report.put("status", "cancelled");
            throw error;
        }
        catch (Exception error) {
            report.put("status", "failed");
            report.put("error", error.toString());
            throw error;
        }
        finally {
            report.put("elapsed_seconds", seconds(start));
            report.put("pointer_count", pointerCount);
            report.put("pointers_created", pointersCreated);
            report.put("named_function_count", importedFunctions.size());
            report.put("alias_labels_created", aliasLabelsCreated);
            report.put("unresolved_labels_created", unresolvedLabelsCreated);
            if (reportPath != null) {
                try (Writer writer = Files.newBufferedWriter(reportPath, StandardCharsets.UTF_8)) {
                    new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(report, writer);
                    writer.write('\n');
                }
                println("[jayMT] Report: " + reportPath);
            }
        }
    }

    private void options() throws Exception {
        List<String> positional = new ArrayList<>();
        for (String argument : getScriptArgs()) {
            if (argument.equals("--verbose")) verbose = true;
            else if (argument.equals("--no-bruteforce")) noBruteforce = true;
            else if (argument.equals("--allow-stock-language")) allowStock = true;
            else if (argument.startsWith("--stack-threads=")) {
                stackThreads = Integer.parseInt(argument.substring(argument.indexOf('=') + 1));
                if (stackThreads <= 0) throw new IllegalArgumentException("stack worker count must be positive");
            }
            else if (argument.startsWith("--max-emulation-steps=")) {
                maxEmulationSteps = Integer.parseInt(argument.substring(argument.indexOf('=') + 1));
                if (maxEmulationSteps <= 0) throw new IllegalArgumentException("emulation step limit must be positive");
            }
            else if (argument.startsWith("--")) throw new IllegalArgumentException("unknown option: " + argument);
            else positional.add(argument);
        }
        if (positional.size() > 2) throw new IllegalArgumentException("expected SYMBOLS.csv [REPORT.json]");
        if (!positional.isEmpty()) {
            csvPath = Paths.get(positional.get(0)).toAbsolutePath();
            if (positional.size() == 2) reportPath = Paths.get(positional.get(1)).toAbsolutePath();
        }
        else if (isRunningHeadless()) {
            throw new IllegalArgumentException("headless analysis requires an explicit md1_dbginfo.csv path");
        }
        else {
            if (currentProgram == null) throw new IllegalArgumentException("Import md1rom before running jayMT_Analyzer");
            File programFile = getProgramFile();
            Path adjacent = programFile == null ? null : programFile.toPath().toAbsolutePath().getParent().resolve("md1_dbginfo.csv");
            csvPath = adjacent != null && Files.isRegularFile(adjacent) ? adjacent : askFile("Choose md1_dbginfo.csv", "Choose").toPath().toAbsolutePath();
        }
        if (reportPath == null) reportPath = csvPath.getParent().resolve("analysis-report.json");
        if (!Files.isRegularFile(csvPath)) throw new IllegalArgumentException("symbol file not found: " + csvPath);
    }

    private void initialize() throws Exception {
        if (currentProgram == null) throw new IllegalArgumentException("Import md1rom before running jayMT_Analyzer");
        String language = currentProgram.getLanguageID().toString();
        report.put("language", language);
        if (!LANGUAGE.equals(language)) {
            if (!allowStock || !language.equals("MIPS:LE:32:default")) {
                throw new IllegalArgumentException("Use the bundled " + LANGUAGE + " language, got " + language);
            }
            warn("Stock language explicitly allowed; custom MediaTek instructions may be missing");
        }
        if (currentProgram.getProgramContext().getRegister("ISA_MODE") == null) {
            throw new IllegalArgumentException("language lacks ISA_MODE context register");
        }
        memory = currentProgram.getMemory();
        listing = currentProgram.getListing();
        functions = currentProgram.getFunctionManager();
        bookmarks = currentProgram.getBookmarkManager();
        pseudo = new PseudoDisassembler(currentProgram);
        mainBlock = memory.getBlock(toAddr(BASE));
        if (mainBlock == null) {
            mainBlock = memory.getBlock(toAddr(0));
            if (mainBlock == null || mainBlock.getStart().getOffset() != 0) {
                throw new IllegalArgumentException("md1rom must be imported at 0 or 0x90000000");
            }
            currentProgram.setImageBase(toAddr(BASE), true);
            mainBlock = memory.getBlock(toAddr(BASE));
        }
        if (mainBlock.getStart().getOffset() != BASE || !mainBlock.isInitialized()) {
            throw new IllegalArgumentException("expected initialized md1rom block starting at 0x90000000");
        }
        mainBlock.setWrite(false);
        mainBlock.setExecute(true);
        romSize = mainBlock.getSize();
        report.put("rom_bytes", romSize);
        if (LANGUAGE.equals(language)) {
            Map<String, String> options = getCurrentAnalysisOptionsAndValues(currentProgram);
            if (!options.containsKey("jayMT MIPS Instruction Fix")) {
                throw new IllegalArgumentException("jayMT processor analyzer missing; install the complete extension");
            }
            setAnalysisOption(currentProgram, "MIPS UnAlligned Instruction Fix", "false");
            setAnalysisOption(currentProgram, "jayMT MIPS Instruction Fix", "true");
        }
        Map<String, String> options = getCurrentAnalysisOptionsAndValues(currentProgram);
        String stackOption = "Stack.Max Threads";
        if (stackThreads != null) {
            if (!options.containsKey(stackOption)) throw new IllegalArgumentException("this Ghidra runtime does not expose " + stackOption);
            setAnalysisOption(currentProgram, stackOption, stackThreads.toString());
        }
        report.put("stack_threads", stackThreads == null ? options.get(stackOption) : stackThreads.toString());
    }

    private void analyzeImage() throws Exception {
        List<Symbol> symbols = readSymbols();
        report.put("symbol_count", symbols.size());
        Map<String, Symbol> byName = new HashMap<>();
        for (Symbol symbol : symbols) byName.put(symbol.name, symbol);
        timed("Memory mapping", () -> mapRegions(byName));
        timed("Seed justified instruction modes", () -> seedModes(symbols));
        discoverFunctions(symbols);
        timed("Function pointers", this::createPointers);
        timed("Delay-slot completion", this::cleanupDelaySlots);
        timed("Final incremental analysis", () -> analyzeChanges(currentProgram));
        cleanupBookmarks();
        report.put("function_count", functions.getFunctionCount());
        String status = warnings.isEmpty() && unresolved.isEmpty() && heuristic.isEmpty() ? "completed" : "completed_with_warnings";
        report.put("status", status);
        info(String.format(Locale.ROOT, "%s: %d functions, %d pointers, %d unresolved, %d heuristic choices", status,
            functions.getFunctionCount(), pointerCount, unresolved.size(), heuristic.size()));
    }

    /** Space-delimited CSV with RFC-style doubled quotes; supports names containing spaces. */
    public static List<String> csvFields(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean quoted = false;
        boolean started = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (quoted) {
                if (c == '"' && i + 1 < line.length() && line.charAt(i + 1) == '"') { field.append('"'); i++; }
                else if (c == '"') quoted = false;
                else field.append(c);
            }
            else if (c == '"' && !started) { quoted = true; started = true; }
            else if (c == ' ') {
                if (started) { fields.add(field.toString()); field.setLength(0); started = false; }
            }
            else { field.append(c); started = true; }
        }
        if (quoted) throw new IllegalArgumentException("unclosed CSV quote");
        if (started) fields.add(field.toString());
        return fields;
    }

    private static long number(String text) {
        return text.toLowerCase(Locale.ROOT).startsWith("0x") ? Long.parseLong(text.substring(2), 16) : Long.parseLong(text);
    }

    private List<Symbol> readSymbols() throws Exception {
        List<Symbol> result = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        try (BufferedReader reader = Files.newBufferedReader(csvPath, StandardCharsets.UTF_8)) {
            String line = reader.readLine();
            if (line == null) throw new IllegalArgumentException("symbol CSV is empty");
            List<String> header = csvFields(line.replace("\ufeff", ""));
            int nameColumn = header.indexOf("name"), addressColumn = header.indexOf("addr"), sizeColumn = header.indexOf("size"), modeColumn = header.indexOf("mode");
            if (nameColumn < 0 || addressColumn < 0 || sizeColumn < 0) throw new IllegalArgumentException("symbol CSV needs name, addr and size columns");
            int lineNumber = 1;
            while ((line = reader.readLine()) != null) {
                monitor.checkCancelled();
                lineNumber++;
                if (line.trim().isEmpty()) continue;
                try {
                    List<String> fields = csvFields(line);
                    String name = fields.get(nameColumn);
                    long raw = number(fields.get(addressColumn)), size = number(fields.get(sizeColumn));
                    long start = romAddress(raw & ~1L);
                    if (raw < 0 || raw >= LIMIT || size < 0 || size > LIMIT - start) throw new IllegalArgumentException("invalid symbol bounds");
                    String key = start + ":" + size + ":" + name;
                    if (!seen.add(key)) continue;
                    result.add(new Symbol(start, start + size, name));
                    String mode = modeColumn >= 0 && fields.size() > modeColumn ? fields.get(modeColumn).toUpperCase(Locale.ROOT) : "";
                    if ((raw & 1) != 0 || Arrays.asList("MIPS16", "MIPS16E", "MIPS16E2", "M16", "16").contains(mode)) hints.put(start, true);
                    else if (Arrays.asList("MIPS32", "M32", "32").contains(mode)) hints.put(start, false);
                }
                catch (RuntimeException error) {
                    throw new IllegalArgumentException("invalid symbol CSV row " + lineNumber + ": " + error.getMessage(), error);
                }
            }
        }
        if (result.isEmpty()) throw new IllegalArgumentException("symbol CSV contains no symbols");
        return result;
    }

    public static void checkedRange(long start, long length) {
        if (start < 0 || start >= LIMIT || length <= 0 || length > LIMIT - start) {
            throw new IllegalArgumentException(String.format("invalid 32-bit range: %x+%x", start, length));
        }
    }

    public static long romAddress(long address, long size) { return address >= 0 && address < size ? BASE + address : address; }

    private long romAddress(long address) { return romAddress(address, romSize); }

    public static List<Long> backwardsRecords(long start, long end, int count, int fields) {
        long width = fields * 4L;
        if (count < 0 || fields <= 0 || end < start || end - start < count * width) throw new IllegalArgumentException("mapping symbol is shorter than its expected table");
        List<Long> result = new ArrayList<>();
        for (int i = 0; i < count; i++) result.add(end - width * (i + 1));
        return result;
    }

    public static List<long[]> uncoveredRanges(long start, long end, List<long[]> occupied) {
        List<long[]> sorted = new ArrayList<>(occupied);
        sorted.sort(Comparator.comparingLong(item -> item[0]));
        List<long[]> result = new ArrayList<>();
        long cursor = start;
        for (long[] block : sorted) {
            if (block[1] <= cursor || block[0] >= end) continue;
            if (block[0] > cursor) result.add(new long[] {cursor, Math.min(block[0], end)});
            cursor = Math.max(cursor, block[1]);
            if (cursor >= end) break;
        }
        if (cursor < end) result.add(new long[] {cursor, end});
        return result;
    }

    private byte[] bytes(long address, int size) throws MemoryAccessException {
        byte[] result = new byte[size];
        int count = memory.getBytes(toAddr(address), result);
        if (count != size) throw new MemoryAccessException("short read at " + toAddr(address));
        return result;
    }

    private static long little32(byte[] bytes, int offset) {
        return (bytes[offset] & 255L) | ((bytes[offset + 1] & 255L) << 8) |
            ((bytes[offset + 2] & 255L) << 16) | ((bytes[offset + 3] & 255L) << 24);
    }

    private long dword(long address) throws MemoryAccessException {
        return Integer.toUnsignedLong(memory.getInt(toAddr(romAddress(address))));
    }

    private boolean mapped(long start, long end) {
        return end > start && memory.getLoadedAndInitializedAddressSet().contains(toAddr(start), toAddr(end - 1));
    }

    private AddressSet disassemble(long start, Long end, boolean mode16) throws Exception {
        monitor.checkCancelled();
        AddressSet restricted = end == null ? null : new AddressSet(toAddr(start), toAddr(end - 1));
        MipsDisassembleCommand command = new MipsDisassembleCommand(toAddr(start), restricted, mode16);
        command.enableCodeAnalysis(false);
        command.applyTo(currentProgram, monitor);
        monitor.checkCancelled();
        return command.getDisassembledAddressSet();
    }

    private Boolean detectMode(long start) throws Exception {
        if (hints.containsKey(start)) return hints.get(start);
        if (modeCache.containsKey(start)) return modeCache.get(start);
        Boolean result = null;
        ProgramContext context = currentProgram.getProgramContext();
        Register register = context.getRegister("ISA_MODE");
        for (boolean mode16 : new boolean[] {true, false}) {
            if (!mode16 && (start & 3) != 0) continue;
            PseudoDisassemblerContext probe = new PseudoDisassemblerContext(context);
            // Context writes during an active flow are delayed. Seed the address BEFORE flowStart.
            probe.setValue(register, toAddr(start), mode16 ? BigInteger.ONE : BigInteger.ZERO);
            probe.flowStart(toAddr(start));
            PseudoInstruction instruction;
            try { instruction = pseudo.disassemble(toAddr(start), probe, false); }
            catch (InsufficientBytesException | UnknownContextException | UnknownInstructionException error) { instruction = null; }
            if (instruction != null) {
                String mnemonic = instruction.getMnemonicString().toLowerCase(Locale.ROOT);
                if (mnemonic.equals("save") || (!mode16 && mnemonic.equals("special2"))) { result = mode16; break; }
            }
        }
        modeCache.put(start, result);
        return result;
    }

    private void seedModes(List<Symbol> symbols) throws Exception {
        Register register = currentProgram.getRegister("ISA_MODE");
        monitor.initialize(symbols.size());
        int index = 0, seeded = 0;
        for (Symbol symbol : symbols) {
            monitor.checkCancelled();
            if (mapped(symbol.start, symbol.end)) {
                Boolean mode = detectMode(symbol.start);
                Address address = toAddr(symbol.start);
                // Only seed undefined entry bytes. Do not overwrite existing instructions,
                // data, user contexts, or an entire debug extent containing literal pools.
                if (mode != null && listing.isUndefined(address, address)) {
                    currentProgram.getProgramContext().setValue(register, address, address, mode ? BigInteger.ONE : BigInteger.ZERO);
                    seeded++;
                }
            }
            if (++index % 5000 == 0) info("Mode seeds: " + index + "/" + symbols.size());
            monitor.setProgress(index);
        }
        report.put("mode_seeds", seeded);
    }

    private boolean label(long start, String name) throws Exception {
        Address address = toAddr(start);
        for (ghidra.program.model.symbol.Symbol symbol : currentProgram.getSymbolTable().getSymbols(address)) {
            if (symbol.getName().equals(name)) return false;
        }
        currentProgram.getSymbolTable().createLabel(address, name, SourceType.IMPORTED);
        return true;
    }

    private boolean function(Symbol symbol) throws Exception {
        String name = SymbolUtilities.replaceInvalidChars(symbol.name, true);
        Function existing = functions.getFunctionAt(toAddr(symbol.start));
        if (existing != null) {
            SourceType source = existing.getSymbol().getSource();
            if (!importedFunctions.contains(symbol.start) && (source == SourceType.DEFAULT || source == SourceType.ANALYSIS)) existing.setName(name, SourceType.IMPORTED);
            else if (!existing.getName().equals(name) && label(symbol.start, name)) aliasLabelsCreated++;
            importedFunctions.add(symbol.start);
            return true;
        }
        if (listing.getInstructionAt(toAddr(symbol.start)) == null) return false;
        // Debug extents may include literal pools. Preserve Ghidra's flow-derived body.
        Function created = createFunction(toAddr(symbol.start), name);
        if (created != null) {
            // Auto-detected thunks may inherit a DEFAULT symbol from their target.
            // setSource cannot cross DEFAULT; assigning the name/source together can.
            created.setName(name, SourceType.IMPORTED);
            importedFunctions.add(symbol.start);
        }
        return created != null;
    }

    private boolean hasDataReference(long address) {
        for (Reference reference : currentProgram.getReferenceManager().getReferencesTo(toAddr(address))) {
            if (reference.getReferenceType().isData()) return true;
        }
        return false;
    }

    private boolean handleFunction(Symbol symbol, int stage) throws Exception {
        long start = symbol.start, end = symbol.end;
        monitor.checkCancelled();
        if (!mapped(start, end)) return false;
        Boolean mode = detectMode(start);
        Instruction instruction = listing.getInstructionAt(toAddr(start));
        if (instruction != null && mode != null) {
            BigInteger actual = currentProgram.getProgramContext().getValue(currentProgram.getRegister("ISA_MODE"), toAddr(start), false);
            boolean actual16 = BigInteger.ONE.equals(actual);
            if (actual16 != mode) {
                Function existing = functions.getFunctionAt(toAddr(start));
                Function owner = functions.getFunctionContaining(toAddr(start));
                SourceType source = existing == null ? null : existing.getSymbol().getSource();
                boolean automatic = source == SourceType.ANALYSIS || source == SourceType.DEFAULT;
                if (automatic && existing.equals(owner)) {
                    AddressSet body = existing.getBody().intersect(new AddressSet(toAddr(start), toAddr(end - 1)));
                    removeFunction(existing);
                    clearListing(body);
                    disassemble(start, null, mode);
                }
                else {
                    if (modeConflicts.add(start)) warn(String.format("%s at %x: existing code conflicts with inferred ISA mode; preserved for review", symbol.name, start));
                    return false;
                }
            }
        }
        if (functions.getFunctionAt(toAddr(start)) != null || listing.getInstructionAt(toAddr(start)) != null) return function(symbol);
        if (mode != null) {
            addEntryPoint(toAddr(start));
            disassemble(start, null, mode);
            return function(symbol);
        }
        if (stage == 0) return false;
        // Low-bit mode inference applies to pointer DATA references, never direct call targets.
        boolean refs32 = hasDataReference(start), refs16 = hasDataReference(start + 1);
        if (refs32 != refs16) {
            addEntryPoint(toAddr(start));
            disassemble(start, null, refs16);
            return function(symbol);
        }
        if (stage != 2 || !listing.isUndefined(toAddr(start), toAddr(end - 1))) return false;
        for (boolean mode16 : new boolean[] {true, false}) {
            if (!mode16 && (start & 3) != 0) continue;
            AddressSet decoded = disassemble(start, end, mode16);
            boolean valid = decoded != null && !decoded.isEmpty();
            if (valid && mode16) valid = decoded.getNumAddresses() >= (end - start) / 4.0;
            if (valid && function(symbol)) {
                addEntryPoint(toAddr(start));
                heuristic.add(record("name", symbol.name, "address", start, "mode", mode16 ? "MIPS16" : "MIPS32"));
                return true;
            }
            if (decoded != null && !decoded.isEmpty()) clearListing(decoded);
        }
        return false;
    }

    private void discoverFunctions(List<Symbol> symbols) throws Exception {
        List<Symbol> remaining = new ArrayList<>();
        for (Symbol symbol : symbols) {
            monitor.checkCancelled();
            if (mapped(symbol.start, symbol.end)) remaining.add(symbol);
            else unresolved.add(record("name", symbol.name, "address", symbol.start, "reason", "unmapped or empty extent"));
        }
        for (int stage = 0; stage < (noBruteforce ? 2 : 3); stage++) {
            if (stage == 1) timed("Full automatic analysis", () -> analyzeAll(currentProgram));
            long started = System.nanoTime();
            int before = remaining.size();
            while (!remaining.isEmpty()) {
                monitor.initialize(remaining.size());
                List<Symbol> survivors = new ArrayList<>();
                int index = 0;
                for (Symbol symbol : remaining) {
                    if (!handleFunction(symbol, stage)) survivors.add(symbol);
                    if (index % 1000 == 0) info(String.format("Stage %d: %d/%d symbols", stage + 1, index, remaining.size()));
                    monitor.setProgress(++index);
                }
                boolean changed = survivors.size() != remaining.size();
                remaining = survivors;
                analyzeChanges(currentProgram);
                monitor.checkCancelled();
                if (!changed) break;
            }
            double elapsed = seconds(started);
            stages.add(record("name", "Function discovery " + (stage + 1), "seconds", elapsed, "resolved", before - remaining.size(), "remaining", remaining.size()));
            info(String.format(Locale.ROOT, "Stage %d: %d resolved, %d pending in %.2fs", stage + 1, before - remaining.size(), remaining.size(), elapsed));
        }
        for (Symbol symbol : remaining) {
            if (label(symbol.start, SymbolUtilities.replaceInvalidChars(symbol.name, true))) unresolvedLabelsCreated++;
            unresolved.add(record("name", symbol.name, "address", symbol.start, "reason", "no confident function; label retained"));
        }
    }

    private void addMap(String name, long address, long length, Long source, boolean executable, boolean writable) throws Exception {
        monitor.checkCancelled();
        if (length == 0) return;
        checkedRange(address, length);
        MemoryBlock existing = memory.getBlock(toAddr(address));
        if (existing != null) {
            if (existing.getStart().getOffset() <= address && existing.getEnd().getOffset() >= address + length - 1) {
                if (verbose) info("Mapping " + name + " already covered by " + existing.getName());
                return;
            }
            throw new IllegalArgumentException(name + " partially overlaps existing block " + existing.getName());
        }
        AddressSet proposed = new AddressSet(toAddr(address), toAddr(address + length - 1));
        if (memory.intersects(proposed)) throw new IllegalArgumentException(name + " overlaps an existing memory block");
        MemoryBlock block;
        if (source != null) {
            source = romAddress(source);
            checkedRange(source, length);
            if (!mapped(source, source + length)) throw new IllegalArgumentException(name + " source is not initialized");
            block = memory.createInitializedBlock(name, toAddr(address), length, (byte) 0, monitor, false);
            for (long offset = 0; offset < length; offset += CHUNK) {
                monitor.checkCancelled();
                int size = (int) Math.min(CHUNK, length - offset);
                block.putBytes(toAddr(address + offset), bytes(source + offset, size));
            }
        }
        else block = memory.createUninitializedBlock(name, toAddr(address), length, false);
        block.setPermissions(true, writable, executable);
        mappings.add(record("name", name, "start", address, "size", length, "source", source, "executable", executable));
    }

    private void addMap(String name, long address, long length, Long source) throws Exception {
        addMap(name, address, length, source, false, true);
    }

    private void addHoles(List<long[]> ranges) throws Exception {
        for (MemoryBlock block : memory.getBlocks()) if (block.getName().startsWith("sys_mem_")) return;
        for (long[] range : ranges) {
            checkedRange(range[0], range[1] - range[0]);
            List<long[]> occupied = new ArrayList<>();
            for (MemoryBlock block : memory.getBlocks()) {
                if (!block.isOverlay()) occupied.add(new long[] {block.getStart().getOffset(), block.getEnd().getOffset() + 1});
            }
            for (long[] hole : uncoveredRanges(range[0], range[1], occupied)) {
                addMap(String.format("uninit_%08x_%08x", hole[0], hole[1]), hole[0], hole[1] - hole[0], null);
            }
        }
    }

    private void spram(Map<String, Symbol> symbols, String prefix, boolean executable) throws Exception {
        String kind = executable ? "CODE" : "DATA";
        String[] names = {"custom_get_" + prefix + "_Load_Base", "custom_get_" + prefix + "_" + kind + "_Base", "custom_get_" + prefix + "_" + kind + "_End"};
        for (String name : names) {
            if (!symbols.containsKey(name)) { warn(prefix + " mapping symbols missing; layout was not guessed"); return; }
        }
        long[][] tables = new long[3][2];
        for (int i = 0; i < 3; i++) {
            Symbol symbol = symbols.get(names[i]);
            if (symbol.end - symbol.start < 4) throw new IllegalArgumentException("mapping symbol too short: " + names[i]);
            long table = dword(symbol.end - 4);
            tables[i][0] = dword(table);
            tables[i][1] = dword(table + 4);
        }
        for (int cpu = 0; cpu < 2; cpu++) addMap(prefix.toLowerCase(Locale.ROOT) + "_cpu" + cpu,
            tables[1][cpu], tables[2][cpu] - tables[1][cpu], tables[0][cpu], executable, true);
    }

    private long[] words(long start, int count) throws Exception {
        long[] result = new long[count];
        for (int i = 0; i < count; i++) result[i] = dword(start + i * 4L);
        return result;
    }

    private static void tableFits(Symbol symbol, int count, int fields) {
        if (symbol.end - symbol.start < count * fields * 4L) throw new IllegalArgumentException(symbol.name + " is shorter than its expected mapping table");
    }

    private void mapRegions(Map<String, Symbol> symbols) throws Exception {
        spram(symbols, "ISPRAM", true);
        spram(symbols, "DSPRAM", false);
        Symbol symbol = symbols.get("INT_InitPerCoreRegion_C");
        if (symbol != null) {
            tableFits(symbol, 8, 5);
            List<Long> records = backwardsRecords(symbol.start, symbol.end, 8, 5);
            for (int index = 0; index < records.size(); index++) {
                long[] item = words(records.get(index), 5);
                String name = "cpu_" + (index / 4) + "_percore_region_" + (4 - index % 4);
                addMap(name, item[2], item[0], item[1]);
                addMap(name + "_bss", item[4], item[3], null);
            }
        }
        symbol = symbols.get("INT_InitL2cacheLockRegion_C");
        if (symbol != null) {
            tableFits(symbol, 1, 7);
            long[] item = words(symbol.end - 28, 5);
            addMap("L2CacheRegion", item[1], item[0], item[2], true, false);
            addMap("L2CacheRegion_bss", item[4], item[3], null);
        }
        symbol = symbols.get("INT_InitRegions_C");
        if (symbol != null) {
            String[] names = {"CACHED_EXTSRAM_NVRAM_LTABLE", "Image_DYNAMIC_CACHEABLE_EXTSRAM_DEFAULT_NONCACHEABLE_RW",
                "DYNAMIC_CACHEABLE_EXTSRAM_DEFAULT_CACHEABLE_RW", "DYNAMIC_CACHEABLE_EXTSRAM_DEFAULT_NONCACHEABLE_RW",
                "DYNAMIC_CACHEABLE_EXTSRAM_DEFAULT_NONCACHEABLE_MCURW_HWRW", "DYNAMIC_CACHEABLE_EXTSRAM_DEFAULT_CACHEABLE_MCURW_HWRW",
                "CACHED_EXTSRAM_IOCU2_MCURW_HWRW", "CACHED_EXTSRAM_IOCU3_READ_ALLOC_MCURW_HWRW", "EXTSRAM_MCURW_HWRW",
                "CACHED_EXTSRAM_MCURW_HWRW", "EXTSRAM_DSP_TX", "EXTSRAM_DSP_RX", "CACHED_EXTSRAM"};
            tableFits(symbol, names.length, 5);
            long cursor = symbol.end;
            for (int i = names.length - 1; i >= 0; i--) {
                cursor -= 20;
                if (cursor < symbol.start) throw new IllegalArgumentException("initialization table exceeds symbol bounds");
                long[] item = words(cursor, 5);
                long size = item[0], source = item[1], destination = item[2], bssSize = item[3], bss = item[4];
                if (i == names.length - 1) { bss = item[3]; bssSize = item[4] - item[3]; }
                else if (bssSize > destination) {
                    cursor -= 4;
                    if (cursor < symbol.start) throw new IllegalArgumentException("extended initialization table exceeds symbol bounds");
                    item = words(cursor, 6);
                    size = item[0]; source = item[1]; destination = item[2];
                    long skip = item[3], total = item[4];
                    if (skip > total) throw new IllegalArgumentException("initialization skip exceeds total BSS size");
                    bss = item[5] + skip; bssSize = total - skip;
                }
                addMap(names[i], destination, size, source);
                addMap(names[i] + "_bss", bss, bssSize, null);
            }
        }
        else warn("INT_InitRegions_C absent; only supported discovered memory regions were mapped");
        symbol = symbols.get("custom_mk_ram_info");
        if (symbol != null) {
            if (handleFunction(symbol, 0)) addHoles(emulateRamInfo(symbol.start));
            else warn("custom_mk_ram_info mode unresolved; emulation skipped");
        }
    }

    private List<long[]> emulateRamInfo(long entry) throws Exception {
        EmulatorHelper helper = new EmulatorHelper(currentProgram);
        List<long[]> ranges = new ArrayList<>();
        try {
            helper.enableMemoryWriteTracking(true);
            helper.writeRegister(helper.getPCRegister(), entry);
            helper.writeRegister("ra", 0);
            helper.writeRegister("sp", 0xff000000L);
            boolean completed = false;
            for (int step = 0; step < maxEmulationSteps; step++) {
                monitor.checkCancelled();
                if (helper.getExecutionAddress().getOffset() == 0) { completed = true; break; }
                if (!helper.step(monitor)) {
                    monitor.checkCancelled();
                    warn("RAM-info emulation failed: " + helper.getLastError());
                    return ranges;
                }
            }
            if (!completed) { warn("RAM-info emulation reached " + maxEmulationSteps + " instructions; partial output ignored"); return ranges; }
            long first = Long.MAX_VALUE;
            for (AddressRange interval : helper.getTrackedMemoryWriteSet()) {
                long left = Math.max(interval.getMinAddress().getOffset(), 0x64000000L);
                long right = Math.min(interval.getMaxAddress().getOffset() + 1, 0x65000000L);
                long aligned = (left + 3) & ~3L;
                if (aligned < right) first = Math.min(first, aligned);
            }
            if (first == Long.MAX_VALUE) { warn("RAM-info emulation wrote no recognizable output table"); return ranges; }
            byte[] data = helper.readMemory(toAddr(first), 0x400);
            for (int offset = 0; offset < data.length; offset += 8) {
                long address = little32(data, offset), size = little32(data, offset + 4);
                if (size > 0) { checkedRange(address, size); ranges.add(new long[] {address, address + size}); }
            }
            return ranges;
        }
        finally { helper.dispose(); }
    }

    private void createPointers() throws Exception {
        Set<Long> entries = new HashSet<>();
        for (Function function : functions.getFunctions(true)) entries.add(function.getEntryPoint().getOffset());
        ghidra.program.model.data.DataType pointer = currentProgram.getDataTypeManager().getPointer(null);
        List<MemoryBlock> blocks = new ArrayList<>();
        blocks.add(mainBlock);
        for (String name : new String[] {"L2CacheRegion", "dspram_cpu0", "ispram_cpu0", "CACHED_EXTSRAM"}) {
            MemoryBlock block = memory.getBlock(name);
            if (block != null && block.isInitialized() && !blocks.contains(block)) blocks.add(block);
        }
        for (MemoryBlock block : blocks) {
            long start = block.getStart().getOffset(), size = block.getSize();
            monitor.initialize(size);
            for (long offset = (-start) & 3; offset < size; offset += CHUNK) {
                monitor.checkCancelled();
                int length = (int) Math.min(CHUNK, size - offset);
                byte[] data = bytes(start + offset, length);
                for (int i = 0; i + 4 <= length; i += 4) {
                    long target = little32(data, i);
                    if (!entries.contains(target & ~1L)) continue;
                    Address address = toAddr(start + offset + i);
                    if (functions.getFunctionContaining(address) != null) continue;
                    Data existing = listing.getDataAt(address);
                    if (existing != null && existing.isPointer()) { pointerCount++; continue; }
                    if (!listing.isUndefined(address, address.add(3))) continue;
                    createData(address, pointer);
                    pointerCount++; pointersCreated++;
                }
                monitor.setProgress(offset + length);
            }
        }
    }

    private void cleanupDelaySlots() throws Exception {
        for (Function function : functions.getFunctions(true)) {
            monitor.checkCancelled();
            Instruction last = listing.getInstructionContaining(function.getBody().getMaxAddress());
            if (last == null || last.getDelaySlotDepth() <= 0) continue;
            long after = last.getMaxAddress().getOffset() + 1;
            BigInteger value = currentProgram.getProgramContext().getValue(currentProgram.getRegister("ISA_MODE"), last.getAddress(), false);
            boolean mode16 = BigInteger.ONE.equals(value);
            int width = mode16 ? 2 : 4;
            if (mapped(after, after + width) && listing.isUndefined(toAddr(after), toAddr(after + width - 1))) disassemble(after, after + width, mode16);
        }
    }

    private void cleanupBookmarks() throws Exception {
        List<Bookmark> obsolete = new ArrayList<>();
        Iterator<Bookmark> iterator = bookmarks.getBookmarksIterator(BookmarkType.ERROR);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Bookmark bookmark = iterator.next();
            if (bookmark.getCategory().equals("Bad Instruction") && listing.getInstructionAt(bookmark.getAddress()) != null) obsolete.add(bookmark);
        }
        for (Bookmark bookmark : obsolete) bookmarks.removeBookmark(bookmark);
        report.put("stale_error_bookmarks_removed", obsolete.size());
        Map<String, Integer> errors = new TreeMap<>();
        List<Map<String, Object>> examples = new ArrayList<>();
        iterator = bookmarks.getBookmarksIterator(BookmarkType.ERROR);
        int count = 0;
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Bookmark bookmark = iterator.next();
            String category = bookmark.getCategory();
            errors.put(category, errors.getOrDefault(category, 0) + 1);
            count++;
            if (examples.size() < 100) examples.add(record("address", bookmark.getAddress().getOffset(), "category", category, "comment", bookmark.getComment()));
        }
        report.put("error_bookmarks_by_category", errors);
        report.put("error_bookmark_examples", examples);
        if (count > 0) warn(count + " analysis error bookmarks remain; see report examples and the Ghidra log");
    }
}
