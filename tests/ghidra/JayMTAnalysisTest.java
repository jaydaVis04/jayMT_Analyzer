// Verify the saved synthetic mixed-MIPS workflow fixture.
// @category jayMT.Tests
import java.math.BigInteger;
import java.io.PrintWriter;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptUtil;
import generic.jar.ResourceFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.program.model.mem.MemoryBlock;

public class JayMTAnalysisTest extends GhidraScript {
    private Class<?> analyzerClass;

    private Object nativeCall(String name, Class<?>[] types, Object... values) throws Exception {
        try {
            return analyzerClass.getMethod(name, types).invoke(null, values);
        }
        catch (InvocationTargetException wrapped) {
            if (wrapped.getCause() instanceof Exception) throw (Exception) wrapped.getCause();
            throw wrapped;
        }
    }

    @SuppressWarnings("unchecked")
    private List<long[]> uncovered(long start, long end, List<long[]> occupied) throws Exception {
        return (List<long[]>) nativeCall("uncoveredRanges", new Class<?>[] {long.class, long.class, List.class}, start, end, occupied);
    }

    private void checked(long start, long length) throws Exception {
        nativeCall("checkedRange", new Class<?>[] {long.class, long.class}, start, length);
    }

    private Object backwards(long start, long end, int count, int fields) throws Exception {
        return nativeCall("backwardsRecords", new Class<?>[] {long.class, long.class, int.class, int.class}, start, end, count, fields);
    }

    private Object romAddress(long address, long size) throws Exception {
        return nativeCall("romAddress", new Class<?>[] {long.class, long.class}, address, size);
    }

    private Object csvFields(String value) throws Exception {
        return nativeCall("csvFields", new Class<?>[] {String.class}, value);
    }

    private GhidraScript newParser() throws Exception {
        return (GhidraScript) analyzerClass.getDeclaredConstructor().newInstance();
    }

    private static void equal(Object expected, Object actual, String message) {
        if (!expected.equals(actual)) {
            throw new AssertionError(message + ": expected " + expected + ", got " + actual);
        }
    }

    private static void ranges(long[][] expected, List<long[]> actual) {
        if (actual.size() != expected.length) throw new AssertionError("Wrong RAM hole count");
        for (int i = 0; i < expected.length; i++) {
            if (!Arrays.equals(expected[i], actual.get(i))) throw new AssertionError("Wrong RAM hole at " + i);
        }
    }

    private void logicRegressions() throws Exception {
        ranges(new long[][] {{10, 20}}, uncovered(10, 20, Collections.emptyList()));
        ranges(new long[][] {{19, 20}}, uncovered(10, 20,
            Arrays.asList(new long[] {10, 19})));
        ranges(new long[][] {{20, 22}, {25, 30}}, uncovered(10, 30,
            Arrays.asList(new long[] {8, 20}, new long[] {12, 15}, new long[] {22, 25})));
        for (long[] invalid : new long[][] {{-1, 1}, {1, 0}, {1, -1}, {0xffffffffL, 2}, {1, Long.MAX_VALUE}}) {
            try {
                checked(invalid[0], invalid[1]);
                throw new AssertionError("Invalid mapping range accepted");
            }
            catch (IllegalArgumentException expected) { }
        }
        checked(0xffffffffL, 1);
        equal(Arrays.asList(180L, 160L, 140L, 120L, 100L, 80L, 60L, 40L),
            backwards(0, 200, 8, 5), "Per-core table records");
        try {
            backwards(0, 100, 8, 5);
            throw new AssertionError("Truncated mapping table accepted");
        }
        catch (IllegalArgumentException expected) { }
        equal(0x90000010L, romAddress(16, 768), "Low ROM alias");
        equal(0x64000000L, romAddress(0x64000000L, 768), "RAM address preservation");
        equal(Arrays.asList("quoted \"function\"", "17", "8", "UNKNOWN", "FUNC"),
            csvFields("\"quoted \"\"function\"\"\" 17 8 UNKNOWN FUNC"), "Escaped CSV quotes");
        try {
            csvFields("\"unterminated 17 8 UNKNOWN FUNC");
            throw new AssertionError("Unterminated CSV quote accepted");
        }
        catch (IllegalArgumentException expected) { }
        csvRegressions();
    }

    private static Field field(Object instance, String name) throws Exception {
        Field result = instance.getClass().getDeclaredField(name);
        result.setAccessible(true);
        return result;
    }

    private List<?> readCsv(String csv, GhidraScript parser) throws Exception {
        Path temporary = Files.createTempFile("jaymt-csv-regression-", ".csv");
        try {
            Files.write(temporary, csv.getBytes(StandardCharsets.UTF_8));
            parser.set(getState(), monitor, new PrintWriter(System.out));
            field(parser, "csvPath").set(parser, temporary);
            field(parser, "romSize").setLong(parser, 768);
            Method read = analyzerClass.getDeclaredMethod("readSymbols");
            read.setAccessible(true);
            try {
                return (List<?>) read.invoke(parser);
            }
            catch (InvocationTargetException wrapped) {
                if (wrapped.getCause() instanceof Exception) throw (Exception) wrapped.getCause();
                throw wrapped;
            }
        }
        finally {
            Files.deleteIfExists(temporary);
        }
    }

    private void csvRegressions() throws Exception {
        GhidraScript parser = newParser();
        List<?> symbols = readCsv("name addr size mode type\n\"quoted function\" 17 8 UNKNOWN FUNC\n" +
            "absolute 0x90000020 16 MIPS32 FUNC\nram 0x64000000 8 UNKNOWN FUNC\n", parser);
        equal(3, symbols.size(), "CSV symbol count");
        Object first = symbols.get(0);
        equal("quoted function", field(first, "name").get(first), "Quoted symbol name");
        equal(0x90000010L, field(first, "start").getLong(first), "Tagged entry normalization");
        equal(0x90000018L, field(first, "end").getLong(first), "Normalized symbol extent");
        Object ram = symbols.get(2);
        equal(0x64000000L, field(ram, "start").getLong(ram), "RAM symbol stays absolute");
        Map<?, ?> hints = (Map<?, ?>) field(parser, "hints").get(parser);
        equal(Boolean.TRUE, hints.get(0x90000010L), "Tagged MIPS16 mode hint");
        equal(Boolean.FALSE, hints.get(0x90000020L), "Explicit MIPS32 mode hint");
        for (String invalid : new String[] {"garbage\n", "name addr size\n", "name addr size\nbad no 2\n",
                "name addr size\nbad 1 -2\n", "name addr size\nbad 0xffffffff 8\n"}) {
            try {
                readCsv(invalid, newParser());
                throw new AssertionError("Malformed CSV accepted: " + invalid);
            }
            catch (IllegalArgumentException expected) { }
        }
    }

    private void function(long offset, String name) {
        Address address = toAddr(offset);
        Function function = currentProgram.getFunctionManager().getFunctionAt(address);
        if (function == null || !function.getName().equals(name)) {
            throw new AssertionError("Expected " + name + " at " + address + ", got " + function);
        }
    }

    @Override
    protected void run() throws Exception {
        ResourceFile source = GhidraScriptUtil.findScriptByName("JayMTAnalyze.java");
        if (source == null) throw new AssertionError("Native analyzer script missing from script path");
        analyzerClass = GhidraScriptUtil.getProvider(source).getScriptInstance(source, new PrintWriter(System.out)).getClass();
        logicRegressions();
        function(0x90000000L, "return_test");
        function(0x90000010L, "compact_test");
        function(0x90000040L, "unhinted_test");
        function(0x90000050L, "referenced_test");
        function(0x90000060L, SymbolUtilities.replaceInvalidChars("quoted function", true));
        function(0x90000070L, SymbolUtilities.replaceInvalidChars("quote\"function", true));
        function(0x90000100L, "INT_InitPerCoreRegion_C");
        boolean aliasFound = false;
        for (Symbol symbol : currentProgram.getSymbolTable().getSymbols(toAddr(0x90000000L))) {
            aliasFound |= symbol.getName().equals("return_alias");
        }
        if (!aliasFound) {
            throw new AssertionError("CSV function alias was discarded");
        }
        Instruction compact = getInstructionAt(toAddr(0x90000010L));
        if (compact == null || !compact.getMnemonicString().equals("save")) {
            throw new AssertionError("MIPS16 prologue was not preserved: " + compact);
        }
        BigInteger mode = currentProgram.getProgramContext().getValue(
            currentProgram.getRegister("ISA_MODE"), compact.getAddress(), false);
        if (!BigInteger.ONE.equals(mode)) {
            throw new AssertionError("MIPS16 ISA_MODE missing");
        }
        if (!BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(
                currentProgram.getRegister("ISA_MODE"), toAddr(0x90000040L), false))) {
            throw new AssertionError("Unhinted MIPS16 code was prematurely decoded as MIPS32");
        }
        if (getInstructionAt(toAddr(0x90000004L)) == null) {
            throw new AssertionError("MIPS32 return delay slot missing");
        }
        for (long pointer : new long[] {0x90000030L, 0x90000034L, 0x90000038L}) {
            if (getDataAt(toAddr(pointer)) == null || !getDataAt(toAddr(pointer)).isPointer()) {
                throw new AssertionError("Function pointer missing at " + toAddr(pointer));
            }
        }
        for (int index = 0; index < 8; index++) {
            Address copied = toAddr(0x64000000L + index * 0x10);
            MemoryBlock data = getMemoryBlock(copied);
            MemoryBlock bss = getMemoryBlock(copied.add(4));
            if (data == null || !data.isInitialized() || data.getSize() != 4 ||
                    currentProgram.getMemory().getInt(copied) != 0x03e00008) {
                throw new AssertionError("Distinct per-core copy record missing at " + copied);
            }
            if (bss == null || bss.isInitialized() || bss.getSize() != 4) {
                throw new AssertionError("Distinct per-core BSS record missing at " + copied.add(4));
            }
        }
        println("JAYMT_ANALYSIS_TEST_PASS");
    }
}
