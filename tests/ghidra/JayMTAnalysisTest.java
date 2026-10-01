// Verify the saved synthetic mixed-MIPS workflow fixture.
// @category jayMT.Tests
import java.math.BigInteger;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class JayMTAnalysisTest extends GhidraScript {
    private void function(long offset, String name) {
        Address address = toAddr(offset);
        Function function = currentProgram.getFunctionManager().getFunctionAt(address);
        if (function == null || !function.getName().equals(name)) {
            throw new AssertionError("Expected " + name + " at " + address + ", got " + function);
        }
    }

    @Override
    protected void run() throws Exception {
        function(0x90000000L, "return_test");
        function(0x90000010L, "compact_test");
        Instruction compact = getInstructionAt(toAddr(0x90000010L));
        if (compact == null || !compact.getMnemonicString().equals("save")) {
            throw new AssertionError("MIPS16 prologue was not preserved: " + compact);
        }
        BigInteger mode = currentProgram.getProgramContext().getValue(
            currentProgram.getRegister("ISA_MODE"), compact.getAddress(), false);
        if (!BigInteger.ONE.equals(mode)) {
            throw new AssertionError("MIPS16 ISA_MODE missing");
        }
        if (getInstructionAt(toAddr(0x90000004L)) == null) {
            throw new AssertionError("MIPS32 return delay slot missing");
        }
        for (long pointer : new long[] {0x90000030L, 0x90000034L}) {
            if (getDataAt(toAddr(pointer)) == null || !getDataAt(toAddr(pointer)).isPointer()) {
                throw new AssertionError("Function pointer missing at " + toAddr(pointer));
            }
        }
        println("JAYMT_ANALYSIS_TEST_PASS");
    }
}
