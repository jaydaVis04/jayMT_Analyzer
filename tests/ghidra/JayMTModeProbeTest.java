// Verify side-effect-free MIPS16 mode probing using the real Ghidra API.
// @category jayMT.Tests
import java.math.BigInteger;
import java.util.Objects;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoDisassemblerContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.ProgramContext;

public class JayMTModeProbeTest extends GhidraScript {
    @Override
    protected void run() throws Exception {
        ProgramContext context = currentProgram.getProgramContext();
        Address address = toAddr(0x90000010L);
        Register register = context.getRegister("ISA_MODE");
        BigInteger originalMode = context.getValue(register, address, false);
        Instruction originalInstruction = getInstructionAt(address);
        for (int mode = 0; mode <= 1; mode++) {
            PseudoDisassemblerContext probe = new PseudoDisassemblerContext(context);
            probe.setValue(register, address, BigInteger.valueOf(mode));
            probe.flowStart(address);
            Instruction instruction = new PseudoDisassembler(currentProgram).disassemble(address, probe, false);
            BigInteger actual = probe.getValue(register, false);
            if (actual == null || actual.intValue() != mode) {
                throw new AssertionError("Pseudo decode ignored requested ISA mode " + mode);
            }
            if (mode == 1 && (instruction == null || !instruction.getMnemonicString().equals("save"))) {
                throw new AssertionError("MIPS16 prologue was not decoded with the requested context");
            }
            println("mode=" + mode + " instruction=" + instruction);
        }
        if (!Objects.equals(originalMode, context.getValue(register, address, false))) {
            throw new AssertionError("Mode probe changed stored program context");
        }
        if (!Objects.equals(originalInstruction, getInstructionAt(address))) {
            throw new AssertionError("Mode probe changed the listing");
        }
        println("JAYMT_MODE_PROBE_TEST_PASS");
    }
}
