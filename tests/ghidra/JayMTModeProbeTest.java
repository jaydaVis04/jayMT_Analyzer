// Verify side-effect-free MIPS16 mode probing using the real Ghidra API.
// @category jayMT.Tests
import java.math.BigInteger;
import java.util.Objects;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptUtil;
import generic.jar.ResourceFile;
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
        ResourceFile source = new ResourceFile(getSourceFile().getParentFile().getParentFile().getParentFile(), "ghidra_scripts/JayMTAnalyze.java");
        GhidraScript analyzer = GhidraScriptUtil.getProvider(source).getScriptInstance(source, new PrintWriter(System.out));
        analyzer.set(getState(), monitor, new PrintWriter(System.out));
        Method initialize = analyzer.getClass().getDeclaredMethod("initialize");
        initialize.setAccessible(true);
        initialize.invoke(analyzer);
        Method decode = analyzer.getClass().getDeclaredMethod("probeInstruction", long.class, boolean.class);
        decode.setAccessible(true);
        for (int mode = 0; mode <= 1; mode++) {
            Instruction instruction = (Instruction) decode.invoke(analyzer, address.getOffset(), mode == 1);
            BigInteger actual = instruction == null ? null : instruction.getValue(register, false);
            if (instruction != null && (actual == null || actual.intValue() != mode)) {
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
