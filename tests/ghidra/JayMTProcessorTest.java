// Regression checks for the compiled MediaTek language. Import any small raw binary first.
// @category jayMT.Tests
import java.math.BigInteger;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class JayMTProcessorTest extends GhidraScript {
    private Instruction decode(int index, int first, int second, String mnemonic) throws Exception {
        Address address = currentProgram.getMinAddress().add(index * 8L);
        currentProgram.getListing().clearCodeUnits(address, address.add(7), false);
        currentProgram.getMemory().setBytes(address, new byte[] {
            (byte) first, (byte) (first >>> 8), (byte) second, (byte) (second >>> 8), 0, 0, 0, 0});
        Register mode = currentProgram.getRegister("ISA_MODE");
        currentProgram.getProgramContext().setValue(mode, address, address.add(7), BigInteger.ONE);
        DisassembleCommand command = new DisassembleCommand(address, new AddressSet(address, address.add(3)), false);
        command.enableCodeAnalysis(false);
        if (!command.applyTo(currentProgram, monitor)) {
            throw new AssertionError("Disassembly failed: " + command.getStatusMsg());
        }
        Instruction instruction = currentProgram.getListing().getInstructionAt(address);
        if (instruction == null || !instruction.getMnemonicString().equals(mnemonic) || instruction.getLength() != 4) {
            throw new AssertionError("Expected " + mnemonic + " at " + address + ", got " + instruction);
        }
        println("PASS decode " + instruction);
        return instruction;
    }

    private void usesRegister(Instruction instruction, String name) {
        Register register = currentProgram.getRegister(name);
        for (PcodeOp op : instruction.getPcode()) {
            for (Varnode input : op.getInputs()) {
                if (input.isRegister() && input.getAddress().equals(register.getAddress())) {
                    return;
                }
            }
        }
        throw new AssertionError(instruction + " does not read " + name);
    }

    private void hasConstant(Instruction instruction, int opcode, long value) {
        for (PcodeOp op : instruction.getPcode()) {
            if (op.getOpcode() != opcode) continue;
            for (Varnode input : op.getInputs()) {
                if (input.isConstant() && input.getOffset() == value) return;
            }
        }
        throw new AssertionError(instruction + " missing p-code constant " + value);
    }

    @Override
    protected void run() throws Exception {
        if (!currentProgram.getLanguageID().toString().equals("MIPS:LE:32:jaymt")) {
            throw new AssertionError("Load test fixture with the jayMT language");
        }
        usesRegister(decode(0, 0xf000, 0x9220, "lw"), "gp");
        usesRegister(decode(1, 0xf000, 0xd220, "sw"), "gp");
        usesRegister(decode(2, 0xf000, 0x0220, "addiu"), "gp");
        hasConstant(decode(3, 0xf007, 0x670c, "ei"), PcodeOp.INT_OR, 1);
        hasConstant(decode(4, 0xf12b, 0x3264, "ins"), PcodeOp.INT_RIGHT, 24);
        usesRegister(decode(5, 0xf004, 0x92c0, "ll"), "a0");
        usesRegister(decode(6, 0xf004, 0xd2c0, "sc"), "a0");
        decode(7, 0xf000, 0x6a20, "lui");
        println("JAYMT_PROCESSOR_TEST_PASS");
    }
}
