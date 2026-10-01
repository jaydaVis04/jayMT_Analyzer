// Regression checks for the compiled MediaTek language. Import any small raw binary first.
// @category jayMT.Tests
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.app.util.importer.MessageLog;
import jaymt.analysis.JayMTMipsPreAnalyzer;

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
        for (PcodeOp op : instruction.getPcode()) println(op.toString());
        throw new AssertionError(instruction + " missing p-code constant " + value);
    }

    private void verifyInsertion(Instruction instruction) {
        // Evaluate the integer p-code, so temporary representation/constant folding
        // changes do not obscure a regression in the actual INS result.
        Map<Address, Long> values = new HashMap<>();
        values.put(currentProgram.getRegister("v0").getAddress(), 0x12abL);
        values.put(currentProgram.getRegister("v1").getAddress(), 0xdeadbeefL);
        for (PcodeOp op : instruction.getPcode()) {
            Varnode[] inputs = op.getInputs();
            long[] v = new long[inputs.length];
            for (int i = 0; i < inputs.length; i++) {
                v[i] = inputs[i].isConstant() ? inputs[i].getOffset() : values.get(inputs[i].getAddress());
            }
            long result;
            switch (op.getOpcode()) {
                case PcodeOp.COPY: result = v[0]; break;
                case PcodeOp.INT_2COMP: result = -v[0]; break;
                case PcodeOp.INT_NEGATE: result = ~v[0]; break;
                case PcodeOp.INT_MULT: result = v[0] * v[1]; break;
                case PcodeOp.INT_SUB: result = v[0] - v[1]; break;
                case PcodeOp.INT_RIGHT: result = v[1] >= 64 ? 0 : v[0] >>> v[1]; break;
                case PcodeOp.INT_LEFT: result = v[1] >= 64 ? 0 : v[0] << v[1]; break;
                case PcodeOp.INT_AND: result = v[0] & v[1]; break;
                case PcodeOp.INT_OR: result = v[0] | v[1]; break;
                default: throw new AssertionError("Unexpected INS p-code: " + op);
            }
            values.put(op.getOutput().getAddress(), result & 0xffffffffL);
        }
        long result = values.get(currentProgram.getRegister("v1").getAddress());
        if (result != 0xdeadbabfL) throw new AssertionError("INS produced " + Long.toHexString(result));
    }

    private void verifyPairs() throws Exception {
        Address base = currentProgram.getMinAddress().add(64);
        // swl v0,3(a0); swr v0,0(a0), then an invalid swl/swl pair.
        byte[] pairBytes = new byte[] {
            4, (byte) 0xf0, (byte) 0xe3, (byte) 0xd2,
            0x14, (byte) 0xf0, (byte) 0xe0, (byte) 0xd2,
            4, (byte) 0xf0, (byte) 0xe3, (byte) 0xd2,
            4, (byte) 0xf0, (byte) 0xe0, (byte) 0xd2};
        currentProgram.getMemory().setBytes(base, pairBytes);
        AddressSet range = new AddressSet(base, base.add(pairBytes.length - 1));
        currentProgram.getProgramContext().setValue(currentProgram.getRegister("ISA_MODE"),
            base, range.getMaxAddress(), BigInteger.ONE);
        for (int i = 0; i < 4; i++) {
            DisassembleCommand cmd = new DisassembleCommand(base.add(i * 4), range, false);
            cmd.enableCodeAnalysis(false);
            if (!cmd.applyTo(currentProgram, monitor)) throw new AssertionError("Pair decoding failed");
        }
        new JayMTMipsPreAnalyzer().added(currentProgram, range, monitor, new MessageLog());
        Instruction first = currentProgram.getListing().getInstructionAt(base);
        Instruction second = currentProgram.getListing().getInstructionAt(base.add(4));
        if (first == null || second == null || !first.getMnemonicString().equals("swl") ||
                !second.getMnemonicString().equals("swr")) {
            throw new AssertionError("Pair re-disassembly lost instructions");
        }
        if (first.getPcode().length != 0) throw new AssertionError("Little-endian paired SWL should be a no-op");
        Register flag = currentProgram.getRegister("PAIR_INSTRUCTION_FLAG");
        if (BigInteger.ONE.equals(currentProgram.getProgramContext().getValue(flag, base.add(8), false))) {
            throw new AssertionError("Two SWL instructions were incorrectly paired");
        }
        println("PASS MIPS16e2 pair repair and non-pair rejection");
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
        verifyInsertion(decode(4, 0xf12b, 0x3264, "ins"));
        usesRegister(decode(5, 0xf004, 0x92c0, "ll"), "a0");
        usesRegister(decode(6, 0xf004, 0xd2c0, "sc"), "a0");
        decode(7, 0xf000, 0x6a20, "lui");
        verifyPairs();
        println("JAYMT_PROCESSOR_TEST_PASS");
    }
}
