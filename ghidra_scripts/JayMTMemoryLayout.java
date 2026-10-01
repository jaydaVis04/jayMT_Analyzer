// Print the current program's mapped memory regions without running analysis.
// @category jayMT_Analyzer
// @menupath Tools.jayMT_Analyzer.Print memory layout
// SPDX-License-Identifier: Apache-2.0

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;

public class JayMTMemoryLayout extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            printerr("Open md1rom in CodeBrowser first.");
            return;
        }
        StringBuilder text = new StringBuilder();
        text.append("jayMT_Analyzer memory layout: ").append(currentProgram.getName()).append('\n');
        text.append("Mapped Ghidra regions; end addresses are inclusive. Unmapped hardware is not listed.\n");
        text.append("Initialized means bytes exist in the program database, including synthesized zero-fill.\n\n");
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        int nameWidth = 28;
        for (MemoryBlock block : blocks) nameWidth = Math.max(nameWidth, block.getName().length());
        String format = "%-" + nameWidth + "s %-18s %-18s %12s %-3s %s%n";
        text.append(String.format(Locale.ROOT, format,
            "Region", "Start", "End (inclusive)", "Bytes", "RWX", "Initialized"));
        long total = 0;
        for (MemoryBlock block : blocks) {
            monitor.checkCancelled();
            String permissions = (block.isRead() ? "r" : "-") +
                (block.isWrite() ? "w" : "-") + (block.isExecute() ? "x" : "-");
            text.append(String.format(Locale.ROOT, format,
                block.getName(), block.getStart(), block.getEnd(), block.getSize(),
                permissions, block.isInitialized() ? "yes" : "no"));
            total += block.getSize();
        }
        text.append(String.format(Locale.ROOT, "%n%d regions; %d mapped bytes (%.2f MiB).%n",
            blocks.length, total, total / 1048576.0));
        text.append("Mapped bytes describe address ranges, not disk size or host RAM usage.\n");
        println(text.toString());
        String[] args = getScriptArgs();
        Path output = args.length == 1 ? Paths.get(args[0]).toAbsolutePath() : null;
        if (args.length > 1) throw new IllegalArgumentException("Usage: JayMTMemoryLayout.java [output.txt]");
        if (!isRunningHeadless() && output == null && askYesNo("Memory layout", "Save this layout as a text file?")) {
            output = askFile("Save memory layout", "Save").toPath();
        }
        if (output != null) {
            Files.write(output, text.toString().getBytes(StandardCharsets.UTF_8));
            println("[jayMT] Memory layout saved: " + output);
        }
    }
}
