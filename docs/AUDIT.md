# Repository audit and design

The starting point is FirmWire/ghidra commit `61a1b439af5f6d5ba7e92809c05145dbe44e5d97`. Its upstream base is `3e245c6f80b1fe6465a8d5f73c09bcd1fd823fb1`, a February 2022 Ghidra development snapshot. The source identifies itself as Ghidra 10.2 FIRMWIRE-MTK.

The audit inventoried the entire tracked tree, build configuration, dependency boundaries and commit delta, then read the custom extractor, analysis script, processor specifications, analyzer, and relevant Ghidra scheduling/launch APIs. It does not claim a line-by-line security audit of every inherited Ghidra feature.

## Why the old checkout is large

On the audited filesystem it occupies about 563 MiB: 347 MiB of Git metadata/history and about 216 MiB of source, documentation and assets, with 17,938 tracked files. The tree contains the entire GUI, debugger backends, unrelated CPU modules, decompiler, platform launchers, Eclipse integrations, GPL utilities, tests and build infrastructure.

Only **nine files** differ from the upstream base (1,975 added lines and 16 removed lines):

| Custom area | Why it matters |
| --- | --- |
| `unpack_mtk_cp_update.py` | Container extraction and debug-symbol export |
| `analyze_mtk_image.py` | Memory reconstruction, instruction modes, functions and pointers |
| `mips.sinc`, `mips16.sinc`, `mips32Instructions.sinc` | MediaTek DSP and MIPS16e2 instruction support |
| `MipsPreAnalyzer.java` | Paired-instruction correction |
| MIPS emulation state modifier | Comment-only change |
| `application.properties`, `README.md` | Release identity and workflow |

Removing unrelated processors from a full Ghidra build is unnecessary. This project keeps only the custom MIPS include closure and its compiler/processor specifications, packages it under the distinct `MIPS:LE:32:jaymt` language, and uses an installed Ghidra distribution for the shared application. The original checkout is retained locally as the reference. The new repository has its own concise history and preserves attribution.

## Defects addressed

| Original behavior | Replacement |
| --- | --- |
| CLI accepts only Samsung CP archives | Raw md1img first, optional CP/LZ4 compatibility |
| Extracts every archive member | Streams only the selected image; validates names and bounds |
| Copies full images/sections into memory | Bounded streaming copies |
| Decompresses debug metadata twice | One parse/export pass |
| Unterminated metadata strings can hang | Bounded parsing with explicit errors |
| Ignores function-symbol offset | Seeks the declared table offset |
| Repeated `list.remove()` on symbols | Linear survivor list |
| Reprobes instruction modes | Cached mode decisions |
| Analysis restart every 200 created functions | Explicit stage/batch analysis |
| Pointer scan calls into Java per dword | Chunked reads and Python candidate filtering |
| Function creation deletes all subsequent bookmarks | Retains diagnostics outside the relevant range/type |
| Per-core mapping cursor repeatedly reads one record | Advances through the records |
| RAM-hole mapping omits disjoint regions | Handles uncovered intervals |
| Firmware emulation can run forever | Instruction limit and guaranteed resource disposal |
| Hardcoded headless resource settings | Explicit worker and heap settings |
| Script failure can look like successful import | Machine-readable report and saved-project verification |

## Threading conclusions

The original Ghidra `SystemUtilities.getDefaultThreadPoolSize()` caps the default analysis pool at ten. `-max-cpu` is a limit, not a mechanism to raise that cap; `cpu.core.override` supplies an exact pool size. The original headless script also fixes `MAXMEM=2G`, `ParallelGCThreads=2`, and `CICompilerCount=2`. The new launcher calls Ghidra's common launcher directly with an explicit heap and CPU override, without those GC/JIT limits.

Concurrent writes into one Program are not safe optimization. The importer still performs ordered database modifications, while Ghidra can parallelize its supported analyzers. Algorithmic reductions and chunked reads target known repeated work. Any end-to-end speed claim must identify its firmware, machine, settings, runtime, and baseline.

## Remaining boundaries

The inherited mapping recognizers assume particular firmware initialization layouts. A raw container can hold a different CPU architecture or omit debug symbols. The preserved instruction set contains incomplete DSP semantics. This project records these limitations and reports unresolved analysis; it does not turn heuristic reverse engineering into guaranteed original-source recovery.

References: [FirmWire fork](https://github.com/FirmWire/ghidra), [original upstream base](https://github.com/NationalSecurityAgency/ghidra/tree/3e245c6f80b1fe6465a8d5f73c09bcd1fd823fb1), [Ghidra headless documentation](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/RuntimeScripts/support/analyzeHeadlessREADME.md), [FirmWire firmware corpus](https://zenodo.org/records/6516030).
