# MediaTek processor support

The language ID is `MIPS:LE:32:jaymt`, with compiler `default`. It retains the
FirmWire fork's MIPS32, MIPS16e2, DSP/MT instruction definitions and microMIPS
include dependency. It does not replace Ghidra's built-in MIPS language.

The source comes from [FirmWire/ghidra](https://github.com/FirmWire/ghidra) commit
`61a1b439af5f6d5ba7e92809c05145dbe44e5d97`, based on NSA Ghidra commit
`3e245c6f80b1fe6465a8d5f73c09bcd1fd823fb1`. The upstream file hashes are recorded
in `extension/UPSTREAM.json`. Original Apache licensing and attribution remain
in the extension and every built ZIP.

Only six SLEIGH source files (373,931 bytes before corrections), one processor
specification, one compiler specification and the pair analyzer are needed from
the fork. The emulation Java change in FirmWire was comment-only. None of the
unrelated processor families, debugger, GUI source, build dependencies or old
Git history is needed in this repository. Ghidra itself remains a separately
installed runtime.

## Corrections and performance

The added MIPS16e2 `gp`-relative load/store/addiu semantics now read `gp`, instead
of incorrectly reading `sp`. `ei` sets Status bit 0, and `ins` computes its mask
using the register width in bits. Linked load/store use their encoded base
register; their p-code now includes the same reservation user operations as
Ghidra's MIPS32 instructions, with successful `sc` assigning 1 to its result.
These corrections were checked against the
[NSA MIPS16e2 definitions](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors/MIPS/data/languages/mips16.sinc).

`jayMT MIPS Instruction Fix` retains the MIPS16e2 pair handling, but traverses
defined instructions instead of every address byte. It restricts itself to the
jayMT language. Re-disassembly uses Ghidra's public API with flow following
disabled, preserving the original script's instruction-mode corrections
without reflection. The EXTEND prefix match is exact, and two left instructions
are no longer treated as a matching left/right pair.

The importer disables the built-in `MIPS UnAlligned Instruction Fix` option for
this custom language and enables `jayMT MIPS Instruction Fix`.

## What remains incomplete

FirmWire's DSP/MT extension constructors include many empty `#TODO` semantic
bodies. Their disassembly is preserved; those instructions do **not** have
complete p-code, so decompilation and emulation of affected code cannot be
claimed correct. The inherited definitions also contain unresolved instruction
pattern overlap notes and missing MIPS16e2 system instructions. No speed change
can recover absent ISA semantics or absent firmware symbols. ROM memory mapping
and heuristic mode detection must still be reviewed for unfamiliar chipsets.

Ghidra 11.4.2 is the validation target. More recent Ghidra releases contain their
own evolving MIPS16e2 implementation; the custom language prevents accidental
dependence on whichever definitions are bundled. Rebuild against the Ghidra
version you install, since compiled SLEIGH and Java compatibility can change.

## Build and regression checks

```sh
python3 scripts/build_extension.py --ghidra /path/to/ghidra --install
python3 -m unittest discover -s tests -p 'test_extension.py'
```

`--java-home /path/to/jdk` overrides `JAVA_HOME`/`PATH`. `--output` accepts either
a ZIP filename or a directory. The build uses the installed Sleigh compiler and
JDK directly; Gradle and a Ghidra source checkout are unnecessary. The ZIP
includes language source, compiled SLA, Java source and analyzer JAR.
Upgrades keep a rollback copy in the installation's `.jaymt-backups/` directory.
Restart Ghidra after installation.

`tests/ghidra/JayMTProcessorTest.java` checks actual instruction decoding and
p-code for the corrected gp access, EI, INS, LL/SC and LUI instructions. Run it
through `analyzeHeadless` after importing a 64-byte or larger raw fixture with
`-processor MIPS:LE:32:jaymt -noanalysis`, supplying `tests/ghidra` as the script
path. A successful run prints `JAYMT_PROCESSOR_TEST_PASS`.
