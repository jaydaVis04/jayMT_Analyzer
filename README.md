<p align="center"><img src="assets/banner.svg" alt="jayMT_ANALAYZER" width="100%"></p>

# jayMT_Analyzer

A compact toolkit for bringing **MediaTek MIPS / MIPS16e2 modem firmware into Ghidra**. Start with `md1img.img`, extract the ROM and symbols, then run a timed headless analysis that reconstructs memory regions and function entry points. The main analyzer runs in **native Java**, with no Jython interpreter in the analysis path. Python handles extraction, setup, and launching.

Derived from [FirmWire's Ghidra fork](https://github.com/FirmWire/ghidra), with its MediaTek processor support retained as a small extension. Ghidra is a separate dependency; this repository does not carry the full Ghidra source tree or its history.

## Quick start

Use Python 3.10+, a JDK compatible with your Ghidra release, and an official Ghidra distribution. The initial integration target is **Ghidra 11.4.2 + JDK 21**. Run these commands from this repository:

```sh
git clone https://github.com/jaydaVis04/jayMT_Analyzer.git
cd jayMT_Analyzer

export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.4.2_PUBLIC
export JAVA_HOME=/path/to/jdk-21
export PATH="$JAVA_HOME/bin:$PATH"

# Build/install just the processor extension. No full Ghidra build or Gradle.
python3 -m jaymt setup

# Extract and analyze; progress, logs, JSON report, and saved Ghidra project.
python3 -m jaymt analyze /path/to/md1img.img --heap 4G
```

Open the resulting `md1img_jaymt/projects/md1.gpr` in Ghidra. Each run prints its exact project and report paths. Choose `--workspace PATH` and `--project NAME` to control those locations. Existing projects are never overwritten.

To prepare files without starting Ghidra:

```sh
python3 -m jaymt unpack /path/to/md1img.img -o prepared
python3 -m jaymt analyze prepared --workspace analysis
```

Raw md1img requires **only the Python standard library**. Compressed `.lz4` images and CP archives containing LZ4 need the optional dependency:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-lz4.txt
.venv/bin/python -m jaymt unpack firmware.tar.md5 -o prepared
```

`unpack_md1img.py` is the standalone extractor. The old `unpack_mtk_cp_update.py` filename remains a compatibility entry point and now also accepts md1img directly.

**`md1.bin` is supported too:** inputs are recognized by their container header, not their filename or extension. Use the same `unpack` or `analyze` command. A bare ROM without a container header needs a prepared directory containing that ROM named `md1rom` and its matching `md1_dbginfo.csv`; this tool cannot recreate missing debug symbols.

## What you get

- `md1rom`: firmware bytes, unchanged.
- `md1_dbginfo.csv`: embedded function symbols, when available.
- `manifest.json`: image hashes, section offsets, load addresses, and build metadata.
- Optional `--all-sections`: also preserve the DSP, raw debug, and other section payloads.
- Analysis logs, stage timings, unresolved-symbol counts, warnings, and a Ghidra project.

## Performance controls

```sh
python3 -m jaymt analyze prepared --threads 16 --heap 8G
```

The default worker count uses the CPUs available to Python. The launcher sets Ghidra's `cpu.core.override` and `-max-cpu`, exposes the Java heap, and lets the JVM choose its GC/JIT worker counts. It does not modify your Ghidra launch scripts. Some analysis tasks and database edits are serial; all-core utilization is not a measure of correctness or a guaranteed speedup.

The analysis removes quadratic symbol-list removal, repeated mode probes, frequent analysis restarts, per-function console spam, and per-word Java calls during pointer scanning. Full analysis remains the default. `--no-bruteforce` explicitly skips the uncertain last MIPS16/MIPS32 guessing stage, trading coverage for time. `--verbose` enables detailed logging.

The launcher also prints elapsed time every 30 seconds while a native analyzer is busy. It never presents a guessed completion percentage. `analysis-*.json` records stage durations, function and pointer counts, unresolved symbols, heuristic mode choices, and remaining error bookmarks.

| Option | Meaning |
| --- | --- |
| `--ghidra PATH` | Ghidra installation; defaults to `GHIDRA_INSTALL_DIR` |
| `--java-home PATH` | JDK containing `bin/java`; otherwise use your environment |
| `--threads N` | Ghidra worker pool size; defaults to available CPUs |
| `--heap 4G` | Maximum Java heap; default 4 GB, choose according to available RAM |
| `--workspace PATH` | Place extracted files, logs, reports, and project here |
| `--project NAME` | New Ghidra project name; default `md1` |
| `--no-bruteforce` | Skip uncertain final mode guesses; full analysis is the default |
| `--verbose` | More diagnostic output |

If a run fails after extraction, reuse its `extracted/` directory as input with a new workspace or project name. A missing or failed report is an error even if Ghidra reports a successful import. `completed_with_warnings` means the project was saved but its unresolved symbols, heuristic choices, or diagnostics need review.

## GUI workflow

1. Run `setup`, or install the generated ZIP from `dist/` through Ghidra's extension manager, then restart Ghidra.
2. Import `md1rom` as **Raw Binary**, language **MIPS:LE:32:jaymt**, compiler **default**.
3. Decline initial automatic analysis.
4. Run **`JayMTAnalyze.java`** from the **jayMT_Analyzer** script category. Select `md1_dbginfo.csv` when asked.

The headless command performs these steps automatically. Its success check requires both a completed script report and a saved project, because Ghidra can otherwise return success even after a script error.

The old `analyze_mtk_image.py` name remains only as a small compatibility wrapper. It explicitly declares `# @runtime Jython` and delegates to the same Java analyzer. Use the Java entry point to avoid Jython entirely.

## Analysis and processor support

The pipeline relocates the raw ROM to `0x90000000`, reads exported symbols, reconstructs recognized initialization tables, then discovers functions using prologues, automatic analysis, pointer references, and finally optional mode guesses. It creates function pointers, completes recognized delay slots, and removes only obsolete instruction-error bookmarks. Missing mappings and unresolved modes remain visible in the report.

The custom language `MIPS:LE:32:jaymt` retains FirmWire's MIPS32, MIPS16e2, DSP/MT definitions and the microMIPS include dependency. It does not replace built-in MIPS. The custom pair analyzer scans defined instructions instead of every byte, uses public APIs, and rejects invalid left/left pairs. The importer enables it and disables the overlapping built-in pair analyzer for this language.

Corrections include `gp`-relative operations that previously read `sp`, the `ei` status bit, the `ins` bit mask, and linked-load/store semantics. Definitions were checked against [NSA's MIPS16e2 implementation](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors/MIPS/data/languages/mips16.sinc) and actual Ghidra instruction/p-code tests. Mapping fixes include per-core table advancement, disjoint RAM holes, BSS start/end handling, and bounded emulation.

## Scope and accuracy

This preserves the original A41-class **MIPS** workflow. A file named md1img does not identify its CPU: ARM and nanoMIPS firmware need different processor support. Extraction is architecture-neutral; analysis is not. Stripped images can be extracted, but this symbol-driven analysis requires embedded debug symbols.

Memory initialization layouts and uncertain instruction modes are firmware-specific. Some inherited MediaTek DSP instructions have decoding but incomplete p-code semantics. Decompiled C is an analysis aid, not a perfect reconstruction of source. Reports retain warnings and unresolved symbols; broad firmware compatibility and universal speedup are not claimed.

The bundled SLEIGH compiler reports inherited NOP constructors; some are architectural no-ops, while many custom DSP constructors have empty semantics. These are preserved and disclosed, not presented as fully modeled instructions. Ghidra 11.4.2 is the tested runtime target; rebuild against your installed version because SLEIGH and Java compatibility can change.

## Validation

Real firmware comes from [FirmWire's public research dataset](https://zenodo.org/records/6516030): Galaxy A41 `A415FXXU1ATE1`, MT6768_S00, `MOLY.LR12A.R3.TC10.6M.PR.GBL.SP.V1.P20`, build 2020/05/16.

| Check | Result |
| --- | --- |
| Published archive MD5 | `86f58e7116ceda5a8f04f1153dd989e5` verified |
| Raw container | 60,612,720 bytes, 23 sections |
| Extracted ROM | 23,719,076 bytes; byte-identical to the original loader |
| Symbol parity | All 99,346 valid names, addresses, and sizes match |
| Invalid legacy record | Empty-name trailing record excluded instead of reading into the source-file table |
| Raw versus CP/LZ4 | Identical ROM and CSV; repeated certificate sections preserved with distinct filenames |
| Extraction time | Approximately 0.32 seconds raw and 0.47 seconds CP/LZ4 in individual local runs |

ROM SHA-256: `d2fab6ece6d77f8d1666903bcba3f252e05d7315cf5bfca4c29e9164c62a3e8f`.

Validation passed **39 Python tests** with optional LZ4 installed, actual Ghidra processor/p-code tests, and the native Java workflow checks: **8 functions, 3 pointers, 16 mapped blocks, zero unresolved fixture symbols**, and all three discovery stages. Checks cover thunks, aliases, quoted names, instruction-mode probing, bounds, memory holes, and saved-project reanalysis. CI builds against an official Ghidra 11.4.2 download verified by SHA-256.

The full A41 run was started but stopped before completion to deliver this version promptly. Real extraction parity and native fixture results are verified; whole-image completion, coverage, and a speedup ratio are **not yet established**. The Java port removes scripting overhead, but Ghidra's native analysis can still dominate runtime.

## Why this repository is small

The original checkout contains 17,938 tracked files (176.38 MiB of file contents), and occupies about 563 MiB on disk including 347 MiB of Git history. Only nine files differ from its upstream Ghidra base: the extraction and analysis scripts, three MIPS language files, the pair analyzer, one comment-only emulation change, release properties, and README.

This repository keeps the custom MIPS include closure and the required workflow. Ghidra itself supplies the GUI, decompiler, debugger, unrelated processors, and shared libraries. The six retained SLEIGH files originally total only 373,931 bytes. There are no firmware binaries, copied Ghidra distribution, dependency trees, or old Git history here.

Provenance: FirmWire commit `61a1b439af5f6d5ba7e92809c05145dbe44e5d97`, based on NSA commit `3e245c6f80b1fe6465a8d5f73c09bcd1fd823fb1`. Original file hashes are in [extension/UPSTREAM.json](extension/UPSTREAM.json). The audit covered the tracked tree, build/dependency boundaries, complete custom delta, and relevant Ghidra APIs; it was not a line-by-line audit of every inherited Ghidra feature.

## Development

```sh
python3 -m unittest discover -s tests -v
python3 scripts/build_extension.py --ghidra "$GHIDRA_INSTALL_DIR"
```

The small Python CLI needs no package installation. See [NOTICE](NOTICE) for upstream attribution and [LICENSE](LICENSE) for Apache 2.0 licensing. Firmware images, extracted proprietary binaries, Ghidra distributions, and analysis databases are not included.

The builder accepts `--java-home PATH`, `--output ZIP_OR_DIRECTORY`, and `--install`. It invokes the installed SLEIGH compiler and JDK directly. The small ZIP contains the language source and compiled definitions, analyzer JAR/source, scripts, README, and upstream notices. Upgrades retain a rollback in the Ghidra installation's `.jaymt-backups/` directory. Restart Ghidra after installation.

## Improvements over the original FirmWire fork

| Area | Original | jayMT_Analyzer |
| --- | --- | --- |
| Repository | 176 MiB tracked source; ~563 MiB checkout with history | About 0.6 MiB of focused source; Ghidra installed separately |
| Firmware input | CP archive required by the CLI | Direct md1img, with optional CP/LZ4 support |
| Extraction | Whole-file copies and repeated debug parsing | Streaming copies, one debug parse, validated offsets and hashes |
| Analysis work | Repeated list searches, mode probes, per-word Java calls | Linear symbol filtering, cached probes, chunked pointer scanning |
| Analyzer runtime | Python/Jython orchestration and loops | Native Java analyzer; optional tiny legacy wrapper |
| Resources | Legacy launcher: 2 GB heap and fixed GC/JIT limits | Configurable heap and worker count; JVM-managed GC/JIT |
| Compatibility & accuracy | Implicit Python runtime; mapping and symbol-parsing bugs | Java main path, explicit legacy runtime, corrected mappings/ISA semantics, focused tests |
| Visibility | Long-running script with noisy per-function output | Green branding, stage progress, elapsed-time updates, JSON results |

Real A41 extraction preserves the ROM and all **99,346 valid symbols**. Full analysis remains the default; no unmeasured speedup multiplier is claimed.
