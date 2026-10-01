# Validation

Validation uses official Ghidra 11.4.2, Homebrew OpenJDK 21, and a public Galaxy A41 sample. Firmware and runtime downloads live outside this repository.

## Real firmware extraction

Source: [FirmWire NDSS research dataset, Zenodo record 6516030](https://zenodo.org/records/6516030), `CP_A415FXXU1ATE1_CP15883562_CL18317596_QB31188168_REV00_user_low_ship_MULTI_CERT.tar.md5`.

- Published archive MD5 verified: `86f58e7116ceda5a8f04f1153dd989e5`.
- Raw md1img: 60,612,720 bytes, 23 sections.
- Extracted md1rom: 23,719,076 bytes; SHA-256 `d2fab6ece6d77f8d1666903bcba3f252e05d7315cf5bfca4c29e9164c62a3e8f`.
- Metadata: MT6768_S00, MOLY.LR12A.R3.TC10.6M.PR.GBL.SP.V1.P20, build 2020/05/16.
- All 99,346 valid symbol names, addresses, and sizes match the original loader exactly. One invalid empty-name legacy record caused by reading beyond the symbol-table sentinel is excluded.
- Raw and CP/LZ4 routes produce byte-identical ROM and CSV outputs. All 23 sections can be preserved, including repeated certificate sections.
- Observed extraction: approximately 0.32 seconds raw, 0.47 seconds CP/LZ4 on the validation machine. These are individual runs, not portable performance guarantees.

## Runtime checks

- Official Ghidra ZIP SHA-256 verified: `795a02076af16257bd6f3f4736c4fc152ce9ff1f95df35cd47e2adc086e037a6`.
- Small extension compiles with the bundled SLEIGH compiler and JDK; no complete Ghidra build is needed.
- Ghidra loads `# @runtime Jython` scripts successfully.
- Headless mixed-mode smoke test verifies named MIPS32 and MIPS16 functions, MIPS16 context/prologue inference, a branch delay slot, and tagged/untagged function pointers.
- Python regression suite passes with optional LZ4 installed.

Full A41 analysis is being validated. No whole-image speedup ratio is claimed without an equivalent measured baseline. Firmware-specific mapping, unresolved function modes, incomplete inherited DSP semantics, and remaining Ghidra diagnostics must be considered when assessing decompilation.
