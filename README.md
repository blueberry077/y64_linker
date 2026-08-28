# Y64 (Yoshi64) Linker 

Custom lightweight linker designed for the **Yoshi’s Story (Nintendo 64) decompilation project**.

---

## 🔎 Overview

`y64_linker` is a lightweight **MIPS64 ELF section linker and relocation resolver**. 

Standard `objcopy` cannot resolve relocations when extracting binary sections, forcing developers to write complex linker scripts. `y64_linker` bridges this gap by reading unlinked or partially linked MIPS ELF object files, resolving relocations directly against a symbol address file, and outputting ready-to-inject `.text` binary blobs.

## ✨ Features

- Parses **MIPS ELF object files**
- Resolves **R_MIPS_26 relocations** (`jal` / `j`)
- Partically resolves **R_MIPS_HI16** and **R_MIPS_LO16** relocations
- Accepts `.rodata` start address as parameter for
- Links against an external **symbol address file**
- Outputs a raw **`.text` binary blob**
- No full ELF linking stage required

---

## 📦 Usage

```bash
usage: y64_linker Input Output SymbolFile Address
       Input        : Input Object File
       Output       : Output Text Blob
       SymbolFile   : Symbols File
                        Format: name = address
       Address      : Address of the .text in RAM
       RODatAddress : Address of the .rodata in RAM
```

## 📄 symbols.txt syntax

The symbol file provides absolute RAM addresses for unresolved symbols.
It is used by the linker to patch relocations without performing full ELF linking.

### Example with full syntax:
```txt
# main
boot = 0x8006743C
idle = 0x80067284

# utility
func_80065984 = 0x80065984

```
