# Y64 (Yoshi64) Linker 

Custom lightweight linker designed for the **Yoshi’s Story (Nintendo 64) decompilation project**.

The Y64 Linker resolves relocations directly from MIPS ELF object files and produces raw `.text` binary blobs, **without generating a full ELF executable**.

This tool is intentionally minimal and focused: it only implements what is required for N64 MIPS code linking.

---

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
idle = 080067284

# utility
func_80065984 = 0x80065984
```