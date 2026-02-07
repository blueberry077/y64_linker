/*

  TITLE Y64 (Yoshi64) Linker
  AUTHOR Marc-Daniel DALEBA
  FILE y64_linker.c
  DATE 2026-01-20
  DESCRIPTION
    Custom Linker for the Yoshi's Story Decompilation project
    It links unresovled jumps and data without needed to create
    a full .elf file.
    https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#:~:text=In%20computing%2C%20the%20Executable%20and,device%20drivers%2C%20and%20core%20dumps.
    https://refspecs.linuxfoundation.org/elf/elf.pdf
  
  VERSION 1.0 - Resolves `jal` jumps (R_MIPS_26) and generates .text binary file
  VERSION 2.0 - Resolves extern variable relocations
  VERSION 3.0 - Accepts `Address` as the base of the .text blob
  VERSION 4.0 - Accepts .rodata starts address

*/
#include <stdio.h>
#include <stdint.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>

#define R_MIPS_26   4
#define R_MIPS_HI16 5
#define R_MIPS_LO16 6

typedef struct {
  uint32_t offset;
  std::string sym_name;
  uint8_t type;
} reloc_t;

const char *usage_text =
"usage: %s Input Output SymbolFile Address\n"
"       Input        : Input Object File\n"
"       Output       : Output Text Blob\n"
"       SymbolFile   : Symbols File\n"
"                        Format: name = address\n"
"       Address      : Address of the .text in RAM\n"
"       RODatAddress : Address of the .rodata in RAM\n";
char *global_input_file = NULL;
char *global_output_file = NULL;
char *global_symbol_file = NULL;
uint32_t global_address = 0;
uint32_t global_rodata_address = 0;
std::map<std::string, uint32_t> global_symbol_table;
std::map<std::string, uint32_t> global_local_symbols;
std::vector<reloc_t> global_relocations;

void usage(char *progname);
uint32_t parse_hex(const std::string& str);
uint16_t read_u16_be(const std::vector<uint8_t>& buffer, size_t offset);
uint32_t read_u32_be(const std::vector<uint8_t>& buffer, size_t offset);
std::string read_cstr(const std::vector<uint8_t>& buffer, size_t offset);

void load_symbols(void);
int process_object(void);

int main(int argc, char **argv)
{
    // Load arguments
  if (argc < 5) {
    usage(argv[0]);
    return 0;
  }
  global_input_file = argv[1];
  global_output_file = argv[2];
  global_symbol_file = argv[3];
  global_address = parse_hex(argv[4]);
  global_rodata_address = parse_hex(argv[5]);
  
    // Parse symbol files
  load_symbols();
  
    // Process object file
  process_object();
  return 0;
}

void usage(char *progname)
{
  printf("Y64 Linker VERSION 4.0 - Marc-Daniel DALEBA\n");
  printf(usage_text, progname);
}

uint32_t parse_hex(const std::string& str)
{
  uint32_t val;
  std::stringstream ss;
  ss << std::hex << str;
  ss >> val;
  return val;
}

uint16_t read_u16_be(const std::vector<uint8_t>& buffer, size_t offset)
{
  if (offset + 4 > buffer.size()) {
    return 0;
  }
  uint16_t ret = (buffer[offset] << 8) | buffer[offset + 1];
  return ret;
}

uint32_t read_u32_be(const std::vector<uint8_t>& buffer, size_t offset)
{
  if (offset + 4 > buffer.size()) {
    return 0;
  }
  uint32_t ret = (buffer[offset] << 24) |
                 (buffer[offset + 1] << 16) |
                 (buffer[offset + 2] << 8) |
                 (buffer[offset + 3]);
  return ret;
}

std::string read_cstr(const std::vector<uint8_t>& buffer, size_t offset)
{
  std::string s;
  while (offset < buffer.size() && buffer[offset] != 0) {
    s += static_cast<char>(buffer[offset]);
    offset++;
  }
  return s;
}

void load_symbols(void)
{
  std::ifstream symFile(global_symbol_file);
  std::string line;
  while (std::getline(symFile, line)) {
    // skip empty lines or comments
    if (line.empty() || line[0] == '#')
      continue;

    // find '='
    size_t eq = line.find('=');
    if (eq == std::string::npos)
      continue;

    std::string name = line.substr(0, eq);
    std::string value = line.substr(eq + 1);

    // trim spaces
    name.erase(0, name.find_first_not_of(" \t"));
    name.erase(name.find_last_not_of(" \t") + 1);
    value.erase(0, value.find_first_not_of(" \t"));
    value.erase(value.find_last_not_of(" \t") + 1);

    uint32_t addr = parse_hex(value);
    global_symbol_table[name] = addr;
  }

  printf("[+] LOADED %d SYMBOLS\n", global_symbol_table.size());
  global_symbol_table[".rodata"] = global_rodata_address;
}


int process_object(void)
{
  std::ifstream file(global_input_file, std::ios::binary);
  if (!file) {
    printf("process_object(): failed to open %s\n", global_input_file);
    return -1;
  }
    // Copy file content
  std::vector<uint8_t> buffer(
    (std::istreambuf_iterator<char>(file)),
    std::istreambuf_iterator<char>()
  );
  
    // Parse ELF header
  uint32_t symtab_sh_offset = 0;
  uint32_t symtab_sh_size = 0;
  uint32_t symtab_sh_entsize = 0;
  
  uint32_t strtab_sh_offset = 0;
  uint32_t strtab_sh_size = 0;
  
  uint32_t text_sh_offset = 0;
  uint32_t text_sh_size = 0;
  
  uint32_t rel_text_sh_offset = 0;
  uint32_t rel_text_sh_size = 0;
  
  // Read section table
  uint32_t e_shoff = read_u32_be(buffer, 0x20);
  uint16_t e_shentsize = read_u16_be(buffer, 0x2E);
  uint16_t e_shnum = read_u16_be(buffer, 0x30);
  uint16_t e_shstrndx = read_u16_be(buffer, 0x32);
  size_t shstr_offset = read_u32_be(buffer, e_shoff + e_shstrndx * e_shentsize + 0x10);

  for (int i = 0; i < e_shnum; ++i) {
    size_t entry_offset = e_shoff + i * e_shentsize;
    uint32_t sh_name    = read_u32_be(buffer, entry_offset + 0x00);
    uint32_t sh_offset  = read_u32_be(buffer, entry_offset + 0x10);
    uint32_t sh_size    = read_u32_be(buffer, entry_offset + 0x14);
    uint32_t sh_entsize = read_u32_be(buffer, entry_offset + 0x24);
    
    std::string section_name = read_cstr(buffer, shstr_offset + sh_name);
    if (section_name == ".symtab") {
      symtab_sh_offset = sh_offset;
      symtab_sh_size = sh_size;
      symtab_sh_entsize = sh_entsize;
    } else
    if (section_name == ".strtab") {
      strtab_sh_offset = sh_offset;
      strtab_sh_size = sh_size;
    } else
    if (section_name == ".text") {
      text_sh_offset = sh_offset;
      text_sh_size = sh_size;
    } else
    if (section_name == ".rel.text") {
      rel_text_sh_offset = sh_offset;
      rel_text_sh_size = sh_size;
    }
  }
  
    // Load local functions
  int sym_count = symtab_sh_size / symtab_sh_entsize;
  for (int i = 0; i < sym_count; ++i) {
    size_t sym_entry = symtab_sh_offset + i * symtab_sh_entsize;
    uint32_t st_name = read_u32_be(buffer, sym_entry + 0x00);
    uint32_t st_value = read_u32_be(buffer, sym_entry + 0x04);
    uint32_t st_size = read_u32_be(buffer, sym_entry + 0x08);
    uint8_t st_info = buffer[sym_entry + 0x0C];

    std::string sym_name = read_cstr(buffer, strtab_sh_offset + st_name);
    bool is_function = ((st_info >> 4) == 2); // STT_FUNC

    if (is_function) {
      global_local_symbols[sym_name] = global_address + st_value;
    }
  }
  
    // Read relocation (rel.text) entries
  int rel_count = rel_text_sh_size / 8;
  for (int i = 0; i < rel_count; ++i) {
    uint32_t r_offset = read_u32_be(buffer, rel_text_sh_offset + i * 8 + 0x00);
    uint32_t r_info = read_u32_be(buffer, rel_text_sh_offset + i * 8 + 0x04);
    uint32_t sym_index = r_info >> 8;
    uint8_t type = r_info & 0xFF;
    
    size_t sym_entry = symtab_sh_offset + sym_index * symtab_sh_entsize;
    uint32_t st_name = read_u32_be(buffer, sym_entry + 0x00);
    std::string sym_name = read_cstr(buffer, strtab_sh_offset + st_name);
    
    reloc_t reloc;
    reloc.offset = r_offset;
    reloc.sym_name = sym_name;
    reloc.type = type;
    global_relocations.push_back(reloc);
  }
  
    // Copy .text content
  std::vector<uint8_t> text_bytes(
    buffer.begin() + text_sh_offset,
    buffer.begin() + text_sh_offset + text_sh_size
  );
    
    // Apply relocations based on symbols
  for (const auto& reloc : global_relocations) {
    uint32_t addr = 0;
    std::string sym_name = reloc.sym_name;
    if (global_symbol_table.count(sym_name)) {
      addr = global_symbol_table[sym_name];
    } else
    if (global_local_symbols.count(sym_name)) {
      addr = global_local_symbols[sym_name];
    } else {
      printf("process_object(): unknown symbol %s\n", sym_name.c_str());
      addr = 0;
    }
    
    uint32_t instr = read_u32_be(text_bytes, reloc.offset);
    int16_t addend = instr & 0xFFFF;
    switch (reloc.type) {
      case R_MIPS_26:
        {
          instr = (instr & 0xFC000000) | ((addr >> 2) & 0x03FFFFFF);
        }
        break;
      
      case R_MIPS_HI16:
        {
          uint32_t full = addr + addend;
          uint16_t hi = (full + 0x8000) >> 16;
          instr = (instr & 0xFFFF0000) | hi;
        }
        break;

      case R_MIPS_LO16:
        {
          uint32_t full = addr + addend;
          uint16_t lo = full & 0xFFFF;
          instr = (instr & 0xFFFF0000) | lo;
        }
        break;
        
      default:
        printf("process_object(): unknown reloc type %d\n", reloc.type);
        break;
    }
      // Patch text buffer
    text_bytes[reloc.offset + 0] = (instr >> 24) & 0xFF;
    text_bytes[reloc.offset + 1] = (instr >> 16) & 0xFF;
    text_bytes[reloc.offset + 2] = (instr >> 8) & 0xFF;
    text_bytes[reloc.offset + 3] = instr & 0xFF;
  }
  
    // Save .text blobs
  std::ofstream out(global_output_file, std::ios::binary);
  out.write(reinterpret_cast<const char*>(text_bytes.data()), text_bytes.size());
  return 0;
}