################################################################################
# CPE Patch Generator
# Created by Robert Pafford (rjp5th)
#
# Creates a CPE patch file from the compiled CPE patch file
# This is called in the makefile in this directory
#
# SPDX-FileCopyrightText: 2024 Robert Pafford
# SPDX-License-Identifier: MIT
################################################################################

import datetime
import io
import os
import struct
import sys

class ELFDecodeError(RuntimeError):
    @classmethod
    def check(cls, cond: bool, msg: str):
        if not cond:
            raise cls(msg)

def readf(f: 'io.BytesIO', size) -> bytes:
    data = f.read(size)
    ELFDecodeError.check(len(data) == size, "Unexpected EOF")
    return data

class StringTable:
    def __init__(self, f: 'io.BytesIO', shdr: 'SectionHdr'):
        ELFDecodeError.check(shdr.sh_type == 3, "Tried to make a string table from non string table section")
        ELFDecodeError.check(shdr.sh_offset != 0 and shdr.sh_size != 0, "String table is not loaded in program?")
        ELFDecodeError.check(shdr.sh_addr == 0, "String table has non-zero address")
        ELFDecodeError.check(shdr.sh_flags == 0, "String section has unexpected flags")
        f.seek(shdr.sh_offset)
        self._data = readf(f, shdr.sh_size)

    def get_str(self, offset: int) -> str:
        ELFDecodeError.check(offset >= 0 and offset < len(self._data), "Bad string offset")
        null_idx = self._data.find(b'\0', offset)
        ELFDecodeError.check(null_idx >= 0, "Could not find null terminator for string")
        return self._data[offset:null_idx].decode()

class SymbolDef:
    def __init__(self, idx: int, f: 'io.BytesIO', strtab: 'StringTable', sh_entsize: int):
        self.idx = idx

        ELF_SYM_DEF = "<3I2BH"
        ELFDecodeError.check(sh_entsize == struct.calcsize(ELF_SYM_DEF), "symtab ent size doesn't match struct length")
        elf_sym_raw = readf(f, struct.calcsize(ELF_SYM_DEF))
        elf_sym = struct.unpack(ELF_SYM_DEF, elf_sym_raw)
        self.st_name_idx = elf_sym[0]
        self.st_name = strtab.get_str(self.st_name_idx)
        self.st_value = elf_sym[1]
        self.st_size = elf_sym[2]
        self.st_bind = elf_sym[3] >> 4
        self.st_type = elf_sym[3] & 0xF
        self.st_other = elf_sym[4]
        self.st_shndx = elf_sym[5]

    def __repr__(self):
        return "<SymbolDef @0x{:08X}: {}>".format(self.st_value, repr(self.st_name))

class SectionHdr:
    def __init__(self, idx: int, f: 'io.BytesIO', shstrtab: 'StringTable | None', e_shentsize: int):
        self.idx = idx

        ELF_SHDR_DEF = "<10I"
        ELFDecodeError.check(e_shentsize == struct.calcsize(ELF_SHDR_DEF), "shentsize doesn't match struct length")
        elf_shdr_raw = readf(f, e_shentsize)
        elf_shdr = struct.unpack(ELF_SHDR_DEF, elf_shdr_raw)
        self.sh_name_idx = elf_shdr[0]
        if shstrtab is not None:
            self.sh_name = shstrtab.get_str(self.sh_name_idx)
        else:
            self.sh_name = None
        self.sh_type = elf_shdr[1]
        self.sh_flags = elf_shdr[2]
        self.sh_addr = elf_shdr[3]
        self.sh_offset = elf_shdr[4]
        self.sh_size = elf_shdr[5]
        self.sh_link = elf_shdr[6]
        self.sh_info = elf_shdr[7]
        self.sh_addralign = elf_shdr[8]
        self.sh_entsize = elf_shdr[9]

class ELFDecoder:
    def __init__(self, f: 'io.BytesIO'):
        f.seek(0)
        e_ident = readf(f, 0x10)
        ELFDecodeError.check(e_ident[:4] == b"\x7FELF", "Bad Header Magic")
        ELFDecodeError.check(e_ident[4] == 1, "ELF not 32-bit")
        ELFDecodeError.check(e_ident[5] == 1, "ELF not little endian")
        ELFDecodeError.check(e_ident[6] == 1, "ELF is not V1 format")
        ELFDecodeError.check(e_ident[7] == 0 and e_ident[8] == 0, "ELF is not none-abi type")

        # Decode the rest of the header
        ELF_REMHDR_DEF = "<HHIIIIIHHHHHH"
        elf_hdr_remaining = readf(f, struct.calcsize(ELF_REMHDR_DEF))
        elf_hdr_fields: 'tuple[int]' = struct.unpack(ELF_REMHDR_DEF, elf_hdr_remaining)
        self.e_type = elf_hdr_fields[0]
        self.e_machine = elf_hdr_fields[1]
        self.e_version = elf_hdr_fields[2]
        self.e_entry = elf_hdr_fields[3]
        self.e_phoff = elf_hdr_fields[4]
        self.e_shoff = elf_hdr_fields[5]
        self.e_flags = elf_hdr_fields[6]
        self.e_ehsize = elf_hdr_fields[7]
        self.e_phentsize = elf_hdr_fields[8]
        self.e_phnum = elf_hdr_fields[9]
        self.e_shentsize = elf_hdr_fields[10]
        self.e_shnum = elf_hdr_fields[11]
        self.e_shstrndx = elf_hdr_fields[12]

        ELFDecodeError.check(len(e_ident) + len(elf_hdr_remaining) == self.e_ehsize, "ELF header size does not match expected")
        ELFDecodeError.check(self.e_type == 2, "ELF not type ET_EXEC")
        ELFDecodeError.check(self.e_machine == 0x28, "ELF is not for ARM (32-bit)")
        ELFDecodeError.check(self.e_version == 1, "ELF is not V1 format")
        ELFDecodeError.check(self.e_flags == 0x5000200, "ELF is not 'Version5 EABI, soft-float ABI'")

        partial_shstr_hdr = self._decode_section(self.e_shstrndx, f, None)
        shstrtab = StringTable(f, partial_shstr_hdr)

        self.sections = [self._decode_section(i, f, shstrtab) for i in range(self.e_shnum)]


        symtab_hdr = self.find_section(".symtab")
        ELFDecodeError.check(symtab_hdr.sh_type == 2, "Symtab is not SHT_SYMTAB type")
        ELFDecodeError.check(symtab_hdr.sh_offset != 0 and symtab_hdr.sh_size != 0, "String table is not loaded in program?")
        ELFDecodeError.check(symtab_hdr.sh_addr == 0, "Symtab has non-zero address")
        ELFDecodeError.check(symtab_hdr.sh_flags == 0, "Symtab has unexpected header flags")

        strtab = StringTable(f, self.sections[symtab_hdr.sh_link])  # Get the string table linked to the symbolt able

        first_nonlocal_symidx = symtab_hdr.sh_info  # We only care about global symbols

        # Read through the global symbols

        f.seek(symtab_hdr.sh_offset + (symtab_hdr.sh_entsize * first_nonlocal_symidx))
        num_syms = symtab_hdr.sh_size // symtab_hdr.sh_entsize
        self.symbols = [SymbolDef(i, f, strtab, symtab_hdr.sh_entsize) for i in range(first_nonlocal_symidx, num_syms)]

    def _decode_section(self, shidx: int, f: 'io.BytesIO', shstrtab: 'StringTable | None'):
        ELFDecodeError.check(shidx >= 0 and shidx < self.e_shnum, f"Invalid section #")
        off = self.e_shoff + (self.e_shentsize * shidx)
        f.seek(off)
        return SectionHdr(shidx, f, shstrtab, self.e_shentsize)

    def find_section(self, name: str):
        for shdr in self.sections:
            if shdr.sh_name == name:
                return shdr
        ELFDecodeError.check(False, f"Could not find section with name '{name}'")

    def section_symbol_itr(self, section: 'SectionHdr'):
        for sym in self.symbols:
            if sym.st_shndx == section.idx:
                yield sym

    def read_section(self, f: 'io.BytesIO', section: 'SectionHdr', require_alloc=False):
        ELFDecodeError.check(section.sh_type == 1, "Section is not progbits")
        ELFDecodeError.check(section.sh_offset != 0 and section.sh_size != 0, "Section does not have contents")
        ELFDecodeError.check(section.sh_flags & 2 != 0 or not require_alloc, "Section is not allocated into memory")
        f.seek(section.sh_offset)
        return readf(f, section.sh_size)

PATCH_VECBASE = 0x2100404C
MAX_IRQ_PATCHES = 12
MAX_TABLE_PATCHES = 172
VECTABLE_PATCH_SYMPREFIX = "vectable_patch__idx"
IRQ_PATCH_SYMPREFIX = "irq_patch__idx"

class PatchGen:
    def __init__(self):
        self.patch_baseaddr = None
        self.patch_array = []
        self.table_patch_indices = {}
        self.irq_patch_addrs = {}

    def write_header(self, fout, filename):
        ts = datetime.datetime.now().astimezone()
        fout.write(f"/******************************************************************************\n")
        fout.write(f"*\n")
        fout.write(f"* Filename: {filename}\n")
        fout.write(f"*\n")
        fout.write(f"* This file was created using the CPE Patch Compiler\n")
        fout.write(f"* Generated on {ts.strftime('%Y-%m-%d %H:%M:%S%z')}\n")
        fout.write(f"*\n")
        fout.write(f"******************************************************************************/\n")
        fout.write("\n")

    def load(self, filename):
        with open(filename, 'rb') as f:
            dec = ELFDecoder(f)

            vectable_section = None
            vectable_data = None
            patch_section = None
            patch_data = None
            irqdef_section = None
            irqdef_data = None

            for section in dec.sections:
                if section.sh_name == ".vectable_ptrs":
                    vectable_section = section
                    vectable_data = dec.read_section(f, section, True)
                elif section.sh_name == ".patch":
                    patch_section = section
                    patch_data = dec.read_section(f, section, True)
                elif section.sh_name == ".irqpatch_ptrs":
                    ELFDecodeError.check(section.sh_flags & 2 == 0, ".irqpatch_ptrs should be nonalloc")
                    ELFDecodeError.check(section.sh_addr == 0, ".irqpatch_ptrs should have 0 address")
                    irqdef_section = section
                    irqdef_data = dec.read_section(f, section, False)
                elif section.sh_flags & 2 != 0:
                    # Error if the section is allocated and we don't expect it to be
                    raise RuntimeError(f"Unexpected allocated section found: '{section.sh_name}'")

        if patch_data is None:
            raise RuntimeError("Could not locate .patch section in binary")

        if vectable_data is None and irqdef_data is None:
            raise RuntimeError("Missing both irq and vector lookups in output binary")

        if vectable_data is not None:
            # Make sure the addresses check out
            if vectable_section.sh_addr + vectable_section.sh_size != patch_section.sh_addr:
                raise RuntimeError("Vector table to patch is not continguous")

            start = vectable_section.sh_addr
            end = patch_section.sh_addr + patch_section.sh_size
            vectable_endidx = vectable_section.sh_size // 4

        else:
            start = patch_section.sh_addr
            end = patch_section.sh_addr + patch_section.sh_size
            vectable_endidx = 0

        if start % 4 != 0 or end % 4 != 0:
            raise RuntimeError("Patch isn't word aligned")
        if start < 0x2100404C or end > 0x21006000:
            raise RuntimeError("Patch does not fit inside RFC ULL SRAM")
        self.patch_baseaddr = start

        # Generate patch array
        patch_word_cnt = (end - start) // 4

        for i in range(patch_word_cnt):
            if i < vectable_endidx:
                offset = i * 4
                word = int.from_bytes(vectable_data[offset:offset + 4], 'little')
            else:
                offset = (i - vectable_endidx) * 4
                word = int.from_bytes(patch_data[offset:offset + 4], 'little')
            self.patch_array.append(word)

        if vectable_data is not None:
            # Decode patches from symbols
            for sym in dec.section_symbol_itr(vectable_section):
                ELFDecodeError.check(sym.st_type == 1, "Not object type symbol")
                ELFDecodeError.check(sym.st_size == 4, "Must be a 4 byte symbol (pointer)")
                ELFDecodeError.check(sym.st_bind == 1, "Not global symbol")
                symname = sym.st_name

                # Get the index in the CPE vector table
                ELFDecodeError.check(symname.startswith(VECTABLE_PATCH_SYMPREFIX), "Bad symbol name")
                vectable_idxstr = symname[len(VECTABLE_PATCH_SYMPREFIX):]
                ELFDecodeError.check(vectable_idxstr.isdigit(), "Table index must be digit")
                vectable_idx = int(vectable_idxstr)
                ELFDecodeError.check(vectable_idx >= 0 and vectable_idx < MAX_TABLE_PATCHES, "Patch index does not exist")

                # Get index into our patch table
                addr = sym.st_value
                ELFDecodeError.check(addr >= vectable_section.sh_addr and addr < vectable_section.sh_addr + vectable_section.sh_size, "Symbol outside of section?")
                ELFDecodeError.check(addr % 4 == 0, "Symbol is not word aligned")
                patchtable_idx = (addr - vectable_section.sh_addr) // 4

                # Create it
                ELFDecodeError.check(vectable_idx not in self.table_patch_indices, f"Vectable Patch {vectable_idx} already defined")
                self.table_patch_indices[vectable_idx] = patchtable_idx

        if irqdef_data is not None:
            # Decode irq patches
            for sym in dec.section_symbol_itr(irqdef_section):
                ELFDecodeError.check(sym.st_type == 1, "Not object type symbol")
                ELFDecodeError.check(sym.st_size == 4, "Must be a 4 byte symbol (pointer)")
                ELFDecodeError.check(sym.st_bind == 1, "Not global symbol")
                symname = sym.st_name

                # Get the index in the CPE vector table
                ELFDecodeError.check(symname.startswith(IRQ_PATCH_SYMPREFIX), "Bad symbol name")
                irq_idxstr = symname[len(IRQ_PATCH_SYMPREFIX):]
                ELFDecodeError.check(irq_idxstr.isdigit(), "IRQ index must be digit")
                irq_idx = int(irq_idxstr)
                ELFDecodeError.check(irq_idx >= 0 and irq_idx < MAX_IRQ_PATCHES, "IRQ index does not exist")

                # Get pointer for the function
                addr = sym.st_value
                ELFDecodeError.check(addr >= 0 and addr < irqdef_section.sh_size, "Symbol outside of section?")
                ELFDecodeError.check(addr % 4 == 0, "Symbol is not word aligned")
                irqpatch_addr = int.from_bytes(irqdef_data[addr:addr+4], 'little')

                # Create it
                ELFDecodeError.check(irq_idx not in self.irq_patch_addrs, f"IRQ Patch {irq_idx} already defined")
                self.irq_patch_addrs[irq_idx] = irqpatch_addr

    def create_header_patch(self, f: 'io.TextIOWrapper', fname):
        self.write_header(f, fname)
        indent_lvl = 0
        indent_str = "    "
        def putline(msg="", indent=False, outdent=False):
            nonlocal indent_lvl
            if outdent:
                assert indent_lvl > 0
                indent_lvl -= 1
            if len(msg) == 0:
                f.write("\n")
            else:
                f.write(indent_str * indent_lvl + msg + "\n")
            if indent:
                indent_lvl += 1

        putline("#pragma once")
        putline()
        putline("#include <stdint.h>")
        putline("#include <string.h>")
        putline()

        putline("static const uint32_t patchImageCpe[] = {", indent=True)
        for word in self.patch_array:
            putline("0x{:08X},".format(word))
        putline("};", outdent=True)
        putline()

        putline("static inline void rf_patch_cpe_custom(void) {", indent=True)
        putline("memcpy((uint32_t*) 0x{:08X}, patchImageCpe, sizeof(patchImageCpe));".format(self.patch_baseaddr))

        if len(self.table_patch_indices) > 0:
            putline()
            putline("*(uint32_t*) 0x210003d0 = 0x{:08X};".format(self.patch_baseaddr))
            putline("uint8_t *pPatchTab = (uint8_t *) 0x210003d4;")
            for patch_table_idx, vec_idx in self.table_patch_indices.items():
                putline(f"pPatchTab[{patch_table_idx}] = {vec_idx};")

        if len(self.irq_patch_addrs) > 0:
            putline()
            putline("uint32_t *pIrqTab = (uint32_t *) 0x21000484;")
            for irq_idx, patch_addr in self.irq_patch_addrs.items():
                putline("pIrqTab[{}] = 0x{:08X};".format(irq_idx * 2, patch_addr))

        putline("}", outdent=True)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} [in elf] [out python]", file=sys.stderr)
        exit(1)

    gen = PatchGen()
    gen.load(sys.argv[1])
    with open(sys.argv[2], "w") as f:
        gen.create_header_patch(f, os.path.basename(sys.argv[2]))
