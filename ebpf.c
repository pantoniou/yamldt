/*
 * ebpf.c - a working userspace ebpf VM
 *
 * Execute EPBF ELF files at user space and hooks.
 *
 * (C) Copyright Pantelis Antoniou <pantelis.antoniou@konsulko.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3)The name of the author may not be used to
 *     endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Copied and modified from ubpf at:
 * 	git@github.com:iovisor/ubpf.git
 *
 * Original Copyright Notice:
 *
 * Copyright 2015 Big Switch Networks, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <time.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>

#include <libelf.h>

#ifndef __APPLE__
#include <endian.h>
#else
/* Apple just had to do it like this */
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)

#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)

#endif

#include "list.h"
#include "utils.h"

#include "ebpf.h"

/* eBPF definitions */

struct ebpf_inst {
	uint8_t opcode;
	uint8_t dst : 4;
	uint8_t src : 4;
	int16_t offset;
	int32_t imm;
};

#define EBPF_CLS_MASK 0x07
#define EBPF_ALU_OP_MASK 0xf0

#define EBPF_CLS_LD 0x00
#define EBPF_CLS_LDX 0x01
#define EBPF_CLS_ST 0x02
#define EBPF_CLS_STX 0x03
#define EBPF_CLS_ALU 0x04
#define EBPF_CLS_JMP 0x05
#define EBPF_CLS_ALU64 0x07

#define EBPF_SRC_IMM 0x00
#define EBPF_SRC_REG 0x08

#define EBPF_SIZE_W 0x00
#define EBPF_SIZE_H 0x08
#define EBPF_SIZE_B 0x10
#define EBPF_SIZE_DW 0x18

/* Other memory modes are not yet supported */
#define EBPF_MODE_IMM 0x00
#define EBPF_MODE_MEM 0x60

#define EBPF_OP_ADD_IMM  (EBPF_CLS_ALU|EBPF_SRC_IMM|0x00)
#define EBPF_OP_ADD_REG  (EBPF_CLS_ALU|EBPF_SRC_REG|0x00)
#define EBPF_OP_SUB_IMM  (EBPF_CLS_ALU|EBPF_SRC_IMM|0x10)
#define EBPF_OP_SUB_REG  (EBPF_CLS_ALU|EBPF_SRC_REG|0x10)
#define EBPF_OP_MUL_IMM  (EBPF_CLS_ALU|EBPF_SRC_IMM|0x20)
#define EBPF_OP_MUL_REG  (EBPF_CLS_ALU|EBPF_SRC_REG|0x20)
#define EBPF_OP_DIV_IMM  (EBPF_CLS_ALU|EBPF_SRC_IMM|0x30)
#define EBPF_OP_DIV_REG  (EBPF_CLS_ALU|EBPF_SRC_REG|0x30)
#define EBPF_OP_OR_IMM   (EBPF_CLS_ALU|EBPF_SRC_IMM|0x40)
#define EBPF_OP_OR_REG   (EBPF_CLS_ALU|EBPF_SRC_REG|0x40)
#define EBPF_OP_AND_IMM  (EBPF_CLS_ALU|EBPF_SRC_IMM|0x50)
#define EBPF_OP_AND_REG  (EBPF_CLS_ALU|EBPF_SRC_REG|0x50)
#define EBPF_OP_LSH_IMM  (EBPF_CLS_ALU|EBPF_SRC_IMM|0x60)
#define EBPF_OP_LSH_REG  (EBPF_CLS_ALU|EBPF_SRC_REG|0x60)
#define EBPF_OP_RSH_IMM  (EBPF_CLS_ALU|EBPF_SRC_IMM|0x70)
#define EBPF_OP_RSH_REG  (EBPF_CLS_ALU|EBPF_SRC_REG|0x70)
#define EBPF_OP_NEG      (EBPF_CLS_ALU|0x80)
#define EBPF_OP_MOD_IMM  (EBPF_CLS_ALU|EBPF_SRC_IMM|0x90)
#define EBPF_OP_MOD_REG  (EBPF_CLS_ALU|EBPF_SRC_REG|0x90)
#define EBPF_OP_XOR_IMM  (EBPF_CLS_ALU|EBPF_SRC_IMM|0xa0)
#define EBPF_OP_XOR_REG  (EBPF_CLS_ALU|EBPF_SRC_REG|0xa0)
#define EBPF_OP_MOV_IMM  (EBPF_CLS_ALU|EBPF_SRC_IMM|0xb0)
#define EBPF_OP_MOV_REG  (EBPF_CLS_ALU|EBPF_SRC_REG|0xb0)
#define EBPF_OP_ARSH_IMM (EBPF_CLS_ALU|EBPF_SRC_IMM|0xc0)
#define EBPF_OP_ARSH_REG (EBPF_CLS_ALU|EBPF_SRC_REG|0xc0)
#define EBPF_OP_LE       (EBPF_CLS_ALU|EBPF_SRC_IMM|0xd0)
#define EBPF_OP_BE       (EBPF_CLS_ALU|EBPF_SRC_REG|0xd0)

#define EBPF_OP_ADD64_IMM  (EBPF_CLS_ALU64|EBPF_SRC_IMM|0x00)
#define EBPF_OP_ADD64_REG  (EBPF_CLS_ALU64|EBPF_SRC_REG|0x00)
#define EBPF_OP_SUB64_IMM  (EBPF_CLS_ALU64|EBPF_SRC_IMM|0x10)
#define EBPF_OP_SUB64_REG  (EBPF_CLS_ALU64|EBPF_SRC_REG|0x10)
#define EBPF_OP_MUL64_IMM  (EBPF_CLS_ALU64|EBPF_SRC_IMM|0x20)
#define EBPF_OP_MUL64_REG  (EBPF_CLS_ALU64|EBPF_SRC_REG|0x20)
#define EBPF_OP_DIV64_IMM  (EBPF_CLS_ALU64|EBPF_SRC_IMM|0x30)
#define EBPF_OP_DIV64_REG  (EBPF_CLS_ALU64|EBPF_SRC_REG|0x30)
#define EBPF_OP_OR64_IMM   (EBPF_CLS_ALU64|EBPF_SRC_IMM|0x40)
#define EBPF_OP_OR64_REG   (EBPF_CLS_ALU64|EBPF_SRC_REG|0x40)
#define EBPF_OP_AND64_IMM  (EBPF_CLS_ALU64|EBPF_SRC_IMM|0x50)
#define EBPF_OP_AND64_REG  (EBPF_CLS_ALU64|EBPF_SRC_REG|0x50)
#define EBPF_OP_LSH64_IMM  (EBPF_CLS_ALU64|EBPF_SRC_IMM|0x60)
#define EBPF_OP_LSH64_REG  (EBPF_CLS_ALU64|EBPF_SRC_REG|0x60)
#define EBPF_OP_RSH64_IMM  (EBPF_CLS_ALU64|EBPF_SRC_IMM|0x70)
#define EBPF_OP_RSH64_REG  (EBPF_CLS_ALU64|EBPF_SRC_REG|0x70)
#define EBPF_OP_NEG64      (EBPF_CLS_ALU64|0x80)
#define EBPF_OP_MOD64_IMM  (EBPF_CLS_ALU64|EBPF_SRC_IMM|0x90)
#define EBPF_OP_MOD64_REG  (EBPF_CLS_ALU64|EBPF_SRC_REG|0x90)
#define EBPF_OP_XOR64_IMM  (EBPF_CLS_ALU64|EBPF_SRC_IMM|0xa0)
#define EBPF_OP_XOR64_REG  (EBPF_CLS_ALU64|EBPF_SRC_REG|0xa0)
#define EBPF_OP_MOV64_IMM  (EBPF_CLS_ALU64|EBPF_SRC_IMM|0xb0)
#define EBPF_OP_MOV64_REG  (EBPF_CLS_ALU64|EBPF_SRC_REG|0xb0)
#define EBPF_OP_ARSH64_IMM (EBPF_CLS_ALU64|EBPF_SRC_IMM|0xc0)
#define EBPF_OP_ARSH64_REG (EBPF_CLS_ALU64|EBPF_SRC_REG|0xc0)

#define EBPF_OP_LDXW  (EBPF_CLS_LDX|EBPF_MODE_MEM|EBPF_SIZE_W)
#define EBPF_OP_LDXH  (EBPF_CLS_LDX|EBPF_MODE_MEM|EBPF_SIZE_H)
#define EBPF_OP_LDXB  (EBPF_CLS_LDX|EBPF_MODE_MEM|EBPF_SIZE_B)
#define EBPF_OP_LDXDW (EBPF_CLS_LDX|EBPF_MODE_MEM|EBPF_SIZE_DW)
#define EBPF_OP_STW   (EBPF_CLS_ST|EBPF_MODE_MEM|EBPF_SIZE_W)
#define EBPF_OP_STH   (EBPF_CLS_ST|EBPF_MODE_MEM|EBPF_SIZE_H)
#define EBPF_OP_STB   (EBPF_CLS_ST|EBPF_MODE_MEM|EBPF_SIZE_B)
#define EBPF_OP_STDW  (EBPF_CLS_ST|EBPF_MODE_MEM|EBPF_SIZE_DW)
#define EBPF_OP_STXW  (EBPF_CLS_STX|EBPF_MODE_MEM|EBPF_SIZE_W)
#define EBPF_OP_STXH  (EBPF_CLS_STX|EBPF_MODE_MEM|EBPF_SIZE_H)
#define EBPF_OP_STXB  (EBPF_CLS_STX|EBPF_MODE_MEM|EBPF_SIZE_B)
#define EBPF_OP_STXDW (EBPF_CLS_STX|EBPF_MODE_MEM|EBPF_SIZE_DW)
#define EBPF_OP_LDDW  (EBPF_CLS_LD|EBPF_MODE_IMM|EBPF_SIZE_DW)

#define EBPF_OP_JA       (EBPF_CLS_JMP|0x00)
#define EBPF_OP_JEQ_IMM  (EBPF_CLS_JMP|EBPF_SRC_IMM|0x10)
#define EBPF_OP_JEQ_REG  (EBPF_CLS_JMP|EBPF_SRC_REG|0x10)
#define EBPF_OP_JGT_IMM  (EBPF_CLS_JMP|EBPF_SRC_IMM|0x20)
#define EBPF_OP_JGT_REG  (EBPF_CLS_JMP|EBPF_SRC_REG|0x20)
#define EBPF_OP_JGE_IMM  (EBPF_CLS_JMP|EBPF_SRC_IMM|0x30)
#define EBPF_OP_JGE_REG  (EBPF_CLS_JMP|EBPF_SRC_REG|0x30)
#define EBPF_OP_JSET_REG (EBPF_CLS_JMP|EBPF_SRC_REG|0x40)
#define EBPF_OP_JSET_IMM (EBPF_CLS_JMP|EBPF_SRC_IMM|0x40)
#define EBPF_OP_JNE_IMM  (EBPF_CLS_JMP|EBPF_SRC_IMM|0x50)
#define EBPF_OP_JNE_REG  (EBPF_CLS_JMP|EBPF_SRC_REG|0x50)
#define EBPF_OP_JSGT_IMM (EBPF_CLS_JMP|EBPF_SRC_IMM|0x60)
#define EBPF_OP_JSGT_REG (EBPF_CLS_JMP|EBPF_SRC_REG|0x60)
#define EBPF_OP_JSGE_IMM (EBPF_CLS_JMP|EBPF_SRC_IMM|0x70)
#define EBPF_OP_JSGE_REG (EBPF_CLS_JMP|EBPF_SRC_REG|0x70)
#define EBPF_OP_CALL     (EBPF_CLS_JMP|0x80)
#define EBPF_OP_EXIT     (EBPF_CLS_JMP|0x90)

#define STACK_SIZE 128

#ifndef EM_BPF
#define EM_BPF 247
#endif

#ifndef R_BPF_NONE
#define R_BPF_NONE	0
#endif

#ifndef R_BPF_64_64
#define R_BPF_64_64	1
#endif

#ifndef R_BPF_64_32
#define R_BPF_64_32	10
#endif

int ebpf_setup(struct ebpf_vm *vm,
	       const struct ebpf_callback *callbacks,
	       ebpf_lazy_func_t lazy_func,
	       ebpf_debugf_t debugf,
	       void *debugarg)
{
	const struct ebpf_callback *cb;

	memset(vm, 0, sizeof(*vm));
	vm->callbacks = callbacks;
	for (cb = vm->callbacks; cb && cb->name; cb++)
		vm->num_callbacks++;
	vm->lazy_func = lazy_func;
	vm->debugf = debugf;
	vm->debugarg = debugarg;
	INIT_LIST_HEAD(&vm->unres);
	vm->initialized = true;

	return 0;
}

void ebpf_cleanup(struct ebpf_vm *vm)
{
	struct ebpf_unresolved_entry *ue, *uen;

	if (!vm || !vm->initialized)
		return;

	list_for_each_entry_safe(ue, uen, &vm->unres, node) {
		list_del(&ue->node);
		free(ue);
	}

	if (vm->workspace)
		free(vm->workspace);

	if (vm->sections)
		free(vm->sections);
	memset(vm, 0, sizeof(*vm));
}

int ebpf_load_elf(struct ebpf_vm *vm, const void *elf, size_t elf_size)
{
	const Elf64_Ehdr *ehdr;
	const Elf64_Shdr *shdr;
	const void *elf_end;
	const void *data;
	struct ebpf_section *s, *rel, *symtab, *strtab, *source, *target;
	uint64_t copy_offset, r_offset, imm;
	const Elf64_Rel *rs, *r;
	const Elf64_Sym *syms, *sym;
	unsigned int i, j, num_syms, sym_idx;
	size_t size;
	const char *strings, *sym_name;
	const struct ebpf_callback *cb;
	struct ebpf_unresolved_entry *ue;

	if (!vm || !vm->initialized)
		return -1;
	ehdr = elf;
	elf_end = elf + elf_size;

	/* verify basic things first */
	if (!elf ||
	    ((intptr_t)elf & 7) ||
	    elf_size < sizeof(*ehdr) ||
	    memcmp(ehdr->e_ident, ELFMAG, SELFMAG) || 
	    ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
	    ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||	/* only little endian */
	    ehdr->e_ident[EI_VERSION] != 1 ||
	    ehdr->e_ident[EI_OSABI] != ELFOSABI_NONE ||
	    ehdr->e_type != ET_REL ||
	    (ehdr->e_machine != EM_NONE && ehdr->e_machine != EM_BPF)) {
		ebpf_debug(vm, "Invalid ELF file\n");
		goto error;
	}

	/* check sections for validity */
	for (i = 0; i < ehdr->e_shnum; i++) {
		shdr = elf + ehdr->e_shoff + i * ehdr->e_shentsize;
		if ((const void *)(shdr + 1) > elf_end ||
		    elf + shdr->sh_offset + shdr->sh_size > elf_end) {
			ebpf_debug(vm, "Invalid ELF file 1\n");
			goto error;
		}
	}

	vm->num_sections = ehdr->e_shnum;
	vm->sections = malloc(sizeof(*s) * vm->num_sections);
	if (!vm->sections) {
		ebpf_debug(vm, "Failed to allocate sections\n");
		goto error;
	}
	vm->elf = elf;
	vm->elf_size = elf_size;

	for (i = 0; i < ehdr->e_shnum; i++) {
		shdr = elf + ehdr->e_shoff + i * ehdr->e_shentsize;
		data = elf + shdr->sh_offset;
		size = shdr->sh_size;

		s = &vm->sections[i];
		s->shdr = shdr;
		s->data = data;
		s->size = size;	/* align to 8 bytes */
		s->offset = -1;

		/* align */

		size = (size + 7) & ~7;
		if (shdr->sh_type == SHT_PROGBITS &&
			shdr->sh_flags == (SHF_ALLOC|SHF_EXECINSTR)) {
			s->text = true;
			vm->text_size += size;
			vm->total_size += size;
		} else if (shdr->sh_type == SHT_PROGBITS &&
				shdr->sh_flags == (SHF_ALLOC|SHF_WRITE)) {
			vm->data_size += size;
			vm->total_size += size;
		} else if (shdr->sh_type == SHT_PROGBITS &&
				(shdr->sh_flags & (SHF_ALLOC|SHF_WRITE)) == SHF_ALLOC) {
			vm->rodata_size += size;
			vm->total_size += size;
		} else if (shdr->sh_type == SHT_NOBITS &&
				(shdr->sh_flags == (SHF_ALLOC|SHF_WRITE))) {
			vm->bss_size += size;
			vm->total_size += size;
		}
	}

	ebpf_debug(vm, ".text   size = 0x%08" PRIx64 "\n", vm->text_size);
	ebpf_debug(vm, ".data   size = 0x%08" PRIx64 "\n", vm->data_size);
	ebpf_debug(vm, ".rodata size = 0x%08" PRIx64 "\n", vm->rodata_size);
	ebpf_debug(vm, ".bss    size = 0x%08" PRIx64 "\n", vm->bss_size);
	ebpf_debug(vm, ".total  size = 0x%08" PRIx64 "\n", vm->total_size);

	vm->workspace = malloc(vm->total_size);
	if (!vm->workspace) {
		ebpf_debug(vm, "Out of memory\n");
		goto error;
	}

	/* copy all sections that have text first */
	copy_offset = 0;

	vm->code_offset = copy_offset;
	for (i = 0; i < ehdr->e_shnum; i++) {
		s = &vm->sections[i];
		shdr = s->shdr;

		if (shdr->sh_type == SHT_PROGBITS &&
			shdr->sh_flags == (SHF_ALLOC|SHF_EXECINSTR)) {

			s->offset = copy_offset;
			memcpy(vm->workspace + s->offset, s->data, s->size);
			copy_offset += (s->size + 7) & ~7;

			ebpf_debug(vm, "Section #%d @0x%llx - 0x%llx\n", i,
				(unsigned long long)s->offset,
				(unsigned long long)s->size);
		}
	}
	vm->text_start = vm->workspace + vm->code_offset;
	vm->text_end = vm->text_start + (copy_offset - vm->code_offset);

	/* now copy read only */
	vm->rodata_offset = copy_offset;
	for (i = 0; i < ehdr->e_shnum; i++) {
		s = &vm->sections[i];
		shdr = s->shdr;

		if (s->offset != -1)
			continue;

		if (shdr->sh_type == SHT_PROGBITS &&
			(shdr->sh_flags & (SHF_ALLOC|SHF_WRITE)) == SHF_ALLOC) {
			s->offset = copy_offset;
			memcpy(vm->workspace + s->offset, s->data, s->size);
			copy_offset += (s->size + 7) & ~7;

			ebpf_debug(vm, "Section #%d @0x%llx - 0x%llx\n", i,
				(unsigned long long)s->offset,
				(unsigned long long)s->size);
		}
	}
	vm->rodata_start = vm->workspace + vm->rodata_offset;
	vm->rodata_end = vm->rodata_start + (copy_offset - vm->rodata_offset);

	/* rest of r/w data */
	vm->rwdata_offset = copy_offset;
	for (i = 0; i < ehdr->e_shnum; i++) {
		s = &vm->sections[i];
		shdr = s->shdr;

		if (s->offset != -1)
			continue;

		if (shdr->sh_type == SHT_PROGBITS) {
			s->offset = copy_offset;
			memcpy(vm->workspace + s->offset, s->data, s->size);
			copy_offset += (s->size + 7) & ~7;
			ebpf_debug(vm, "Section #%d @0x%llx - 0x%llx\n", i,
				(unsigned long long)s->offset,
				(unsigned long long)s->size);
		} else if (shdr->sh_type == SHT_NOBITS) {
			s->offset = copy_offset;
			memset(vm->workspace + s->offset, 0, s->size);
			copy_offset += (s->size + 7) & ~7;
			ebpf_debug(vm, "Section #%d @0x%llx - 0x%llx\n", i,
				(unsigned long long)s->offset,
				(unsigned long long)s->size);
		}
	}
	vm->rwdata_start = vm->workspace + vm->rwdata_offset;
	vm->rwdata_end = vm->rwdata_start + (copy_offset - vm->rwdata_offset);

	/* Process each relocation section */
	for (i = 0; i < ehdr->e_shnum; i++) {
		rel = &vm->sections[i];
		if (rel->shdr->sh_type != SHT_REL)
			continue;

		rs = rel->data;
		if (rel->shdr->sh_link >= ehdr->e_shnum) {
			ebpf_debug(vm, "Bad symbol table section #%d\n", i);
			goto error;
		}

		symtab = &vm->sections[rel->shdr->sh_link];
		syms = symtab->data;
		num_syms = symtab->size/sizeof(syms[0]);

		if (symtab->shdr->sh_link >= ehdr->e_shnum) {
			ebpf_debug(vm, "Bad string table section #%d\n", i);
			goto error;
		}

		strtab = &vm->sections[symtab->shdr->sh_link];
		strings = strtab->data;

		for (j = 0; j < rel->size/sizeof(Elf64_Rel); j++) {
			r = &rs[j];

			sym_idx = ELF64_R_SYM(r->r_info);
			if (sym_idx >= num_syms) {
				ebpf_debug(vm, "Bad string table index #%d\n", sym_idx);
				goto error;
			}

			sym = &syms[sym_idx];

			if (sym->st_name >= strtab->size) {
				ebpf_debug(vm, "Bad symbol name\n");
				goto error;
			}

			source = sym->st_shndx ? &vm->sections[sym->st_shndx] : NULL;

			sym_name = strings + sym->st_name;
			target = &vm->sections[rel->shdr->sh_info];

			r_offset = r->r_offset + target->offset;

			switch (ELF64_R_TYPE(r->r_info)) {
			case R_BPF_64_64:
			case R_BPF_64_32:
				if (r_offset + 8 > vm->total_size) {
					ebpf_debug(vm, "bad relocation\n");
					goto error;
				}

				if (!source) {
					for (cb = vm->callbacks; cb && cb->name; cb++) {
						if (!strcmp(cb->name, sym_name))
							break;
					}
					if (cb && !cb->name)
						cb = NULL;

					if (!cb) {
						ebpf_debug(vm, "function '%s' not found; add unres entry\n", sym_name);
						ue = malloc(sizeof(*ue));
						if (!ue) {
							ebpf_debug(vm, "allocation error");
							goto error;
						}
						ue->name = sym_name;
						ue->r_offset = r_offset;
						ue->r_type = ELF64_R_TYPE(r->r_info);
						list_add_tail(&ue->node, &vm->unres);
						imm = -1;	/* marker for unresolved */
					} else
						imm = cb - vm->callbacks;

				} else {
					/* else value */
					ebpf_debug(vm, "source->offset=0x%llx sym->st_value=0x%llx\n",
							(unsigned long long)source->offset,
							(unsigned long long)sym->st_value);

					imm = source->offset + sym->st_value + (intptr_t)vm->workspace;
				}

				if (ELF64_R_TYPE(r->r_info) == R_BPF_64_64) {
					ebpf_debug(vm, "fixup%d 0x%llx @0x%08llx\n",
							64, (unsigned long long)imm,
							(unsigned long long)r_offset);

					/* LE fixup */
					*(uint32_t *)(vm->workspace + r_offset + 4) = (uint32_t)imm;
					*(uint32_t *)(vm->workspace + r_offset + 4 + 8) = (uint32_t)((uint64_t)imm >> 32);
				} else {
					ebpf_debug(vm, "fixup%d 0x%llx @0x%08llx\n",
							32, (unsigned long long)imm,
							(unsigned long long)r_offset);

					*(uint32_t *)(vm->workspace + r_offset + 4) = imm;
				}
				break;
			default:
				ebpf_debug(vm, "bad relocation type %lu (sym_name=%s r->r_offset=%lu)",
						ELF64_R_TYPE(r->r_info), sym_name, r->r_offset);
				goto error;
			}
		}
	}

	return 0;

error:
	ebpf_cleanup(vm);
	return -1;
}

bool
ebpf_load_store_check(const struct ebpf_ctx *ctx, const void *addr, int size,
		      bool store)
{
	const void *end = addr + size;
	const struct ebpf_vm *vm = ctx->vm;
	struct ebpf_chunk *c;

	/* Context access */
	if (ctx->mem && (addr >= ctx->mem && end <= ctx->mem_end))
		return true;

	/* Stack access */
	if (addr >= ctx->stack && end <= ctx->stack_end)
		return true;

	/* R/W */
	if (addr >= vm->rwdata_start && end <= vm->rwdata_end)
		return true;

	/* RO */
	if (!store && (addr >= vm->rodata_start && end <= vm->rodata_end))
		return true;

	/* finally try allocated chunks (or memory windows) */
	list_for_each_entry(c, &ctx->allocs, node) {
		if (store && !c->writeable)
			continue;
		if (addr >= c->addr && end <= c->addr + c->size)
			return true;
	}

	ebpf_debug(vm, "error: out of bounds memory %s at PC %u, addr %p, size %d\n",
			store ? "store" : "load", ctx->pc, addr, size);
	ebpf_debug(vm, "mem %p-%p stack %p-%p text %p-%p rodata %p-%p rwdata %p-%p\n",
			ctx->mem, ctx->mem_end,
			ctx->stack, ctx->stack_end,
			vm->text_start, vm->text_end,
			vm->rodata_start, vm->rodata_end,
			vm->rwdata_start, vm->rwdata_end);

	/* illegal access */
	return false;
}

uint64_t ebpf_exec(struct ebpf_vm *vm, void *mem, size_t mem_len,
		   int *errcode)
{
	uint16_t pc;
	uint16_t cur_pc;
	const struct ebpf_inst *insts = vm->text_start;
	uint64_t reg[16];
	uint64_t stack[(STACK_SIZE+7)/8];
	struct ebpf_inst inst;
	struct ebpf_unresolved_entry *ue;
	struct ebpf_ctx ctx;
	const char *lazy_name;
	struct ebpf_chunk *c, *cn;

	if (!vm)
		return UINT64_MAX;

	if (errcode)
		*errcode = 0;

	memset(&ctx, 0, sizeof(ctx));
	ctx.vm = vm;
	ctx.mem = mem;
	ctx.mem_size = mem_len;
	ctx.mem_end = mem + mem_len;
	ctx.stack = stack;
	ctx.stack_size = sizeof(stack);
	ctx.stack_end = stack + sizeof(stack);
	ctx.reg = reg;
	INIT_LIST_HEAD(&ctx.allocs);

	reg[1] = (uintptr_t)mem;
	reg[10] = (uintptr_t)ctx.stack_end;

	pc = 0;
	cur_pc = 0;
	while (!ctx.errcode) {
		cur_pc = pc;
		inst = insts[pc++];	/* TODO verify */
		ctx.pc = cur_pc;

		ebpf_debug(vm, "[%d] opcode=%02x dst=%1x src=%1x offset=%04x imm=%08x\n",
				cur_pc, (unsigned int)inst.opcode,
				(unsigned int)inst.dst, (unsigned int)inst.src,
				(unsigned int)inst.offset, (unsigned int)inst.imm);

		switch (inst.opcode) {
		case EBPF_OP_ADD_IMM:
			reg[inst.dst] += inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_ADD_REG:
			reg[inst.dst] += reg[inst.src];
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_SUB_IMM:
			reg[inst.dst] -= inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_SUB_REG:
			reg[inst.dst] -= reg[inst.src];
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_MUL_IMM:
			reg[inst.dst] *= inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_MUL_REG:
			reg[inst.dst] *= reg[inst.src];
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_DIV_IMM:
			reg[inst.dst] = (uint32_t)reg[inst.dst] / (uint32_t)inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_DIV_REG:
			if (reg[inst.src] == 0) {
				ebpf_debug(vm, "uBPF error: division by zero at PC %u\n", cur_pc);
				ctx.errcode = -ERANGE;
				break;
			}
			reg[inst.dst] = (uint32_t)reg[inst.dst] / (uint32_t)reg[inst.src];
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_OR_IMM:
			reg[inst.dst] |= inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_OR_REG:
			reg[inst.dst] |= reg[inst.src];
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_AND_IMM:
			reg[inst.dst] &= inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_AND_REG:
			reg[inst.dst] &= reg[inst.src];
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_LSH_IMM:
			reg[inst.dst] <<= inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_LSH_REG:
			reg[inst.dst] <<= reg[inst.src];
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_RSH_IMM:
			reg[inst.dst] = ((uint32_t)reg[inst.dst]) >> inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_RSH_REG:
			reg[inst.dst] = ((uint32_t)reg[inst.dst]) >> reg[inst.src];
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_NEG:
			reg[inst.dst] = -reg[inst.dst];
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_MOD_IMM:
			reg[inst.dst] = (uint32_t)reg[inst.dst] % (uint32_t)inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_MOD_REG:
			if (reg[inst.src] == 0) {
				ebpf_debug(vm, "uBPF error: division by zero at PC %u\n", cur_pc);
				ctx.errcode = -ERANGE;
				break;
			}
			reg[inst.dst] = (uint32_t)reg[inst.dst] % (uint32_t)reg[inst.src];
			break;
		case EBPF_OP_XOR_IMM:
			reg[inst.dst] ^= inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_XOR_REG:
			reg[inst.dst] ^= reg[inst.src];
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_MOV_IMM:
			reg[inst.dst] = inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_MOV_REG:
			reg[inst.dst] = reg[inst.src];
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_ARSH_IMM:
			reg[inst.dst] = (int32_t)reg[inst.dst] >> inst.imm;
			reg[inst.dst] &= UINT32_MAX;
			break;
		case EBPF_OP_ARSH_REG:
			reg[inst.dst] = (int32_t)reg[inst.dst] >> (uint32_t)reg[inst.src];
			reg[inst.dst] &= UINT32_MAX;
			break;

		case EBPF_OP_LE:
			if (inst.imm == 16) {
				reg[inst.dst] = htole16(reg[inst.dst]);
			} else if (inst.imm == 32) {
				reg[inst.dst] = htole32(reg[inst.dst]);
			} else if (inst.imm == 64) {
				reg[inst.dst] = htole64(reg[inst.dst]);
			}
			break;
		case EBPF_OP_BE:
			if (inst.imm == 16) {
				reg[inst.dst] = htobe16(reg[inst.dst]);
			} else if (inst.imm == 32) {
				reg[inst.dst] = htobe32(reg[inst.dst]);
			} else if (inst.imm == 64) {
				reg[inst.dst] = htobe64(reg[inst.dst]);
			}
			break;


		case EBPF_OP_ADD64_IMM:
			reg[inst.dst] += inst.imm;
			break;
		case EBPF_OP_ADD64_REG:
			reg[inst.dst] += reg[inst.src];
			break;
		case EBPF_OP_SUB64_IMM:
			reg[inst.dst] -= inst.imm;
			break;
		case EBPF_OP_SUB64_REG:
			reg[inst.dst] -= reg[inst.src];
			break;
		case EBPF_OP_MUL64_IMM:
			reg[inst.dst] *= inst.imm;
			break;
		case EBPF_OP_MUL64_REG:
			reg[inst.dst] *= reg[inst.src];
			break;
		case EBPF_OP_DIV64_IMM:
			reg[inst.dst] /= inst.imm;
			break;
		case EBPF_OP_DIV64_REG:
			if (reg[inst.src] == 0) {
				ebpf_debug(vm, "uBPF error: division by zero at PC %u\n", cur_pc);
				ctx.errcode = -ERANGE;
				break;
			}
			reg[inst.dst] /= reg[inst.src];
			break;
		case EBPF_OP_OR64_IMM:
			reg[inst.dst] |= inst.imm;
			break;
		case EBPF_OP_OR64_REG:
			reg[inst.dst] |= reg[inst.src];
			break;
		case EBPF_OP_AND64_IMM:
			reg[inst.dst] &= inst.imm;
			break;
		case EBPF_OP_AND64_REG:
			reg[inst.dst] &= reg[inst.src];
			break;
		case EBPF_OP_LSH64_IMM:
			reg[inst.dst] <<= inst.imm;
			break;
		case EBPF_OP_LSH64_REG:
			reg[inst.dst] <<= reg[inst.src];
			break;
		case EBPF_OP_RSH64_IMM:
			reg[inst.dst] >>= inst.imm;
			break;
		case EBPF_OP_RSH64_REG:
			reg[inst.dst] >>= reg[inst.src];
			break;
		case EBPF_OP_NEG64:
			reg[inst.dst] = -reg[inst.dst];
			break;
		case EBPF_OP_MOD64_IMM:
			reg[inst.dst] %= inst.imm;
			break;
		case EBPF_OP_MOD64_REG:
			if (reg[inst.src] == 0) {
				ebpf_debug(vm, "uBPF error: division by zero at PC %u\n", cur_pc);
				ctx.errcode = -ERANGE;
			}
			reg[inst.dst] %= reg[inst.src];
			break;
		case EBPF_OP_XOR64_IMM:
			reg[inst.dst] ^= inst.imm;
			break;
		case EBPF_OP_XOR64_REG:
			reg[inst.dst] ^= reg[inst.src];
			break;
		case EBPF_OP_MOV64_IMM:
			reg[inst.dst] = inst.imm;
			break;
		case EBPF_OP_MOV64_REG:
			reg[inst.dst] = reg[inst.src];
			break;
		case EBPF_OP_ARSH64_IMM:
			reg[inst.dst] = (int64_t)reg[inst.dst] >> inst.imm;
			break;
		case EBPF_OP_ARSH64_REG:
			reg[inst.dst] = (int64_t)reg[inst.dst] >> reg[inst.src];
			break;

		case EBPF_OP_LDXW:
			reg[inst.dst] = ebpf_load32(&ctx, (void *)reg[inst.src] + inst.offset);
			break;
		case EBPF_OP_LDXH:
			reg[inst.dst] = ebpf_load16(&ctx, (void *)reg[inst.src] + inst.offset);
			break;
		case EBPF_OP_LDXB:
			reg[inst.dst] = ebpf_load8(&ctx, (void *)reg[inst.src] + inst.offset);
			break;
		case EBPF_OP_LDXDW:
			reg[inst.dst] = ebpf_load64(&ctx, (void *)reg[inst.src] + inst.offset);
			break;

		case EBPF_OP_STW:
			ebpf_store32(&ctx, (void *)reg[inst.dst] + inst.offset, inst.imm);
			break;
		case EBPF_OP_STH:
			ebpf_store16(&ctx, (void *)reg[inst.dst] + inst.offset, inst.imm);
			break;
		case EBPF_OP_STB:
			ebpf_store8(&ctx, (void *)reg[inst.dst] + inst.offset, inst.imm);
			break;
		case EBPF_OP_STDW:
			ebpf_store64(&ctx, (void *)reg[inst.dst] + inst.offset, inst.imm);
			break;

		case EBPF_OP_STXW:
			ebpf_store32(&ctx, (void *)reg[inst.dst] + inst.offset, reg[inst.src]);
			break;
		case EBPF_OP_STXH:
			ebpf_store16(&ctx, (void *)reg[inst.dst] + inst.offset, reg[inst.src]);
			break;
		case EBPF_OP_STXB:
			ebpf_store8(&ctx, (void *)reg[inst.dst] + inst.offset, reg[inst.src]);
			break;
		case EBPF_OP_STXDW:
			ebpf_store64(&ctx, (void *)reg[inst.dst] + inst.offset, reg[inst.src]);
			break;

		case EBPF_OP_LDDW:
			reg[inst.dst] = (uint64_t)(uint32_t)inst.imm | ((uint64_t)insts[pc++].imm << 32);
			break;

		case EBPF_OP_JA:
			pc += inst.offset;
			break;
		case EBPF_OP_JEQ_IMM:
			if (reg[inst.dst] == inst.imm)
				pc += inst.offset;
			break;
		case EBPF_OP_JEQ_REG:
			if (reg[inst.dst] == reg[inst.src])
				pc += inst.offset;
			break;
		case EBPF_OP_JGT_IMM:
			if (reg[inst.dst] > (uint32_t)inst.imm)
				pc += inst.offset;
			break;
		case EBPF_OP_JGT_REG:
			if (reg[inst.dst] > reg[inst.src])
				pc += inst.offset;
			break;
		case EBPF_OP_JGE_IMM:
			if (reg[inst.dst] >= (uint32_t)inst.imm)
				pc += inst.offset;
			break;
		case EBPF_OP_JGE_REG:
			if (reg[inst.dst] >= reg[inst.src])
				pc += inst.offset;
			break;
		case EBPF_OP_JSET_IMM:
			if (reg[inst.dst] & inst.imm)
				pc += inst.offset;
			break;
		case EBPF_OP_JSET_REG:
			if (reg[inst.dst] & reg[inst.src])
				pc += inst.offset;
			break;
		case EBPF_OP_JNE_IMM:
			if (reg[inst.dst] != inst.imm)
				pc += inst.offset;
			break;
		case EBPF_OP_JNE_REG:
			if (reg[inst.dst] != reg[inst.src])
				pc += inst.offset;
			break;
		case EBPF_OP_JSGT_IMM:
			if ((int64_t)reg[inst.dst] > inst.imm)
				pc += inst.offset;
			break;
		case EBPF_OP_JSGT_REG:
			if ((int64_t)reg[inst.dst] > (int64_t)reg[inst.src])
				pc += inst.offset;
			break;
		case EBPF_OP_JSGE_IMM:
			if ((int64_t)reg[inst.dst] >= inst.imm)
				pc += inst.offset;
			break;
		case EBPF_OP_JSGE_REG:
			if ((int64_t)reg[inst.dst] >= (int64_t)reg[inst.src])
				pc += inst.offset;
			break;
		case EBPF_OP_EXIT:
			ctx.errcode = reg[0];
			goto no_error;

		case EBPF_OP_CALL:
			ctx.pc = cur_pc;
			lazy_name = NULL;
			/* standard immediate call */
			if ((uint32_t)inst.imm < vm->num_callbacks) {
				ebpf_debug(vm, "call #%u 0x%016lx 0x%016lx 0x%016lx 0x%016lx 0x%016lx\n",
						inst.imm, reg[1], reg[2], reg[3], reg[4], reg[5]);
				reg[0] = vm->callbacks[inst.imm].func(reg[1], reg[2], reg[3], reg[4], reg[5], &ctx);
				break;
			}

			/* unresolved? try lazy search */
			if ((uint32_t)inst.imm == -1 && vm->lazy_func) {
				list_for_each_entry(ue, &vm->unres, node) {
					if ((ue->r_offset / 8) == cur_pc) {
						lazy_name = ue->name;
						break;
					}
				}
				if (lazy_name) {
					reg[0] = vm->lazy_func(reg[1], reg[2],
							       reg[3], reg[4],
							       reg[5], &ctx,
							       lazy_name);
					break;
				}
			}

			ebpf_debug(vm, "Call imm=0x%04x is unknown\n", inst.imm);
			ctx.errcode = -ENOENT;
			break;
		}
	}

	printf("Execution error at pc %u\n", cur_pc);

	if (errcode)
		*errcode = ctx.errcode;

no_error:
	/* free all memory */
	list_for_each_entry_safe(c, cn, &ctx.allocs, node)
		ebpf_free(&ctx, c->data);

	return ctx.errcode;
}
