/*
 * EBPF header file.
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

#ifndef EBPF_H
#define EBPF_H

#include <inttypes.h>
#include <stdint.h>
#include <errno.h>

#include <libelf.h>

struct ebpf_vm;

struct ebpf_ctx {
	const struct ebpf_vm *vm;
	void *mem;
	void *mem_end;
	size_t mem_size;
	void *stack;
	void *stack_end;
	size_t stack_size;
	uint64_t *reg;
	uint16_t pc;
	int errcode;
};

typedef uint64_t
(*ebpf_callback_func_t)(uint64_t arg0, uint64_t arg1, uint64_t arg2,
			uint64_t arg3, uint64_t arg4, struct ebpf_ctx *ctx);

typedef uint64_t
(*ebpf_lazy_func_t)(uint64_t arg0, uint64_t arg1, uint64_t arg2,
		    uint64_t arg3, uint64_t arg4,
		    struct ebpf_ctx *ctx, const char *funcname);

struct ebpf_callback {
	const char *name;
	ebpf_callback_func_t func;
};

struct ebpf_section {
	const Elf64_Shdr *shdr;
	const void *data;
	uint64_t size;
	uint64_t offset;
	bool text;
};

struct ebpf_unresolved_entry {
	struct list_head node;
	const char *name;
	Elf64_Addr  r_offset;
	Elf64_Xword r_type;
};

typedef void (*ebpf_debugf_t)(void *arg, const char *fmt, ...)
		__attribute__ ((__format__ (__printf__, 2, 0)));

struct ebpf_vm {
	bool initialized;
	const void *elf;		/* original ELF file */
	size_t elf_size;	
	size_t total_size;
	size_t text_size;
	size_t data_size;
	size_t bss_size;
	size_t code_size;
	size_t rodata_size;
	size_t code_offset;
	size_t rodata_offset;
	size_t rwdata_offset;
	void *workspace;
	const void *text_start;		/* where code may execute */
	const void *text_end;
	const void *rodata_start;	/* where loads may happen but not writes */
	const void *rodata_end;
	void *rwdata_start;		/* where both loads and stores are allowed */
	void *rwdata_end;
	struct list_head unres;
	int num_callbacks;
	const struct ebpf_callback *callbacks;
	ebpf_lazy_func_t lazy_func;
	int num_sections;
	struct ebpf_section *sections;	/* section follow */
	ebpf_debugf_t debugf;
	void *debugarg;
};

int ebpf_setup(struct ebpf_vm *vm, const struct ebpf_callback *callbacks,
	       ebpf_lazy_func_t lazy_func,
	       ebpf_debugf_t debugf, void *debugarg);
void ebpf_cleanup(struct ebpf_vm *vm);
int ebpf_load_elf(struct ebpf_vm *vm, const void *elf, size_t elf_size);

uint64_t ebpf_exec(const struct ebpf_vm *vm, void *mem, size_t mem_len,
		   int *errcode);

bool
ebpf_load_store_check(const struct ebpf_ctx *ctx, const void *addr,
		      int size, bool store);

static inline bool
ebpf_load_check(const struct ebpf_ctx *ctx, const void *addr, int size)
{
	return ebpf_load_store_check(ctx, addr, size, false);
}

static inline bool
ebpf_store_check(const struct ebpf_ctx *ctx, const void *addr, int size)
{
	return ebpf_load_store_check(ctx, addr, size, true);
}

static inline uint64_t
ebpf_load64(struct ebpf_ctx *ctx, const void *addr)
{
	if (!ebpf_load_check(ctx, addr, sizeof(uint64_t))) {
		ctx->errcode = -EFAULT;
		return 0xdeadbeefdeadbeef;
	}
	return *(const uint64_t *)addr;
}

static inline uint32_t
ebpf_load32(struct ebpf_ctx *ctx, const void *addr)
{
	if (!ebpf_load_check(ctx, addr, sizeof(uint32_t))) {
		ctx->errcode = -EFAULT;
		return 0xdeadbeef;
	}
	return *(const uint32_t *)addr;
}

static inline uint16_t
ebpf_load16(struct ebpf_ctx *ctx, const void *addr)
{
	if (!ebpf_load_check(ctx, addr, sizeof(uint16_t))) {
		ctx->errcode = -EFAULT;
		return 0xdead;
	}
	return *(const uint16_t *)addr;
}

static inline uint8_t
ebpf_load8(struct ebpf_ctx *ctx, const void *addr)
{
	if (!ebpf_load_check(ctx, addr, sizeof(uint8_t))) {
		ctx->errcode = -EFAULT;
		return 0xde;
	}
	return *(const uint8_t *)addr;
}

static inline int
ebpf_strlen(const struct ebpf_ctx *ctx, const char *str)
{
	const char *s;
	uint8_t c;

	s = str;
	while (ebpf_load_check(ctx, s, 1)) {
		c = *s++;
		if (!c)
			return s - str;
	}
	return -EFAULT;
}

static inline int
ebpf_store64(struct ebpf_ctx *ctx, const void *addr, uint64_t val)
{
	if (!ebpf_store_check(ctx, addr, sizeof(uint64_t)))
		return ctx->errcode = -EFAULT;
	*(uint64_t *)addr = val;
	return 0;
}

static inline int
ebpf_store32(struct ebpf_ctx *ctx, void *addr, uint32_t val)
{
	if (!ebpf_store_check(ctx, addr, sizeof(uint32_t)))
		return ctx->errcode = -EFAULT;
	*(uint32_t *)addr = val;
	return 0;
}

static inline int
ebpf_store16(struct ebpf_ctx *ctx, void *addr, uint16_t val)
{
	if (!ebpf_store_check(ctx, addr, sizeof(uint16_t)))
		return ctx->errcode = -EFAULT;
	*(uint16_t *)addr = val;
	return 0;
}

static inline int
ebpf_store8(struct ebpf_ctx *ctx, void *addr, uint8_t val)
{
	if (!ebpf_store_check(ctx, addr, sizeof(uint8_t)))
		return ctx->errcode = -EFAULT;
	*(uint8_t *)addr = val;
	return 0;
}

#endif
