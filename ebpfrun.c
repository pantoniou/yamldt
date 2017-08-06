/*
 * ebpfrun.c - Tester for the ebpf VM
 *
 * Use this to test the EBPF VM
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

#define _GNU_SOURCE
#include <getopt.h>

#include <libelf.h>

#include "list.h"
#include "utils.h"

#include "ebpf.h"

static struct option opts[] = {
	{ "help",	no_argument, 0, 'h' },
	{ "debug",	no_argument, 0, 'd' },
	{0, 0, 0, 0}
};

static void help(void)
{
	printf("bpfrun [options] <ebpf-file>\n"
		" options are:\n"
		"   -d, --debug		Enable debug messages\n"
		"   -h, --help		Help\n"
		);
}

static uint64_t lazy_func(uint64_t arg0, uint64_t arg1, uint64_t arg2,
			  uint64_t arg3, uint64_t arg4,
			  struct ebpf_ctx *ctx, const char *funcname)
{
	printf("Lazy function: %s(0x%" PRIx64 ", 0x%" PRIx64 ", 0x%" PRIx64  ", 0x%" PRIx64 ", 0x%" PRIx64 ")\n",
			funcname, arg0, arg1, arg2, arg3, arg4);

	return 0;
}

/* catch all for unresolved calls */
static uint64_t bpf_unresolved(uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3,
			     uint64_t arg4, struct ebpf_ctx *ctx)
{
	fprintf(stderr, "ebpf error: Unresolved call at PC %u\n", ctx->pc);
	ctx->errcode = -EFAULT;
	return 0;
}

static uint64_t bpf_callback(uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3,
			     uint64_t arg4, struct ebpf_ctx *ctx)
{
	printf("%s\n", __func__);

	return 0;
}

static uint64_t bpf_printf(uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3,
			     uint64_t arg4, struct ebpf_ctx *ctx)
{
	const char *fmt = (void *)(intptr_t)arg0;
	const char *s;
	char c;
	int argsno, len;

	/* count instances of % (which are not escaped) */

	/* get length of string (negative on fault) */
	len = ebpf_strlen(ctx, fmt);
	if (len < 0)
		return ctx->errcode = len;

	argsno = 1;	/* fmt is the first */
	s = fmt;
	while ((c = *s++) != '\0') {
		if (c == '\\' && ((c = *s++) == '\0'))
			break;
		if (c == '%')
			argsno++;
	}
	if (argsno > 5)
		ctx->errcode = -EINVAL;
	if (ctx->errcode)
		return ctx->errcode;

	switch (argsno) {
	case 1:
		return puts(fmt);
	case 2:
		return printf(fmt, arg1);
	case 3:
		return printf(fmt, arg1, arg2);
	case 4:
		return printf(fmt, arg1, arg2, arg3);
	case 5:
		return printf(fmt, arg1, arg2, arg3, arg4);
	}

	return -1;
}

static const struct ebpf_callback bpf_cb[] = {
	[0] = {
		.name = "unresolved",
		.func = bpf_unresolved,
	},
	[1] = {
		.name = "callback",
		.func = bpf_callback,
	},
	[2] = {
		.name = "bpf_printf",
		.func = bpf_printf,
	},
	{ NULL, NULL }
};

void bpf_debug(void *arg, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

int main(int argc, char *argv[])
{
	int cc, option_index = 0;
	struct stat st;
	size_t filesz, nread;
	void *data;
	FILE *fp;
	char *filename;
	bool debug = false;
	struct ebpf_vm vm;
	uint64_t ret;
	int err;

	while ((cc = getopt_long(argc, argv,
			"dh?", opts, &option_index)) != -1) {
		switch (cc) {
		case 'd':
			debug = true;
			break;
		case 'h':
		case '?':
			help();
			return cc == 'h' ? 0 : EXIT_FAILURE;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "Missing input file\n");
		return EXIT_FAILURE;
	}

	filename = argv[optind];
	fp = fopen(filename, "rb");
	if (!fp) {
		fprintf(stderr, "Unable to open file %s\n", filename);
		return EXIT_FAILURE;
	}

	if (fstat(fileno(fp), &st) == -1 || !S_ISREG(st.st_mode)) {
		fprintf(stderr, "Invalid file %s\n", filename);
		return EXIT_FAILURE;
	}
	filesz = st.st_size;
	data = alloca(filesz + 7);
	/* align at 8 bytes */
	data = (void *)((intptr_t)(data + 7) & ~7);
	nread = fread(data, 1, filesz, fp);
	fclose(fp);

	if (nread != filesz) {
		fprintf(stderr, "Failed to read file %s\n", filename);
		return EXIT_FAILURE;
	}

	ret = ebpf_setup(&vm, bpf_cb, lazy_func,
			 debug ? bpf_debug : NULL, NULL);
	if (ret) {
		fprintf(stderr, "Failed to setup vm ebpf\n");
		return EXIT_FAILURE;
	}

	ret = ebpf_load_elf(&vm, data, nread);
	if (ret) {
		fprintf(stderr, "Failed to read ebpf file %s\n", filename);
		return EXIT_FAILURE;
	}

	ret = ebpf_exec(&vm, NULL, 0, &err);

	if (err)
		fprintf(stderr, "Error code: %d (%s)\n", err, strerror(-err));

	printf("Execution returns 0x%" PRIx64 "\n", ret);

	ebpf_cleanup(&vm);

	return 0;
}
