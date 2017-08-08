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

#include "dt.h"
#include "nullgen.h"
#include "nullcheck.h"

struct ctx {
	struct yaml_dt_state dt;
	struct ebpf_vm vm;
};
#define ctx_to_dt(_ctx) 	(&(_ctx)->dt)
#define ctx_to_vm(_ctx) 	(&(_ctx)->vm)
#define vm_to_ctx(_vm) 		container_of(_vm, struct ctx, vm)
#define dt_to_ctx(_dt) 		container_of(_dt, struct ctx, dt)

static struct option opts[] = {
	{ "check",	required_argument, 0, 'c' },
	{ "help",	no_argument,       0, 'h' },
	{ "debug",	no_argument,       0, 'd' },
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

/* verify that the node is valid by comparing to each one in the tree */
struct node *get_and_verify_node(struct yaml_dt_state *dt, struct node *np, uint64_t ptr)
{
	struct node *child, *match;

	if ((intptr_t)np == (intptr_t)ptr)
		return np;

	list_for_each_entry(child, &np->children, node) {
		match = get_and_verify_node(dt, child, ptr);
		if (match)
			return match;
	}

	return NULL;
}

const char *get_and_verify_str(struct ebpf_ctx *ctx, uint64_t ptr)
{
	const char *str = (void *)(intptr_t)ptr;
	int len;

	len = ebpf_strlen(ctx, str);
	if (len < 0)
		return NULL;
	return str;
}

const char **get_and_verify_strv(struct ebpf_ctx *ctx, uint64_t ptr)
{
	const char **strv = (void *)(intptr_t)ptr;
	int i, len;
	const char *s;

	i = 0;
	for (;;) {
		/* verify load is possible */
		if (!ebpf_load_check(ctx, &strv[i], sizeof(*strv)))
			break;
		s = strv[i];

		/* NULL? final entry */
		if (!s)
			return strv;

		len = ebpf_strlen(ctx, s);
		if (len < 0)
			break;
		i++;
	}
	return NULL;
}

static uint64_t bpf_get_int(uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3,
			     uint64_t arg4, struct ebpf_ctx *ctx)
{
	const struct ebpf_vm *vm = ctx->vm;
	struct yaml_dt_state *dt = ctx_to_dt(vm_to_ctx(vm));
	struct node *np = get_and_verify_node(dt, tree_root(to_tree(dt)), arg0);
	const char *name = (void *)(intptr_t)arg1;
	int namelen, err;
	char namebuf[NODE_FULLNAME_MAX];
	bool *existsp = (void *)(intptr_t)arg2;
	unsigned long long v;

	if (!np)
		return ctx->errcode = -EINVAL;

	namelen = ebpf_strlen(ctx, name);
	if (namelen < 0)
		return ctx->errcode = namelen;

	if (!ebpf_store_check(ctx, existsp, sizeof(bool)))
		return ctx->errcode = -EFAULT;

	ebpf_debug(vm, "%s %s name=%s\n", __func__,
		dn_fullname(np, namebuf, sizeof(namebuf)),
		name);

	v = dt_get_int(dt, np, name, 0, 0, &err);
	if (err) {
		*existsp = false;
		return 0;
	}

	*existsp = true;

	return (uint64_t)v;
}

static uint64_t bpf_get_bool(uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3,
			     uint64_t arg4, struct ebpf_ctx *ctx)
{
	const struct ebpf_vm *vm = ctx->vm;
	struct yaml_dt_state *dt = ctx_to_dt(vm_to_ctx(vm));
	struct node *np = get_and_verify_node(dt, tree_root(to_tree(dt)), arg0);
	const char *name = (void *)(intptr_t)arg1;
	int namelen, ret;
	char namebuf[NODE_FULLNAME_MAX];
	bool *existsp = (void *)(intptr_t)arg2;

	if (!np)
		return ctx->errcode = -EINVAL;

	namelen = ebpf_strlen(ctx, name);
	if (namelen < 0)
		return ctx->errcode = namelen;

	if (!ebpf_store_check(ctx, existsp, sizeof(bool)))
		return ctx->errcode = -EFAULT;

	ebpf_debug(vm, "%s %s name=%s\n", __func__,
		dn_fullname(np, namebuf, sizeof(namebuf)),
		name);

	ret = dt_get_bool(dt, np, name, 0, 0);
	if (ret < 0) {
		*existsp = false;
		return 0;
	}

	*existsp = true;

	return (uint64_t)ret;
}

static uint64_t bpf_get_str(uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3,
			     uint64_t arg4, struct ebpf_ctx *ctx)
{
	const struct ebpf_vm *vm = ctx->vm;
	struct yaml_dt_state *dt = ctx_to_dt(vm_to_ctx(vm));
	struct node *np = get_and_verify_node(dt, tree_root(to_tree(dt)), arg0);
	const char *name = (void *)(intptr_t)arg1;
	int namelen, err;
	char namebuf[NODE_FULLNAME_MAX];
	bool *existsp = (void *)(intptr_t)arg2;
	const char *str;

	if (!np)
		return ctx->errcode = -EINVAL;

	namelen = ebpf_strlen(ctx, name);
	if (namelen < 0)
		return ctx->errcode = namelen;

	if (!ebpf_store_check(ctx, existsp, sizeof(bool)))
		return ctx->errcode = -EFAULT;

	ebpf_debug(vm, "%s %s name=%s\n", __func__,
		dn_fullname(np, namebuf, sizeof(namebuf)),
		name);

	str = dt_get_string(dt, np, name, 0, 0);
	if (!str) {
		*existsp = false;
		return 0;
	}

	/* open window to the pointed string */
	err = ebpf_open_memory_window(ctx, str, strlen(str) + 1);
	if (err)
		return ctx->errcode = -ENOMEM;

	*existsp = true;

	ebpf_debug(vm, "v = \"%s\"\n", str);

	return (uint64_t)(intptr_t)str;
}

static uint64_t bpf_get_strseq(uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3,
			     uint64_t arg4, struct ebpf_ctx *ctx)
{
	const struct ebpf_vm *vm = ctx->vm;
	struct yaml_dt_state *dt = ctx_to_dt(vm_to_ctx(vm));
	struct node *np = get_and_verify_node(dt, tree_root(to_tree(dt)), arg0);
	const char *name = (void *)(intptr_t)arg1;
	bool *existsp = (void *)(intptr_t)arg2;
	int namelen, i, count ,err;
	char namebuf[NODE_FULLNAME_MAX];
	const char *s;
	const char **strv;

	if (!np || !name)
		return ctx->errcode = -EINVAL;

	namelen = ebpf_strlen(ctx, name);
	if (namelen < 0)
		return ctx->errcode = namelen;

	if (!ebpf_store_check(ctx, existsp, sizeof(bool)))
		return ctx->errcode = -EFAULT;

	ebpf_debug(vm, "%s %s name=%s\n", __func__,
		dn_fullname(np, namebuf, sizeof(namebuf)),
		name);

	/* get number of strings that the property contains */
	count = 0;
	while (dt_get_string(dt, np, name, 0, count))
		count++;

	/* if no strings are found return nothing */
	if (count == 0) {
		*existsp = false;
		return 0;
	}

	/* allocate a strv array */
	strv = ebpf_alloc(ctx, false, sizeof(*strv) * (count + 1));
	if (!strv)
		return ctx->errcode = -ENOMEM;

	/* now fill it in */
	for (i = 0; i < count; i++) {
		s = dt_get_string(dt, np, name, 0, i);
		assert(s);

		/* open window to the pointed string */
		err = ebpf_open_memory_window(ctx, s, strlen(s) + 1);
		if (err)
			return ctx->errcode = -ENOMEM;
		strv[i] = s;
	}
	strv[i] = NULL;

	*existsp = true;

	for (i = 0; i < count; i++)
		ebpf_debug(vm, "v[%d] = \"%s\"\n", i, strv[i]);

	return (uint64_t)(intptr_t)strv;
}

static uint64_t bpf_streq(uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3,
			     uint64_t arg4, struct ebpf_ctx *ctx)
{
	struct ebpf_vm *vm = ctx->vm;
	const char *str1 = get_and_verify_str(ctx, arg0);
	const char *str2 = get_and_verify_str(ctx, arg1);

	if (!str1 || !str2)
		return ctx->errcode = -EINVAL;

	ebpf_debug(vm, "%s %s %s\n", __func__, str1, str2);

	return !strcmp(str1, str2);
}

static uint64_t bpf_anystreq(uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3,
			     uint64_t arg4, struct ebpf_ctx *ctx)
{
	struct ebpf_vm *vm = ctx->vm;
	const char **strv = get_and_verify_strv(ctx, arg0);
	const char *str = get_and_verify_str(ctx, arg1);

	if (!strv || !str)
		return ctx->errcode = -EINVAL;

	ebpf_debug(vm, "%s\n", __func__);

	while (*strv) {
		if (!strcmp(*strv, str))
			return 1;
		strv++;
	}

	return 0;
}

static uint64_t bpf_get_parent(uint64_t arg0, uint64_t arg1,
			       uint64_t arg2, uint64_t arg3,
			       uint64_t arg4, struct ebpf_ctx *ctx)
{
	const struct ebpf_vm *vm = ctx->vm;
	struct yaml_dt_state *dt = ctx_to_dt(vm_to_ctx(vm));
	struct node *np = get_and_verify_node(dt, tree_root(to_tree(dt)), arg0);
	const char *name = (void *)(intptr_t)arg1;
	int namelen;
	char namebuf[NODE_FULLNAME_MAX];

	if (!np)
		return ctx->errcode = -EINVAL;

	namelen = ebpf_strlen(ctx, name);
	if (namelen < 0)
		return ctx->errcode = namelen;

	ebpf_debug(vm, "%s %s name=%s\n", __func__,
		dn_fullname(np, namebuf, sizeof(namebuf)),
		name);

	return (uint64_t)(intptr_t)np->parent;
}

static uint64_t bpf_get_intseq(uint64_t arg0, uint64_t arg1,
			     uint64_t arg2, uint64_t arg3,
			     uint64_t arg4, struct ebpf_ctx *ctx)
{
	const struct ebpf_vm *vm = ctx->vm;
	struct yaml_dt_state *dt = ctx_to_dt(vm_to_ctx(vm));
	struct node *np = get_and_verify_node(dt, tree_root(to_tree(dt)), arg0);
	const char *name = (void *)(intptr_t)arg1;
	int64_t *countp = (void *)(intptr_t)arg2;
	bool *existsp = (void *)(intptr_t)arg3;
	int namelen, i, count, err;
	char namebuf[NODE_FULLNAME_MAX];
	int64_t *intp;

	if (!np || !name)
		return ctx->errcode = -EINVAL;

	namelen = ebpf_strlen(ctx, name);
	if (namelen < 0)
		return ctx->errcode = namelen;

	if (!ebpf_store_check(ctx, countp, sizeof(int64_t)))
		return ctx->errcode = -EFAULT;

	if (!ebpf_store_check(ctx, existsp, sizeof(bool)))
		return ctx->errcode = -EFAULT;

	ebpf_debug(vm, "%s %s name=%s\n", __func__,
		dn_fullname(np, namebuf, sizeof(namebuf)),
		name);

	/* get number of ints that the property contains */
	for (count = 0; ; count++) {
		(void)dt_get_int(dt, np, name, 0, count, &err);
		if (err < 0) {
			*existsp = false;
			return ctx->errcode = err;
		}
			
		count++;
	}

	/* if no strings are found return nothing */
	if (count == 0) {
		*existsp = false;
		return 0;
	}

	/* allocate a strv array */
	intp = ebpf_alloc(ctx, false, sizeof(*intp) * count);
	if (!intp)
		return ctx->errcode = -ENOMEM;

	/* now fill it in */
	for (i = 0; i < count; i++) {
		intp[i] = dt_get_int(dt, np, name, 0, i, &err);
		assert(err == 0);
	}

	*countp = count;
	*existsp = true;

	for (i = 0; i < count; i++)
		ebpf_debug(vm, "v[%d] = %llu\n", i, intp[i]);

	return (uint64_t)(intptr_t)intp;
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
	[3] = {
		.name = "get_int",
		.func = bpf_get_int,
	},
	[4] = {
		.name = "get_bool",
		.func = bpf_get_bool,
	},
	[5] = {
		.name = "get_str",
		.func = bpf_get_str,
	},
	[6] = {
		.name = "get_strseq",
		.func = bpf_get_strseq,
	},
	[7] = {
		.name = "streq",
		.func = bpf_streq,
	},
	[8] = {
		.name = "streq",
		.func = bpf_anystreq,
	},
	[9] = {
		.name = "get_parent",
		.func = bpf_get_parent,
	},
	[10] = {
		.name = "get_intseq",
		.func = bpf_get_intseq,
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

static void run_filter_on_node(struct yaml_dt_state *dt, struct ebpf_vm *vm, struct node *np)
{
	struct node *child;
	char namebuf[NODE_FULLNAME_MAX];
	int err;
	uint64_t ret;

	ebpf_debug(vm, "Running filter on node %s\n",
			dn_fullname(np, namebuf, sizeof(namebuf)));

	ret = ebpf_exec(vm, np, 0, &err);

	if (err)
		fprintf(stderr, "Error code: %d (%s)\n", err, strerror(-err));
	else {
		ebpf_debug(vm, "Execution returns 0x%" PRIx64 "\n", ret);

		if (ret == 0)
			printf("match at node %s\n",
				dn_fullname(np, namebuf, sizeof(namebuf)));
	}

	list_for_each_entry(child, &np->children, node)
		run_filter_on_node(dt, vm, child);
}

int main(int argc, char *argv[])
{
	struct ctx ctx;
	struct yaml_dt_state *dt = &ctx.dt;
	struct ebpf_vm *vm = &ctx.vm;
	struct yaml_dt_config cfg_data, *cfg = &cfg_data;
	int cc, option_index = 0;
	struct stat st;
	size_t filesz, nread;
	void *data;
	FILE *fp;
	char *filename;
	bool debug = false;
	char *check = NULL;
	uint64_t ret;
	int err;
	char *dtargv[2];

	while ((cc = getopt_long(argc, argv,
			"c:dh?", opts, &option_index)) != -1) {
		switch (cc) {
		case 'c':
			check = optarg;
			break;
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

	ret = ebpf_setup(vm, bpf_cb, lazy_func,
			 debug ? bpf_debug : NULL, NULL);
	if (ret) {
		fprintf(stderr, "Failed to setup vm ebpf\n");
		return EXIT_FAILURE;
	}

	ret = ebpf_load_elf(vm, data, nread);
	if (ret) {
		fprintf(stderr, "Failed to read ebpf file %s\n", filename);
		return EXIT_FAILURE;
	}

	if (!check) {
		ret = ebpf_exec(vm, NULL, 0, &err);

		if (err)
			fprintf(stderr, "Error code: %d (%s)\n", err, strerror(-err));
		printf("Execution returns 0x%" PRIx64 "\n", ret);

	} else {
		memset(dt, 0, sizeof(*dt));
		memset(cfg, 0, sizeof(*cfg));
		cfg->debug = debug;

		dtargv[0] = check;
		dtargv[1] = NULL;

		cfg->input_file = dtargv;
		cfg->input_file_count = 1;

		err = dt_setup(dt, cfg, &null_emitter, &null_checker);
		if (err) {
			fprintf(stderr, "Failed to setup parser\n");
			return EXIT_FAILURE;
		}

		err = dt_parse(dt);

		if (err) {
			fprintf(stderr, "Failed to parse\n");
			dt_cleanup(dt, true);
			return EXIT_FAILURE;
		}

		run_filter_on_node(dt, vm, tree_root(to_tree(dt)));

		dt_cleanup(dt, false);
	}

	ebpf_cleanup(vm);

	return 0;
}
