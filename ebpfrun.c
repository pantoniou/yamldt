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

#include "ebpf_dt.h"

#include "dt.h"
#include "nullgen.h"
#include "nullcheck.h"

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

	for_each_child_of_node(np, child)
		run_filter_on_node(dt, vm, child);
}

int main(int argc, char *argv[])
{
	struct ebpf_dt_ctx ctx;
	struct yaml_dt_state dt_state, *dt = &dt_state;
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

	ctx.dt = dt;

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

	ret = ebpf_setup(vm, bpf_dt_cb, NULL,
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
