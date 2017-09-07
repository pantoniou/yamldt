/*
 * yamldt.c - main parser source
 *
 * YAML to DTB generator
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
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <stdbool.h>
#include <stdarg.h>
#include <assert.h>
#include <limits.h>

#define _GNU_SOURCE
#include <getopt.h>

#include "utils.h"
#include "syexpr.h"

#include "dt.h"

#include "dtbgen.h"
#include "yamlgen.h"
#include "nullgen.h"

#include "nullcheck.h"
#include "dtbcheck.h"

static struct option opts[] = {
	{ "output",	 	required_argument, 0, 'o' },
	{ "debug",	 	no_argument,	   0, 'd' },
	{ "",			no_argument,	   0, 'c' },
	{ "compatible",		no_argument,	   0, 'C' },
	{ "yaml",		no_argument,	   0, 'y' },
	{ "dts",		no_argument,	   0, 's' },
	{ "schema",		required_argument, 0, 'S' },
	{ "codegen",		required_argument, 0, 'g' },
	{ "save-temps",		no_argument, 	   0,  0  },
	{ "schema-save",	required_argument, 0,  0  },
	{ "silent",		no_argument,	   0,  0  },
	{ "color",		required_argument, 0,  0  },
	{ "symbols",		no_argument, 	   0, '@' },
	{ "help",	 	no_argument, 	   0, 'h' },
	{ "version",     	no_argument,       0, 'v' },
	{0, 0, 0, 0}
};

static void help(struct list_head *emitters, struct list_head *checkers)
{
	printf(
"yamldt [options] <input-file> [<input-file>...]\n"
" options are:\n"
"   -o, --output        Output file\n"
"   -d, --debug         Debug messages\n"
"   -c                  Don't resolve references (object mode)\n"
"   -C, --compatible    Compatible mode\n"
"   -s, --dts           DTS mode\n"
"   -y, --yaml          YAML mode\n"
"   -S, --schema        Use schema (all yaml files in dir/)\n"
"   -g, --codegen       Code generator configuration file\n"
"       --save-temps    Save temporary files\n"
"       --schema-save   Save schema to given file\n"
"       --silent        Be really silent\n"
"       --color         [auto|off|on]\n"
"   -h, --help          Help\n"
"   -v, --version       Display version\n"
		);
}

int main(int argc, char *argv[])
{
	struct yaml_dt_state dt_state, *dt = &dt_state;
	int err;
	int i, cc, option_index = 0;
	struct yaml_dt_config cfg_data, *cfg = &cfg_data;
	struct list_head emitters;
	struct yaml_dt_emitter *e, *selected_emitter = NULL;
	struct list_head checkers;
	struct yaml_dt_checker *c, *selected_checker = NULL;
	const char *s, *t;
	const char * const *ss;
	bool input_output_optional = false;

	memset(dt, 0, sizeof(*dt));

	/* setup emitters list */
	INIT_LIST_HEAD(&emitters);
	list_add_tail(&dtb_emitter.node, &emitters);
	list_add_tail(&yaml_emitter.node, &emitters);
	list_add_tail(&null_emitter.node, &emitters);

	INIT_LIST_HEAD(&checkers);
	list_add_tail(&null_checker.node, &checkers);
	list_add_tail(&dtb_checker.node, &checkers);

	memset(cfg, 0, sizeof(*cfg));

	/* get and consume common options */
	option_index = -1;
	optind = 0;
	opterr = 0;	/* do not print error for invalid option */
	cfg->color = -1;

	/* try to find output file argument */
	for (i = 1; i < argc; i++) {
		s = &argv[i][0];
		if ((cc = *s++) != '-')
			continue;
		/* no other options from o */
		if ((cc = *s) == 'o') {
			t = strchr(s, '=');
			if (t)
				cfg->output_file = t + 1;
			else if (i + 1 < argc)
				cfg->output_file = argv[i + 1];
		}
		if (cfg->output_file)
			break;
	}

	/* try to select an emitter by asking first */
	list_for_each_entry(e, &emitters, node) {
		if (e->eops && e->eops->select && e->eops->select(argc, argv)) {
			selected_emitter = e;
			break;
		}
	}

	/* no bites, try to search for suffix match */
	if (!selected_emitter && cfg->output_file &&
			(s = strrchr(cfg->output_file, '.'))) {
		list_for_each_entry(e, &emitters, node) {
			if (!e->suffixes)
				continue;

			for (ss = e->suffixes; *ss; ss++)
				if (!strcmp(*ss, s))
					break;

			if (*ss) {
				selected_emitter = e;
				break;
			}
		}
	}

	/* if all fails, fallback to dtb emitter */
	if (!selected_emitter)
		selected_emitter = &dtb_emitter;

	/* try to select an checker by asking first */
	list_for_each_entry(c, &checkers, node) {
		if (c->cops && c->cops->select && c->cops->select(argc, argv)) {
			selected_checker = c;
			break;
		}
	}

	/* if all fails, fallback to null checker */
	if (!selected_checker)
		selected_checker = &null_checker;

	opterr = 1;
	while ((cc = getopt_long(argc, argv,
			"o:dcvCys@S:g:h?", opts, &option_index)) != -1) {

		if (cc == 0 && option_index >= 0) {
			s = opts[option_index].name;
			if (!s)
				continue;
			if (!strcmp(s, "silent")) {
				cfg->silent = true;
				continue;
			}
			if (!strcmp(s, "color")) {
				if (!strcmp(optarg, "auto"))
					cfg->color = -1;
				else if (!strcmp(optarg, "on"))
					cfg->color = 1;
				else
					cfg->color = 0;
				continue;
			}
			if (!strcmp(s, "save-temps")) {
				cfg->save_temps = true;
				continue;
			}
			if (!strcmp(s, "schema-save")) {
				cfg->schema_save = optarg;
				continue;
			}
		}

		switch (cc) {
		case 'o':
			cfg->output_file = optarg;
			break;
		case 'd':
			cfg->debug = true;
			break;
		case 'c':
			cfg->object = true;
			break;
		case 'C':
			cfg->compatible = true;
			break;
		case '@':
			cfg->symbols = true;
			break;
		case 'y':
			cfg->yaml = true;
			break;
		case 's':
			cfg->dts = true;
			break;
		case 'S':
			cfg->schema = optarg;
			break;
		case 'g':
			cfg->codegen = optarg;
			break;
		case 'v':
			printf("%s version %s\n", PACKAGE_NAME, VERSION);
			return 0;
		case 'h':
		case '?':
			help(&emitters, &checkers);
			return cc == 'h' ? 0 : EXIT_FAILURE;
		}
	}

	/* they're optional when saving the schema only */
	input_output_optional = cfg->schema_save;

	if (!input_output_optional && optind >= argc) {
		fprintf(stderr, "Missing input file arguments optind/argc %d/%d\n", optind, argc);
		return EXIT_FAILURE;
	}

	if (!input_output_optional && !cfg->output_file) {
		fprintf(stderr, "Missing output file\n");
		return EXIT_FAILURE;
	}

	cfg->input_file = argv + optind;
	cfg->input_file_count = argc - optind;

	err = dt_setup(dt, cfg, selected_emitter, selected_checker);
	if (err)
		return EXIT_FAILURE;

	err = dt_parse(dt);

	if (!err && cfg->output_file) {
		dt_emitter_emit(dt);
		dt_checker_check(dt);
	}
	dt_cleanup(dt, dt->error_flag);

	return err ? EXIT_FAILURE : 0;
}
