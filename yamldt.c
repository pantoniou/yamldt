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
	{ "quiet",		no_argument,	   0, 'q' },
	{ "in-format",		required_argument, 0, 'I' },
	{ "out-format",		required_argument, 0, 'O' },
	{ "out",	 	required_argument, 0, 'o' },
	{ "out-version",	required_argument, 0, 'V' },
	{ "debug",	 	no_argument,	   0,  0  },
	{ "",			no_argument,	   0, 'c' },
	{ "compatible",		no_argument,	   0, 'C' },
	{ "schema",		required_argument, 0,  0  },
	{ "codegen",		required_argument, 0, 'g' },
	{ "save-temps",		no_argument, 	   0,  0  },
	{ "schema-save",	required_argument, 0,  0  },
	{ "color",		required_argument, 0,  0  },
	{ "symbols",		no_argument, 	   0, '@' },
	{ "reserve",		required_argument, 0, 'R' },
	{ "space",		required_argument, 0, 'S' },
	{ "align",		required_argument, 0, 'a' },
	{ "pad",		required_argument, 0, 'p' },
	{ "help",	 	no_argument, 	   0, 'h' },
	{ "version",     	no_argument,       0, 'v' },
	{0, 0, 0, 0}
};

static void help(void)
{
	printf(
"yamldt [options] <input-file> [<input-file>...]\n"
" options are:\n"
"   -q, --quiet           Suppress; -q (warnings) -qq (errors) -qqq (everything)\n"
"   -I, --in-format=X     Input format type X=[auto|yaml|dts]\n"
"   -O, --out-format=X    Output format type X=[auto|yaml|dtb|dts|null]\n"
"   -o, --out=X           Output file\n"
"   -V, --out-version=X   DTB blob version to produce (only 17 supported)\n"
"   -c                    Don't resolve references (object mode)\n"
"   -C, --compatible      Bit-exact DTC compatibility mode\n"
"   -g, --codegen         Code generator configuration file\n"
"       --schema          Use schema (all yaml files in dir/)\n"
"       --save-temps      Save temporary files\n"
"       --schema-save     Save schema to given file\n"
"       --color           [auto|off|on]\n"
"       --debug           Debug messages\n"
"   -R, --reserve=X       Make space for X reserve map entries\n"
"   -S, --space=X         Make the DTB blob at least X bytes long\n"
"   -a, --align=X         Make the DTB blob align to X bytes\n"
"   -p, --pad=X           Pad the DTB blob with X bytes\n"
"   -h, --help            Help\n"
"   -v, --version         Display version\n"
		);
}

int main(int argc, char *argv[])
{
	struct yaml_dt_state dt_state, *dt = &dt_state;
	int err, cc, option_index = 0;
	struct yaml_dt_config cfg_data, *cfg = &cfg_data;
	struct list_head emitters;
	struct list_head checkers;
	struct yaml_dt_emitter *selected_emitter = NULL;
	struct yaml_dt_checker *selected_checker = NULL;
	const char *s;
	bool input_output_optional = false;

	memset(dt, 0, sizeof(*dt));

	/* setup emitters list */
	INIT_LIST_HEAD(&emitters);
	list_add_tail(&dtb_emitter.node, &emitters);
	list_add_tail(&yaml_emitter.node, &emitters);
	list_add_tail(&null_emitter.node, &emitters);

	/* setup checkers */
	INIT_LIST_HEAD(&checkers);
	list_add_tail(&null_checker.node, &checkers);
	list_add_tail(&dtb_checker.node, &checkers);

	memset(cfg, 0, sizeof(*cfg));
	cfg->color = -1;

	/* get and consume common options */
	option_index = -1;
	optind = 0;
	opterr = 1;
	while ((cc = getopt_long(argc, argv,
			"qo:I:O:d:V:R:S:a:p:cC@g:vh?", opts, &option_index)) != -1) {

		if (cc == 0 && option_index >= 0) {
			s = opts[option_index].name;
			if (!s)
				continue;
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
			if (!strcmp(s, "debug")) {
				cfg->debug = true;
				continue;
			}
			if (!strcmp(s, "schema")) {
				cfg->schema = optarg;
				continue;
			}
		}

		switch (cc) {
		case 'q':
			cfg->quiet++;
			break;
		case 'o':
			cfg->output_file = optarg;
			break;
		case 'I':
			cfg->input_format = optarg;
			break;
		case 'O':
			cfg->output_format = optarg;
			break;
		case 'd':
			cfg->depname = optarg;
			break;
		case 'V':
			cfg->out_version = strtoul(optarg, NULL, 0);
			break;
		case 'R':
			cfg->reserve = strtoul(optarg, NULL, 0);
			break;
		case 'S':
			cfg->space = strtoul(optarg, NULL, 0);
			break;
		case 'a':
			cfg->align = strtoul(optarg, NULL, 0);
			break;
		case 'p':
			cfg->pad = strtoul(optarg, NULL, 0);
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
		case 'g':
			cfg->codegen = optarg;
			break;
		case 'v':
			printf("%s version %s\n", PACKAGE_NAME, VERSION);
			return 0;
		case 'h':
		case '?':
			help();
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

	if (!cfg->input_format)
		cfg->input_format = "auto";

	if (strcmp(cfg->input_format, "auto") &&
	    strcmp(cfg->input_format, "yaml") &&
	    strcmp(cfg->input_format, "dts")) {
		fprintf(stderr, "bad input-format %s\n", cfg->input_format);
		return EXIT_FAILURE;
	}

	if (!cfg->output_format)
		cfg->output_format = "auto";

	if (strcmp(cfg->output_format, "auto") &&
	    strcmp(cfg->output_format, "yaml") &&
	    strcmp(cfg->output_format, "dts") &&
	    strcmp(cfg->output_format, "dtb") &&
	    strcmp(cfg->output_format, "null")) {
		fprintf(stderr, "bad output-format %s\n", cfg->output_format);
		return EXIT_FAILURE;
	}

	if (cfg->space && cfg->pad) {
		fprintf(stderr, "Can't set both space and pad\n");
		return EXIT_FAILURE;
	}

	cfg->input_file = argv + optind;
	cfg->input_file_count = argc - optind;

	/* guess input/output formats */
	if (!strcmp(cfg->input_format, "auto") && cfg->input_file_count > 0) {
		s = strrchr(cfg->input_file[0], '.');
		if (s && !strcmp(s, ".yaml"))
			cfg->input_format = "yaml";
		else if (s && !strcmp(s, ".dts"))
			cfg->input_format = "dts";
	}

	if (!strcmp(cfg->output_format, "auto") && cfg->output_file) {
		s = strrchr(cfg->output_file, '.');
		if (s && !strcmp(s, ".yaml"))
			cfg->output_format = "yaml";
		else if (s && !strcmp(s, ".dtb"))
			cfg->output_format = "dtb";
		else if (s && !strcmp(s, ".dts"))
			cfg->output_format = "dts";
		else
			cfg->output_format = "dtb";	/* default is DTB */
	}

	if (!input_output_optional && !strcmp(cfg->output_format, "auto")) {
		fprintf(stderr, "Output required but can't deduce output format\n");
		return EXIT_FAILURE;
	}

	if (!strcmp(cfg->output_format, "dtb") ||
	    !strcmp(cfg->output_format, "dts"))
		selected_emitter = &dtb_emitter;
	else if (!strcmp(cfg->output_format, "yaml"))
		selected_emitter = &yaml_emitter;
	else
		selected_emitter = &null_emitter;

	if (!cfg->out_version)
		cfg->out_version = 17;

	if (cfg->out_version != 17) {
		fprintf(stderr, "We only support version 17 of the DTB format\n");
		return EXIT_FAILURE;
	}

	/* when selecting a dtb schema, we use the dtb checker */
	if (cfg->schema)
		selected_checker = &dtb_checker;
	else
		selected_checker = &null_checker;

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
