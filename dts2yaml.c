/*
 * dts2yaml.c - Convert DTC to YAML filter
 *
 * Converts DTC to YAML
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
#include <assert.h>

#define _GNU_SOURCE
#include <getopt.h>

#include "syexpr.h"
#include "utils.h"
#include "list.h"

#include "dtsparser.h"

struct d2y_state {
	bool debug;
	bool silent;
	int color;
	int shift;
	const char *filename;
	const char *outfilename;
	FILE *fp;
	FILE *outfp;
	struct dts_state ds;
};

#define to_d2y(_ds)	container_of(_ds, struct d2y_state, ds)
#define to_ds(_d2y)	(&(_d2y)->ds)

static struct option opts[] = {
	{ "output", 	required_argument, 0, 'o' },
	{ "tabs",	required_argument, 0, 't' },
	{ "shift",	required_argument, 0, 's' },
	{ "color",	required_argument, 0,  0  },
	{ "silent",	no_argument, 0, 0  },
	{ "help",	no_argument, 0, 'h' },
	{ "debug",	no_argument, 0, 'd' },
	{0, 0, 0, 0}
};

static void help(void)
{
	printf("dts2yaml [options] [input-file]\n"
		" options are:\n"
		"   -o, --output        Output file\n"
		"   -t, --tabs		Set tab size (default 8)\n"
		"   -s, --shift		Shift when outputing YAML (default 2)\n"
		"   -d, --debug		Enable debug messages\n"
		"       --silent        Be really silent\n"
		"       --color         [auto|off|on]\n"
		"   -h, --help		Help\n"
		"       --color         [auto|off|on]\n"
		);
}

static void d2y_debug(struct dts_state *ds, const char *fmt, ...)
		__attribute__ ((__format__ (__printf__, 2, 0)));

static void d2y_message(struct dts_state *ds, enum dts_message_type type,
		const struct dts_location *loc, const char *fmt, ...)
		__attribute__ ((__format__ (__printf__, 4, 0)));

static void d2y_debug(struct dts_state *ds, const char *fmt, ...)
{
	struct d2y_state *d2y = to_d2y(ds);
	va_list ap;

	va_start(ap, fmt);
	if (d2y->debug && !d2y->silent)
		vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void d2y_message(struct dts_state *ds, enum dts_message_type type,
		const struct dts_location *loc, const char *fmt, ...)
{
	struct d2y_state *d2y = to_d2y(ds);
	va_list ap;
	const char *emph = "", *reset = "";
	const char *kind, *kindemph;
	const char *filename;
	int line, col, tline, tcol;

	if (d2y->silent || (!d2y->debug && type == dmt_info))
		return;

	if ((d2y->color == -1 && isatty(STDERR_FILENO)) ||
	     d2y->color == 1) {
		emph = WHITE;
		reset = RESET;
	}

	switch (type) {
	case dmt_info:
		kind = "";
		kindemph = "";
		break;
	case dmt_warning:
		kind = "warning: ";
		kindemph = MAGENTA;
		break;
	case dmt_error:
		kind = "error: ";
		kindemph = RED;
		break;
	}

	if (!loc) {
		filename = dts_get_filename(ds);
		line = dts_get_line(ds);
		col = dts_get_column(ds);
		tline = dts_get_token_line(ds);
		tcol = dts_get_token_column(ds);
	} else {
		filename = loc->filename;
		line = loc->start_line;
		col = loc->start_col;
		tline = loc->end_line;
		tcol = loc->end_col;
	}

	(void)tline;
	(void)tcol;

	fprintf(stderr, "%s%s:%d:%d: %s%s%s",
			emph, filename, line, col,
			kindemph, kind, emph);

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "%s", reset);
}

static int d2y_emit_bits(struct d2y_state *d2y,
		const struct dts_property_item *pi,
		const struct dts_emit_item *ei)
{
	int bits;

	if (!pi->bits) {
		/* for unadorned items that are bytes */
		if (ei->atom == dea_byte)
			fprintf(d2y->outfp, "!int8 ");
		return 0;
	}

	bits = atoi(pi->bits->contents);
	switch (bits) {
	case 8:
	case 16:
	case 32:
	case 64:
		fprintf(d2y->outfp, "!int%d ", bits);
		break;
	default:
		/* should be caught by the parser, but never hurts */
		return -1;
	}
	return 0;
}

static int d2y_emit_single_scalar(struct d2y_state *d2y,
		const struct dts_property_item *pi,
		const struct dts_emit_item *ei)
{
	struct dts_state *ds = to_ds(d2y);
	const char *s;

	switch (ei->atom) {
	default:
		dts_error_at(ds, &ei->loc, "bad scalar item\n");
		return -1;
	case dea_int:
		fprintf(d2y->outfp, "%s", ei->contents);
		break;
	case dea_char:
		fprintf(d2y->outfp, "'%s'", ei->contents);
		break;
	case dea_expr:
		fprintf(d2y->outfp, "%s", ei->contents);
		break;
	case dea_byte:
		fprintf(d2y->outfp, "0x%s", ei->contents);
		break;
	case dea_string:
		fprintf(d2y->outfp, "\"%s\"", ei->contents);
		break;
	case dea_stringref:
		fprintf(d2y->outfp, "!pathref %s", ei->contents);
		break;
	case dea_ref:
		fprintf(d2y->outfp, "*%s", ei->contents);
		break;
	case dea_pathref:
		/* TODO record and label node that it refers */
		fprintf(d2y->outfp, "*");
		s = ei->contents;
		while (*s) {
			fprintf(d2y->outfp, "%c", ispunct(*s) ? '_' : *s);
			s++;
		}
		break;
	}

	return 0;
}

static void d2y_emit_comment_line(struct d2y_state *d2y,
		int depth, const char *line, int count)
{
	/* those must be escaped */
	static const char *preproc_commands[] = {
		"if",
		"ifdef",
		"ifndef",
		"else",
		"elif",
		"endif",
		"define",
		"include",
		NULL,
	};
	const char *s;
	const char **ss;
	int len;

	fprintf(d2y->outfp, "%*s", depth * d2y->shift, "");
	fprintf(d2y->outfp, "#");
	if (!isspace(*line))
		fprintf(d2y->outfp, " ");
	while (isspace(*line)) {
		fputc(' ', d2y->outfp);
		line++;
		count--;
	}
	if (count > 0) {
		ss = preproc_commands;
		while ((s = *ss++)) {
			len = strlen(s);
			if (count >= len && !memcmp(line, s, len) &&
				isspace(line[len])) {
				fputc('_', d2y->outfp);
				break;
			}
		}
		fwrite(line, count, 1, d2y->outfp);
	}
	fprintf(d2y->outfp, "\n");
}

static void d2y_emit_top_level_comment(struct d2y_state *d2y, int depth,
		const char *comment)
{
	const char *s, *e, *el, *sn;
	int lines;
	char c;

	/* comment should be a C or C++ style comment */
	s = comment;
	if (strlen(s) <= 2 || *s++ != '/')
		return;

	c = *s++;
	if (c != '/' && c != '*')
		return;

	/* C++ style comment; easy */
	if (c == '/') {
		while (isspace(*s))
			s++;
		d2y_emit_comment_line(d2y, depth, s, strlen(s));
		return;
	}

	/* C comments are trickier */

	/* trim end of comment */
	e = s + strlen(s);
	if (s > e - 2)
		return;
	if (strcmp(e - 2, "*/"))
		return;
	e -= 2;

	lines = 0;
	while (s < e) {
		el = strchr(s, '\n');
		if (!el) {
			el = e;
			sn = e;
			lines++;
		} else
			sn = el + 1;

		if (isspace(*s)) {
			while (isspace(*s))
				s++;
		}
		
		if (*s == '*') {
			while (*s == '*')
				s++;
		}
		if (s < el - 1) {
			if (isspace(el[-1])) {
				while (s < el - 1 && isspace(el[-1]))
					el--;
			} else if (el[-1] == '*') {
				while (s < el - 1 && el[-1] == '*')
					el--;
			}
		}

		d2y_emit_comment_line(d2y, depth, s, el - s);

		s = sn;
	}
}

static void d2y_emit_preproc(struct d2y_state *d2y, const char *preproc)
{
	const char *s, *e;
	char *cmd, *filename, *ext;
	char ileft, iright;

	s = preproc;
	if (*s++ != '#')
		return;
	while (isspace(*s))
		s++;
	e = s;
	while (!isspace(*e))
		e++;
	cmd = alloca(e + 1 - s);
	memcpy(cmd, s, e - s);
	cmd[e - s] = '\0';

	s = e;
	while (isspace(*s))
		s++;

	/* look into includes and try to convert them */
	if (!strcmp(cmd, "include")) {
		e = NULL;
		if (*s == '"') {
			e = strchr(s + 1, '"');
			ileft = '"';
			iright = '"';
		} else if (*s == '<') {
			e = strchr(s + 1, '>');
			ileft = '<';
			iright = '>';
		}
		if (!e)
			return;
		filename = alloca(e - (s + 1) + 1);
		memcpy(filename, s + 1, e - (s + 1));
		filename[e - (s + 1)] = '\0';

		ext = strrchr(filename, '.');
		if (ext) {
			if (!strcmp(ext, ".dts")) {
				*ext = '\0';
				ext = ".yaml";
			} else if (!strcmp(ext, ".dtsi")) {
				*ext = '\0';
				ext = ".yamli";
			} else
				ext = "";
		} else
			ext = "";

		fprintf(d2y->outfp, "#include %c%s%s%c\n",
				ileft, filename, ext, iright);
	} else
		fprintf(d2y->outfp, "%s\n", preproc);
}

static int d2y_emit(struct dts_state *ds, int depth,
		enum dts_emit_type type, const struct dts_emit_data *data)
{
	struct d2y_state *d2y = to_d2y(ds);
	const struct dts_property_item *pi;
	const struct dts_emit_item *ei;
	bool is_root;
	int i, j, k, len;
	char *filename, *ext;

	switch (type) {
	case det_separator:
		fprintf(d2y->outfp, "\n");
		break;
	case det_comment:
		d2y_emit_top_level_comment(d2y, depth, data->comment->contents);
		break;
	case det_preproc:
		d2y_emit_preproc(d2y, data->preproc->contents);
		break;
	case det_del_node:
		switch (data->del_node->atom) {
		case dea_name:
			fprintf(d2y->outfp, "%*s", depth * d2y->shift, "");
			fprintf(d2y->outfp, "%s: ~\n", data->del_node->contents);
			break;
		case dea_ref:
		case dea_pathref:
			if (depth > 0)
				break;
			fprintf(d2y->outfp, "%s%s: ~\n",
					data->del_node->atom == dea_ref ? '*': "",
					data->del_node->contents);
			break;
		default:
			break;
		}
		break;
	case det_del_prop:
		/* only handle delete names */
		if (data->del_node->atom == dea_name) {
			fprintf(d2y->outfp, "%*s", depth * d2y->shift, "");
			fprintf(d2y->outfp, "%s", data->del_prop->contents);
			fprintf(d2y->outfp, ": ~\n");
		}
		break;
	case det_include:
		len = strlen(data->include->contents);
		filename = alloca(len + 1);
		strcpy(filename, data->include->contents);

		ext = strrchr(filename, '.');
		if (ext) {
			if (!strcmp(ext, ".dts")) {
				*ext = '\0';
				ext = ".yaml";
			} else if (!strcmp(ext, ".dtsi")) {
				*ext = '\0';
				ext = ".yamli";
			} else
				ext = "";
		} else
			ext = "";

		/* convert DTS include to standard CPP include */
		fprintf(d2y->outfp, "#include \"%s%s\"\n",
				filename, ext);
		break;
	case det_memreserve:
		fprintf(d2y->outfp, "/memreserve/: [ %s, %s ]\n",
			data->memreserves[0]->contents,
			data->memreserves[1]->contents);
		break;
	case det_node:
		is_root = data->pn.name->atom == dea_name &&
			  !strcmp(data->pn.name->contents, "/");
		if (is_root)	/* do not output anything for root */
			break;
		fprintf(d2y->outfp, "%*s", depth * d2y->shift, "");
		if (data->pn.name->atom == dea_ref)
			fprintf(d2y->outfp, "*");

		/* both name && pathref get printed out */
		fprintf(d2y->outfp, "%s", data->pn.name->contents);

		fprintf(d2y->outfp, ":");
		if (data->pn.label)
			fprintf(d2y->outfp, " &%s", data->pn.label->contents);
		fprintf(d2y->outfp, "\n");
		break;
	case det_node_empty:
		fprintf(d2y->outfp, "%*s", (depth + 1) * d2y->shift, "");
		fprintf(d2y->outfp, "~: ~\n");
		break;
	case det_property:
		fprintf(d2y->outfp, "%*s", depth * d2y->shift, "");
		if (!strchr(data->pn.name->contents, '#'))
			fprintf(d2y->outfp, "%s", data->pn.name->contents);
		else
			fprintf(d2y->outfp, "\"%s\"", data->pn.name->contents);
		fprintf(d2y->outfp, ": ");
		if (!data->pn.nr_items) {
			/* single (true) boolean value */
			fprintf(d2y->outfp, "true\n");
			break;
		}

		if (data->pn.nr_items > 1)
			fprintf(d2y->outfp, "[ ");

		for (k = 0; k < data->pn.nr_items; k++) {
			pi = data->pn.items[k];
			ei = data->pn.items[k]->elems[0];
			j = data->pn.items[k]->nr_elems;

			d2y_emit_bits(d2y, pi, ei);
			if (j > 1)
				fprintf(d2y->outfp, "[ ");
			for (i = 0; i < j; i++) {
				ei = pi->elems[i];
				d2y_emit_single_scalar(d2y, pi, ei);
				if ((i + 1) < j)
					fprintf(d2y->outfp, ", ");
			}
			if (j > 1)
				fprintf(d2y->outfp, " ]");

			if ((k + 1) < data->pn.nr_items)
				fprintf(d2y->outfp, ", ");
		}

		if (data->pn.nr_items > 1)
			fprintf(d2y->outfp, " ]");

		fprintf(d2y->outfp, "\n");
		break;
	default:
		break;
	}

	return 0;
}

static const struct dts_ops d2y_ops = {
	.debugf		= d2y_debug,
	.messagef	= d2y_message,
	.emit		= d2y_emit,
};

int main(int argc, char *argv[])
{
	int cc, c, option_index = 0, ret;
	const char *s;
	const char *filename = NULL;
	const char *outfilename = NULL;
	bool debug = false;
	bool silent = false;
	int tabs = 8;
	int shift = 2;
	int color = -1;
	struct d2y_state d2y_state, *d2y = &d2y_state;
	struct dts_state *ds = to_ds(d2y);

	while ((cc = getopt_long(argc, argv,
			"o:t:s:hd?", opts, &option_index)) != -1) {

		if (cc == 0 && option_index >= 0) {
			s = opts[option_index].name;
			if (!s)
				continue;
			if (!strcmp(s, "silent")) {
				silent = true;
				continue;
			}
			if (!strcmp(s, "color")) {
				if (!strcmp(optarg, "auto"))
					color = -1;
				else if (!strcmp(optarg, "on"))
					color = 1;
				else
					color = 0;
			}
			continue;
		}

		switch (cc) {
		case 'o':
			outfilename = optarg;
			break;
		case 's':
			shift = atoi(optarg);
			if (shift <= 0) {
				fprintf(stderr, "illegal shift value %d\n", tabs);
				return EXIT_FAILURE;
			}
			break;
		case 't':
			tabs = atoi(optarg);
			if (tabs <= 0) {
				fprintf(stderr, "illegal tab value %d\n", tabs);
				return EXIT_FAILURE;
			}
			break;
		case 'd':
			debug = true;
			break;
		case 'h':
		case '?':
			help();
			return 0;
		}
	}

	if (optind < argc)
		filename = argv[optind];
	else
		filename = NULL;

	if (!filename || (!strcmp(filename, "<stdin>") ||
			 !strcmp(filename, "-")))
		filename = "<stdin>";

	if (!outfilename || (!strcmp(outfilename, "<stdout>") ||
			    !strcmp(outfilename, "-")))
		outfilename = "<stdout>";

	memset(d2y, 0, sizeof(*d2y));
	d2y->filename = filename;
	d2y->outfilename = outfilename;
	d2y->debug = debug;
	d2y->color = color;
	d2y->silent = silent;
	d2y->shift = shift;

	ret = dts_setup(ds, filename, tabs, &d2y_ops);
	if (ret) {
		fprintf(stderr, "Failed to setup dts parser on %s\n",
				filename);
		return EXIT_FAILURE;
	}

	if (d2y->filename && strcmp(d2y->filename, "<stdin>")) {
		dts_debug(ds, "opening %s for DTS parsing\n", d2y->filename);
		d2y->fp = fopen(d2y->filename, "ra");
		if (!d2y->fp) {
			ret = -1;
			dts_error(ds, "Can't open %s\n", d2y->filename);
			goto out_err;
		}
	} else
		d2y->fp = stdin;

	dts_debug(ds, "opened %s for DTS parsing\n", d2y->filename);

	if (d2y->outfilename && strcmp(d2y->outfilename, "<stdout>")) {
		dts_debug(ds, "opening %s for YAML output\n", d2y->outfilename);
		d2y->outfp = fopen(d2y->outfilename, "wa");
		if (!d2y->outfp) {
			ret = -1;
			dts_error(ds, "Can't open %s\n", d2y->outfilename);
			goto out_err;
		}
	} else
		d2y->outfp = stdout;

	ret = 0;
	while ((c = getc(d2y->fp)) != EOF) {
		ret = dts_feed(ds, c);
		if (ret < 0) 
			break;
	}

	dts_debug(ds, "EOF on %s\n", d2y->filename);

	fclose(d2y->outfp);
	fclose(d2y->fp);
out_err:
	dts_cleanup(ds);

	return ret ? EXIT_FAILURE : 0;
}
