/*
 * intexpr.c - Test integer expression parser
 *
 * Tester of the C integer expression evaluator
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

#define _GNU_SOURCE
#include <getopt.h>

#include "syexpr.h"
#include "utils.h"

static struct option opts[] = {
	{ "help",	no_argument, 0, 'h' },
	{ "debug",	no_argument, 0, 'd' },
	{0, 0, 0, 0}
};

static void help(void)
{
	printf("intexpr [options] <expression>\n"
		" options are:\n"
		"   -d, --debug		Enable debug messages\n"
		"   -h, --help		Help\n"
		);
}

#ifdef SY_DEBUG
static void debugf(void *arg, const char *fmt, ...)
		__attribute__ ((__format__ (__printf__, 2, 0)));

static void debugf(void *arg, const char *fmt, ...)
{
	FILE *f = arg;
	va_list ap;

	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
}
#endif

int main(int argc, char *argv[])
{
	int i, cc, option_index = 0;
	sy_val_t val;
	char *buf, *s;
	int ret, len;
	struct sy_state state, *sy = &state;
	struct sy_config cfg;
	char vstr[SY_VAL_STR_LEN_MAX];
	int errpos;
	const char *errmsg;
	bool debug;

	debug = false;
	while ((cc = getopt_long(argc, argv,
			"hd?", opts, &option_index)) != -1) {
		switch (cc) {
		case 'd':
			debug = true;
			break;
		case 'h':
		case '?':
			help();
			return 0;
		}
	}

	len = 0;
	for (i = optind; i < argc; i++)
		len += strlen(argv[i]) + 1 + 1;

	buf = malloc(len);
	if (buf == NULL) {
		fprintf(stderr, "Unable to allocate %d bytes\n", len);
		return EXIT_FAILURE;
	}

	s = buf;
	for (i = optind; i < argc; i++) {
		strcpy(s, argv[i]);
		s += strlen(argv[i]);
		if (i + 1 < argc)
			*s++ = ' ';
	}
	*s++ = '\0';

	memset(&cfg, 0, sizeof(cfg));
	cfg.size = sy_workbuf_size_max(strlen(buf));
	cfg.workbuf = malloc(cfg.size);
	if (!cfg.workbuf) {
		fprintf(stderr, "Unable to allocate %u bytes\n", cfg.size);
		return EXIT_FAILURE;
	}
#ifdef SY_DEBUG
	if (debug) {
		cfg.debugf = debugf;
		cfg.debugarg = stderr;
	}
#else
	(void)debug;	/* avoid warning */
#endif
	sy_init(sy, &cfg);

	ret = sy_eval(sy, buf, -1, &val);
	if (ret == 0) {
		printf("%s\n", sy_val_str(&val, vstr, sizeof(vstr)));
	} else {
		ret = sy_get_error(sy, &errpos, &errmsg);
		fprintf(stderr, "Error %d @%d : %s\n", ret, errpos, errmsg);
		fprintf(stderr, "%s\n", buf);
		fprintf(stderr, "%*s^\n", errpos, "");
	}

	free(cfg.workbuf);
	free(buf);

	return 0;
}
