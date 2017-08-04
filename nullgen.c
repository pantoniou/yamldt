/*
 * nullgen.c - NULL sink generation
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
#include <time.h>
#include <stdbool.h>
#include <assert.h>
#include <alloca.h>
#include <limits.h>

#include "utils.h"
#include "syexpr.h"
#include "base64.h"

#include "yamldt.h"

static struct ref *null_ref_alloc(struct tree *t, enum ref_type type,
				 const void *data, int len, const char *xtag)
{
	return yaml_dt_ref_alloc(t, type, data, len, xtag,
			sizeof(struct dt_ref));
}

static void null_ref_free(struct tree *t, struct ref *ref)
{
	yaml_dt_ref_free(t, ref);
}

static struct property *null_prop_alloc(struct tree *t, const char *name)
{
	return yaml_dt_prop_alloc(t, name, sizeof(struct dt_property));
}

static void null_prop_free(struct tree *t, struct property *prop)
{
	yaml_dt_prop_free(t, prop);
}

static struct label *null_label_alloc(struct tree *t, const char *name)
{
	return yaml_dt_label_alloc(t, name, sizeof(struct dt_label));
}

static void null_label_free(struct tree *t, struct label *l)
{
	yaml_dt_label_free(t, l);
}

static struct node *null_node_alloc(struct tree *t, const char *name,
				   const char *label)
{
	return yaml_dt_node_alloc(t, name, label, sizeof(struct dt_node));
}

static void null_node_free(struct tree *t, struct node *np)
{
	yaml_dt_node_free(t, np);
}

static const struct tree_ops null_tree_ops = {
	.ref_alloc	= null_ref_alloc,
	.ref_free	= null_ref_free,
	.prop_alloc	= null_prop_alloc,
	.prop_free	= null_prop_free,
	.label_alloc	= null_label_alloc,
	.label_free	= null_label_free,
	.node_alloc	= null_node_alloc,
	.node_free	= null_node_free,
	.debugf		= yaml_dt_tree_debugf,
};

int null_setup(struct yaml_dt_state *dt)
{
	tree_init(to_tree(dt), &null_tree_ops);
	return 0;
}

void null_cleanup(struct yaml_dt_state *dt)
{
	tree_cleanup(to_tree(dt));
}

int null_emit(struct yaml_dt_state *dt)
{
	return 0;
}

static struct option opts[] = {
	{ "null",	 no_argument, 0, 'n' },
	{0, 0, 0, 0}
};

static bool null_select(int argc, char **argv)
{
	int cc, option_index = -1;

	optind = 0;
	opterr = 0;	/* do not print error for invalid option */
	while ((cc = getopt_long(argc, argv,
			"n", opts, &option_index)) != -1) {
		/* explicit null mode select */
		if (cc == 'n')
			return true;
	}

	return false;
}

static int null_parseopts(int *argcp, char **argv, int *optindp,
			  const struct yaml_dt_config *cfg, void **ecfg)
{
	int cc, option_index = -1;

	/* get and consume non common options */
	option_index = -1;
	*optindp = 0;
	opterr = 1;	/* do print error for invalid option */
	while ((cc = getopt_long(*argcp, argv,
			"n", opts, &option_index)) != -1) {

		switch (cc) {
		case 'n':
			/* nothing to do for this */
			break;
		case '?':
			/* invalid option */
			return -1;
		}

		long_opt_consume(argcp, argv, opts, optindp, optarg, cc,
				 option_index);
	}

	return 0;
}

static const struct yaml_dt_emitter_ops null_emitter_ops = {
	.select		= null_select,
	.parseopts	= null_parseopts,
	.setup		= null_setup,
	.cleanup	= null_cleanup,
	.emit		= null_emit,
};

static const char *null_suffixes[] = {
	NULL
};

struct yaml_dt_emitter null_emitter = {
	.name		= "null",
	.tops		= &null_tree_ops,

	.usage_banner	= 
"   -n, --null          Generate no output\n",

	.suffixes	= null_suffixes,
	.eops		= &null_emitter_ops,
};
