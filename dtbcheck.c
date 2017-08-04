/*
 * dtbcheck.c - DTB checker
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

#include "nullgen.h"
#include "nullcheck.h"

#include "dtbcheck.h"
#include "yamlgen.h"

#define DEFAULT_COMPILER "clang-5.0"
#define DEFAULT_CFLAGS "-x c -target bpf -O2 -c -o - -"

struct dtb_check_state {
	/* copy from config */
	const char *schema;
	const char *schema_save;
	/* schema loading */
	struct yaml_dt_config cfg;
	struct yaml_dt_state dt;
};

#define to_dtbchk(_dt) ((struct dtb_check_state *)(_dt)->checker_state)

struct property *get_first_named_property(struct node *np, const char *name)
{
	struct property *prop;

	list_for_each_entry(prop, &np->properties, node)
		if (!strcmp(name, prop->name))
			return prop;
	return NULL;
}

struct ref *get_ref_at(struct property *prop, int idx)
{
	struct ref *ref;

	list_for_each_entry(ref, &prop->refs, node) {
		if (idx-- == 0)
			return ref;
	}
	return NULL;
}

struct ref *get_first_named_property_ref_at(struct node *np, const char *name, int idx)
{
	struct property *prop;

	prop = get_first_named_property(np, name);
	if (!prop)
		return NULL;

	return get_ref_at(prop, idx);
}

struct ref *get_first_named_property_ref_at_with_tag(struct node *np, const char *name, int idx, const char *tag)
{
	struct property *prop;
	struct ref *ref;

	prop = get_first_named_property(np, name);
	if (!prop)
		return NULL;

	ref = get_ref_at(prop, idx);
	if (!ref)
		return NULL;
	if (ref->xtag && strcmp(ref->xtag, tag))
		return NULL;
	return ref;
}

bool ref_str_eq(struct ref *ref, const char *str)
{
	if (ref->xtag && strcmp(ref->xtag, "!str"))
		return false;
	if (strlen(str) != ref->len)
		return false;
	return strlen(str) == ref->len && !memcmp(ref->data, str, ref->len);
}

#if 0
bool ref_int_eq(struct ref *ref, long long val)
{
	if (ref->xtag && strcmp(ref->xtag, "!int"))
		return false;
	return strlen(str) == ref->len && !memcpy(ref->data, str, ref->len);
}
#endif

static int prepare_schema_property(struct yaml_dt_state *dt,
		struct yaml_dt_state *cdt, struct node *np)
{
	struct ref *type, *category, *constraint;

	fprintf(stderr, "Preparing property %s of schema node: %s\n",
			np->name, np->parent->parent->name);

	type = get_first_named_property_ref_at(np, "type", 0);
	category = get_first_named_property_ref_at(np, "category", 0);
	constraint = get_first_named_property_ref_at(np, "constraint", 0);

	(void)constraint;

	if (!type || !category) {
		tree_error_at_node(to_tree(cdt), np,
				"Missing schema properties\n");
		return -1;
	}

	return 0;
}

static int prepare_schema_node(struct yaml_dt_state *dt,
		struct yaml_dt_state *cdt, struct node *np)
{
	struct node *npp, *npp2;
	int ret;

	fprintf(stderr, "Preparing schema node: %s\n", np->name);

	list_for_each_entry(npp, &np->children, node) {
		if (!strcmp(npp->name, "properties")) {
			list_for_each_entry(npp2, &npp->children, node) {
				ret = prepare_schema_property(dt, cdt, npp2);
				if (ret)
					return ret;
			}
		}
	}

	return ret;
}

static int prepare_schema(struct yaml_dt_state *dt)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *cdt = &dtbchk->dt;	
	struct node *root, *np;

	root = tree_root(to_tree(cdt));

	list_for_each_entry(np, &root->children, node)
		prepare_schema_node(dt, cdt, np);

	return 0;
}

int dtbchk_setup(struct yaml_dt_state *dt)
{
	struct dtb_check_state *dtbchk;
	struct yaml_dt_state *cdt;
	struct yaml_dt_config *ccfg;
	char *argv[2];
	FILE *fp;
	int err;

	dtbchk = malloc(sizeof(*dtbchk));
	assert(dtbchk);
	memset(dtbchk, 0, sizeof(*dtbchk));

	dtbchk->schema = dt->cfg.schema;
	dtbchk->schema_save = dt->cfg.schema_save;

	dt->checker_state = dtbchk;

	dt_debug(dt, "DTB checker configuration:\n");
	dt_debug(dt, " schema     = %s\n", dtbchk->schema);
	dt_debug(dt, " schema-save= %s\n", dtbchk->schema_save ? : "<NONE>");

	fprintf(stderr, "parsing schema file...\n");
	cdt = &dtbchk->dt;	
	ccfg = &dtbchk->cfg;	
	ccfg->debug = dt->cfg.debug;
	ccfg->output_file = "/dev/null";

	argv[0] = (char *)dtbchk->schema;
	argv[1] = NULL;
	ccfg->input_file = argv;
	ccfg->input_file_count = 1;

	err = dt_setup(cdt, ccfg, &null_emitter, &null_checker);
	if (err)
		dt_fatal(dt, "Unable to setup schema parser\n");

	dt_parse(cdt);

	err = prepare_schema(dt);
	if (err)
		dt_fatal(dt, "Failed to prepare schema\n");

	if (dtbchk->schema_save) {
		fp = fopen(dtbchk->schema_save, "wa");
		if (!fp)
			dt_fatal(dt, "Failed to open schema intermediate file %s\n",
					dtbchk->schema_save);
		yaml_flatten_node(to_tree(cdt), fp, false, NULL, NULL, NULL, NULL);

		fclose(fp);
	}

	if (cdt->error_flag)
		dt_fatal(dt, "Unable to parse schema\n");

	return 0;
}

void dtbchk_cleanup(struct yaml_dt_state *dt)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *cdt;

	/* cleanup schema */
	cdt = &dtbchk->dt;	
	dt_cleanup(cdt, cdt->error_flag);

	memset(dtbchk, 0, sizeof(*dtbchk));
	free(dtbchk);
}

static void check_single_rule(struct yaml_dt_state *dt,
		struct node *np, struct node *snp)
{
#if 0
	char namebuf[NODE_FULLNAME_MAX];
	fprintf(stderr, "%s: against %s\n",
			dn_fullname(np, namebuf, sizeof(namebuf)),
			snp->name ? : "/");
#endif
}

static void check_node(struct yaml_dt_state *dt,
		       struct node *np)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *cdt = &dtbchk->dt;
	struct node *snp, *sroot = tree_root(to_tree(cdt));
	struct node *child;

	/* check each rule in the root */
	list_for_each_entry(snp, &sroot->children, node)
		check_single_rule(dt, np, snp);

	list_for_each_entry(child, &np->children, node)
		check_node(dt, child);
}

int dtbchk_check(struct yaml_dt_state *dt)
{
	fprintf(stderr, "CHECK NOW\n");
	check_node(dt, tree_root(to_tree(dt)));
	return 0;
}

static bool dtbchk_select(int argc, char **argv)
{
	int i;

	/* explicit dtbchk mode select */
	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-' && argv[i][1] == 'S')
			return true;
	}
	return false;
}

static const struct yaml_dt_checker_ops dtb_checker_ops = {
	.select		= dtbchk_select,
	.setup		= dtbchk_setup,
	.cleanup	= dtbchk_cleanup,
	.check		= dtbchk_check,
};

struct yaml_dt_checker dtb_checker = {
	.name		= "dtbchk",
	.cops		= &dtb_checker_ops,
};
