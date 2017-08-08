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

#define _GNU_SOURCE
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

struct frag {
	struct list_head node;
	const char *template;
	int indent;
	char *text;
};

struct var {
	const char *name;
	const char *value;
};

struct dtb_check_state {
	/* copy from config */
	const char *schema;
	const char *schema_save;
	const char *codegen;

	/* schema loading */
	struct yaml_dt_state *sdt;

	/* codegen */
	struct yaml_dt_state *cgdt;
	struct node *cgpnp_check;

	const char *input_tag;
	const char *output_tag;
	const char *compiler;
	const char *cflags;

	struct node *cg_common;	/* -> common: */
	const char *cg_common_prolog;
	const char *cg_common_epilog;
	struct node *cg_node;	/* -> node: */
	struct node *cg_node_select;
	struct node *cg_node_check;
	const char *cg_node_select_prolog;
	const char *cg_node_select_epilog;
	const char *cg_node_check_prolog;
	const char *cg_node_check_epilog;
	struct node *cg_property;	/* -> property: */
	struct node *cg_property_check;
	const char *cg_property_check_prolog;
	const char *cg_property_check_epilog;
	struct node *cg_property_check_types;
	struct node *cg_property_check_categories;
};

#define to_dtbchk(_dt) ((struct dtb_check_state *)(_dt)->checker_state)

int output_frag(struct yaml_dt_state *dt, const struct var *vars, FILE *fp,
		const char *template, int indent)
{
	const char *s, *e, *le, *var;
	char c;
	int i, varlen;
	enum {
		normal,
		escape,
		dollar,
		left_brace,
		variable,
	} state;

	s = template;
	e = s + strlen(s);

	while (s < e) {
		le = strchr(s, '\n');
		if (!le)
			le = e;
		fprintf(fp, "%*s", indent * 4, "");

		state = normal;
		var = NULL;
		while ((c = *s) && s < le) {
			switch (state) {
			case normal:
				if (c == '\\') {
					state = escape;
					break;
				}
				if (c == '$') {
					state = dollar;
					break;
				}
				fputc(c, fp);
				break;
			case escape:
				if (c == '$') {
					fputc('$', fp);
					state = normal;
					break;
				}
				fputc('\\', fp);
				fputc(c, fp);
				state = normal;
				break;
			case dollar:
				if (c != '{') {
					dt_fatal(dt, "Illegal $ escape\n");
					return -1;
				}
				state = left_brace;
				break;
			case left_brace:
				state = variable;
				var = s;
				break;
			case variable:
				if (c != '}')
					break;
				varlen = s - var;
				for (i = 0; vars && vars[i].name; i++) {
					if (strlen(vars[i].name) == varlen &&
						!memcmp(vars[i].name, var, varlen))
						break;
				}
				if (!vars || !vars[i].name) {
					char *vartmp = alloca(varlen + 1);
					memcpy(vartmp, var, varlen);
					vartmp[varlen] = '\0';
					dt_fatal(dt, "Illegal variable: %s\n", vartmp);
					return -1;
				}
				fputs(vars[i].value, fp);
				var = NULL;
				state = normal;
				break;
			}
			s++;
		}
		if (state != normal) {
			dt_fatal(dt, "Bad line state\n");
			return -1;
		}

		fputc('\n', fp);

		s = le;
		if (le < e)
			s++;
	}
	return 0;
}


static int prepare_schema_property(struct yaml_dt_state *dt,
		struct yaml_dt_state *sdt, struct node *np)
{
	fprintf(stderr, "Preparing property %s of schema node: %s\n",
			np->name, np->parent->parent->name);

	return 0;
}

static int prepare_schema_node(struct yaml_dt_state *dt,
		struct yaml_dt_state *sdt, struct node *np)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *cgdt = dtbchk->cgdt;
	struct node *npp, *npp2;
	struct property *prop;
	struct ref *ref;
	/* char namebuf[NODE_FULLNAME_MAX]; */
	const char *constraint;
	int ret, i, idx;
	struct list_head frags;
	const char *type_prolog, *type_epilog;
	const char *category_prolog, *category_epilog;
	struct node *nptype, *npcategory;
	char idxbuf[9];
	struct var vars[4];
	char *buf;
	size_t size;
	FILE *fp;
	bool first;

	fprintf(stderr, "Preparing schema node: %s\n", np->name);

	INIT_LIST_HEAD(&frags);

	/* open memstream */
	fp = open_memstream(&buf, &size);
	assert(fp);

	first = true;
	idx = 0;
	for (i = 0; (npp = dt_get_noderef(sdt, np, "selected", 0, i)) != NULL; i++) {
		constraint = dt_get_string(sdt, npp, "constraint", 0, 0);
		if (!constraint)
			continue;

		/* lookup failures are errors */
		dt_set_error_on_failed_get(cgdt, true);

		nptype = dt_get_node(cgdt, dtbchk->cg_property_check_types,
				dt_get_string(cgdt, npp, "type", 0, 0), 0);
		type_prolog = dt_get_string(cgdt, nptype, "prolog", 0, 0);
		type_epilog = dt_get_string(cgdt, nptype, "epilog", 0, 0);

		npcategory = dt_get_node(cgdt, dtbchk->cg_property_check_categories,
				dt_get_string(cgdt, npp, "category", 0, 0), 0);
		category_prolog = dt_get_string(cgdt, npcategory, "prolog", 0, 0);
		category_epilog = dt_get_string(cgdt, npcategory, "epilog", 0, 0);

		/* lookup failures are no more errors */
		dt_set_error_on_failed_get(cgdt, false);

		if (cgdt->error_flag)
			dt_fatal(cgdt, "Bad codegen configuration\n");

		/* setup the variables to expand */
		snprintf(idxbuf, sizeof(idxbuf) - 1, "%d", idx);
		idxbuf[sizeof(idxbuf) - 1] = '\0';
		vars[0].name = "NODE_NAME";
		vars[0].value = np->name;
		vars[1].name = "PROPERTY_NAME";
		vars[1].value = npp->name;
		vars[2].name = "PROPERTY_INDEX";
		vars[2].value = idxbuf;
		vars[3].name = NULL;
		vars[3].value = NULL;

		/* prolog */
		if (first) {
			first = false;
			output_frag(dt, vars, fp, dtbchk->cg_common_prolog, 0);
			output_frag(dt, vars, fp, dtbchk->cg_node_select_prolog, 0);
		}

		output_frag(dt, vars, fp, type_prolog, 1);
		output_frag(dt, vars, fp, category_prolog, 1);
		output_frag(dt, vars, fp, dtbchk->cg_property_check_prolog, 1);
		output_frag(dt, vars, fp, constraint, 2);
		output_frag(dt, vars, fp, dtbchk->cg_property_check_epilog, 1);
		output_frag(dt, vars, fp, category_epilog, 1);
		output_frag(dt, vars, fp, type_epilog, 1);

		idx++;
	}

	if (!first) {
		output_frag(dt, vars, fp, dtbchk->cg_node_select_epilog, 0);
		output_frag(dt, vars, fp, dtbchk->cg_common_epilog, 0);
	}
	fclose(fp);

	if (size) {
		fprintf(stderr, "%s\n", buf);

		/* add the source */
		prop = prop_alloc(to_tree(sdt), "selected-rule-source");
		prop->np = np;
		list_add_tail(&prop->node, &np->properties);

		ref = ref_alloc(to_tree(sdt), r_scalar, buf, size, dtbchk->input_tag);
		ref->prop = prop;
		list_add_tail(&ref->node, &prop->refs);

		dt_resolve_ref(sdt, ref);
	}

	free(buf);

	list_for_each_entry(npp, &np->children, node) {
		if (!strcmp(npp->name, "properties")) {
			list_for_each_entry(npp2, &npp->children, node) {
				ret = prepare_schema_property(dt, sdt, npp2);
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
	struct yaml_dt_state *sdt = dtbchk->sdt;
	struct node *root, *np;

	root = tree_root(to_tree(sdt));

	list_for_each_entry(np, &root->children, node)
		prepare_schema_node(dt, sdt, np);

	return 0;
}

int dtbchk_setup(struct yaml_dt_state *dt)
{
	struct dtb_check_state *dtbchk;
	struct yaml_dt_state *cgdt;
	struct node *cgroot;
	int err;

	dtbchk = malloc(sizeof(*dtbchk));
	assert(dtbchk);
	memset(dtbchk, 0, sizeof(*dtbchk));

	dtbchk->schema = dt->cfg.schema;
	dtbchk->schema_save = dt->cfg.schema_save;
	dtbchk->codegen = dt->cfg.codegen;

	dt->checker_state = dtbchk;

	if (!dtbchk->schema)
		dt_fatal(dt, "No schema file provided\n");

	if (!dtbchk->codegen)
		dt_fatal(dt, "No codegen file provided\n");

	dtbchk->sdt = dt_parse_single(dt, dtbchk->schema,
			dtbchk->schema_save, "schema");
	if (!dtbchk->sdt)
		dt_fatal(dt, "Couldn't parse schema file %s\n", dtbchk->schema);

	dtbchk->cgdt = dt_parse_single(dt, dtbchk->codegen, NULL, "codegen");
	if (!dtbchk->cgdt)
		dt_fatal(dt, "Couldn't parse codegen file %s\n", dtbchk->schema);

	cgdt = dtbchk->cgdt;
	cgroot = tree_root(to_tree(cgdt));

	/* lookup failures are errors */
	dt_set_error_on_failed_get(cgdt, true);

	dtbchk->input_tag = dt_get_string(cgdt, cgroot, "input-tag", 0, 0);
	dtbchk->output_tag = dt_get_string(cgdt, cgroot, "output-tag", 0, 0);
	dtbchk->compiler = dt_get_string(cgdt, cgroot, "compiler", 0, 0);
	dtbchk->cflags = dt_get_string(cgdt, cgroot, "cflags", 0, 0);

	dtbchk->cg_common = dt_get_node(cgdt, cgroot, "common", 0);
	dtbchk->cg_common_prolog = dt_get_string(cgdt, dtbchk->cg_common, "prolog", 0, 0);
	dtbchk->cg_common_epilog = dt_get_string(cgdt, dtbchk->cg_common, "epilog", 0, 0);

	dtbchk->cg_node = dt_get_node(cgdt, cgroot, "node", 0);
	dtbchk->cg_node_select = dt_get_node(cgdt, dtbchk->cg_node, "select", 0);
	dtbchk->cg_node_check = dt_get_node(cgdt, dtbchk->cg_node, "check", 0);
	dtbchk->cg_node_select_prolog = dt_get_string(cgdt, dtbchk->cg_node_select, "prolog", 0, 0);
	dtbchk->cg_node_select_epilog = dt_get_string(cgdt, dtbchk->cg_node_select, "epilog", 0, 0);
	dtbchk->cg_node_check_prolog = dt_get_string(cgdt, dtbchk->cg_node_check, "prolog", 0, 0);
	dtbchk->cg_node_check_epilog = dt_get_string(cgdt, dtbchk->cg_node_check, "epilog", 0, 0);

	dtbchk->cg_property = dt_get_node(cgdt, cgroot, "property", 0);
	dtbchk->cg_property_check = dt_get_node(cgdt, dtbchk->cg_property, "check", 0);
	dtbchk->cg_property_check_prolog = dt_get_string(cgdt, dtbchk->cg_property_check, "prolog", 0, 0);
	dtbchk->cg_property_check_epilog = dt_get_string(cgdt, dtbchk->cg_property_check, "epilog", 0, 0);

	dtbchk->cg_property_check_types = dt_get_node(cgdt, dtbchk->cg_property_check, "types", 0);
	dtbchk->cg_property_check_categories = dt_get_node(cgdt, dtbchk->cg_property_check, "categories", 0);

	if (cgdt->error_flag)
		dt_fatal(cgdt, "Could not find codegen data\n");

	dt_set_error_on_failed_get(cgdt, false);

	err = prepare_schema(dt);
	if (err)
		dt_fatal(dt, "Failed to prepare schema\n");

	if (dtbchk->schema_save)
		dt_emitter_emit(dtbchk->sdt);

	dt_debug(dt, "DTB checker configuration:\n");
	dt_debug(dt, " schema      = %s\n", dtbchk->schema);
	dt_debug(dt, " schema-save = %s\n", dtbchk->schema_save ? : "<NONE>");
	dt_debug(dt, " codegen     = %s\n", dtbchk->codegen ? : "<NONE>");
	dt_debug(dt, "-----------------\n");
	dt_debug(dt, " input-tag   = %s\n", dtbchk->input_tag);
	dt_debug(dt, " output-tag  = %s\n", dtbchk->output_tag);
	dt_debug(dt, " compiler    = %s\n", dtbchk->compiler);
	dt_debug(dt, " cflags      = %s\n", dtbchk->cflags);

	return 0;
}

void dtbchk_cleanup(struct yaml_dt_state *dt)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);

	/* the children parsers are automatically cleaned */
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
	struct yaml_dt_state *sdt = dtbchk->sdt;
	struct node *snp, *sroot = tree_root(to_tree(sdt));
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
