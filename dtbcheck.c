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

#include "dt.h"

#include "nullgen.h"
#include "nullcheck.h"

#include "dtbcheck.h"
#include "yamlgen.h"

#ifdef CAN_RUN_EBPF
#include "ebpf.h"
#include "ebpf_dt.h"
#endif

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

enum constraint_type {
	t_select,
	t_check
};

struct constraint_desc {
	struct list_head node;
	enum constraint_type type;
	int idx;		/* index in the code gen */
	struct node *np;	/* schema node */
	struct node *npp;	/* schema property node (that has the constraint) */
};

struct dtb_check_state {
	/* copy from config */
	const char *schema;
	const char *schema_save;
	const char *codegen;
	bool save_temps;

	/* schema loading */
	struct yaml_dt_state *sdt;

	/* codegen */
	struct yaml_dt_state *cgdt;
	struct node *cgpnp_check;

	const char *input_tag;
	const char *input_ext;
	const char *output_tag;
	const char *output_ext;
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

	/* constraint list to map from error codes */
	struct list_head clist;
};

#define to_dtbchk(_dt) ((struct dtb_check_state *)(_dt)->checker_state)

int output_frag(struct yaml_dt_state *dt, const struct var *vars, FILE *fp,
		const char *template, int indent)
{
	const char *s, *e, *le, *var;
	char c;
	int i, varlen;
	char *vartmp;
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
					vartmp = alloca(varlen + 1);
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

static int append_constraint(struct yaml_dt_state *dt,
			     struct yaml_dt_state *sdt,
			     struct node *node_np,
			     struct node *property_np,
			     FILE *fp, const char *constraint,
			     const struct var *vars,
			     enum constraint_type type,
			     int idx)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *cgdt = dtbchk->cgdt;
	const char *type_prolog, *type_epilog;
	const char *category_prolog, *category_epilog;
	struct node *nptype, *npcategory;
	const char *prolog;

	switch (type) {
	case t_select:
		prolog = dtbchk->cg_node_select_prolog;
		break;
	case t_check:
		prolog = dtbchk->cg_node_check_prolog;
		break;
	default:
		return -1;
	}

	/* lookup failures are errors */
	dt_set_error_on_failed_get(cgdt, true);

	nptype = dt_get_node(cgdt, dtbchk->cg_property_check_types,
			dt_get_string(cgdt, property_np, "type", 0, 0), 0);
	type_prolog = dt_get_string(cgdt, nptype, "prolog", 0, 0);
	type_epilog = dt_get_string(cgdt, nptype, "epilog", 0, 0);

	npcategory = dt_get_node(cgdt, dtbchk->cg_property_check_categories,
			dt_get_string(cgdt, property_np, "category", 0, 0), 0);
	category_prolog = dt_get_string(cgdt, npcategory, "prolog", 0, 0);
	category_epilog = dt_get_string(cgdt, npcategory, "epilog", 0, 0);

	/* lookup failures are no more errors */
	dt_set_error_on_failed_get(cgdt, false);

	if (cgdt->error_flag)
		dt_fatal(cgdt, "Bad codegen configuration\n");

	/* common prolog on start */
	if (ftell(fp) == 0) {
		output_frag(dt, vars, fp, dtbchk->cg_common_prolog, 0);
		output_frag(dt, vars, fp, prolog, 0);
	}

	output_frag(dt, vars, fp, type_prolog, 1);
	output_frag(dt, vars, fp, category_prolog, 1);
	output_frag(dt, vars, fp, dtbchk->cg_property_check_prolog, 1);
	output_frag(dt, vars, fp, constraint, 2);
	output_frag(dt, vars, fp, dtbchk->cg_property_check_epilog, 1);
	output_frag(dt, vars, fp, category_epilog, 1);
	output_frag(dt, vars, fp, type_epilog, 1);

	return 0;
}

static int count_selected_single(struct yaml_dt_state *dt, struct node *np)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *sdt = dtbchk->sdt;

	return dt_get_rcount(sdt, np, "selected", 0);
}

static void count_selected(struct yaml_dt_state *dt, struct node *np, int *count)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *sdt = dtbchk->sdt;
	struct node *npp;
	int i, rcount;

	*count += count_selected_single(dt, np);

	rcount = dt_get_rcount(sdt, np, "inherits", 0);
	for (i = 0; i < rcount; i++) {
		npp = dt_get_noderef(sdt, np, "inherits", 0, i);
		if (!npp)
			continue;
		count_selected(dt, npp, count);
	}
}

static int count_constraints_single(struct yaml_dt_state *dt, struct node *np)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *sdt = dtbchk->sdt;
	struct node *child, *npp;
	int count;

	/* constraints of the node */
	count = dt_get_rcount(sdt, np, "constraint", 0);

	/* constraints of the properties */
	list_for_each_entry(child, &np->children, node) {
		if (strcmp(child->name, "properties"))
			continue;
		list_for_each_entry(npp, &child->children, node)
			count += dt_get_rcount(sdt, npp, "constraint", 0);
	}

	return count;
}

static void count_constraints(struct yaml_dt_state *dt, struct node *np, int *count)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *sdt = dtbchk->sdt;
	struct node *npp;
	int i, rcount;

	/* constraints of the node */
	*count += count_constraints_single(dt, np);

	/* iterating into inherits */
	rcount = dt_get_rcount(sdt, np, "inherits", 0);
	for (i = 0; i < rcount; i++) {
		npp = dt_get_noderef(sdt, np, "inherits", 0, i);
		if (!npp)
			continue;
		count_constraints(dt, npp, count);
	}
}

void print_inherits(struct yaml_dt_state *dt, struct node *np, int depth)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *sdt = dtbchk->sdt;
	char namebuf[NODE_FULLNAME_MAX];
	struct node *npp;
	int i, rcount, scount, ccount;

	scount = 0;
	count_selected(dt, np, &scount);

	ccount = 0;
	count_constraints(dt, np, &ccount);

	dt_debug(dt, "%*s", depth * 4, "");
	dt_debug(dt, "%s - selected#=%d constraints#=%d\n",
			dn_fullname(np, namebuf, sizeof(namebuf)),
			scount, ccount);

	rcount = dt_get_rcount(sdt, np, "inherits", 0);
	for (i = 0; i < rcount; i++) {
		npp = dt_get_noderef(sdt, np, "inherits", 0, i);
		if (!npp) {
			dt_debug(dt, "%*s", depth * 4, "");
			dt_debug(dt, "#%d of inherits not a ref\n", i); 
			continue;
		}
		print_inherits(dt, npp, depth + 1);
	}
}

static struct node *
__get_selected_constraint_property_single(struct yaml_dt_state *dt,
		struct node **npstack, int top, int stacksz, int idx,
		const char **constraint, struct node **nprule)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *sdt = dtbchk->sdt;
	struct node *np = npstack[top];
	struct node *npp;
	const char *propname;
	char namebuf[NODE_FULLNAME_MAX];

	dt_debug(dt, "%s on %s#%d\n", __func__,
			dn_fullname(np, namebuf, sizeof(namebuf)), idx);

	/* first try for node deref */
	npp = dt_get_noderef(sdt, np, "selected", 0, idx);
	if (npp) {
		*constraint = dt_get_string(sdt, npp, "constraint", 0, 0);
		if (*constraint) {
			*nprule = np;
			return npp;
		}
		dt_fatal(dt, "FFFF\n");
		return NULL;
	}

	/* otherwise it might be property name */

	/* get the property name */
	propname = dt_get_string(sdt, np, "selected", 0, idx);
	if (!propname)
		return NULL;

	/* we have to use the most 'deep' property starting from start */

	while (top >= 0 && (np = npstack[top]) != NULL) {

		dt_debug(dt, "checking %s on %s#%d for %s\n", __func__,
				dn_fullname(np, namebuf, sizeof(namebuf)), idx,
				propname);

		/* get properties node of the current node */
		npp = dt_get_node(sdt, np, "properties", 0);
		if (npp)
			npp = dt_get_node(sdt, npp, propname, 0);
		if (npp) {
			dt_debug(dt, "found constraint %s on %s#%d\n", __func__,
					dn_fullname(npp, namebuf, sizeof(namebuf)), idx);

			*constraint = dt_get_string(sdt, npp, "constraint", 0, 0);
			if (*constraint) {
				*nprule = np;
				return npp;
			}
		}
		top--;
	}

	return NULL;
}

static struct node *
__get_check_constraint_property_single(struct yaml_dt_state *dt,
		struct node **npstack, int top, int stacksz, int idx,
		const char **constraint, struct node **nprule)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *sdt = dtbchk->sdt;
	struct node *np = npstack[top];
	struct node *npp, *child;
	char namebuf[NODE_FULLNAME_MAX];
	int rcount;

	dt_debug(dt, "%s on %s#%d\n", __func__,
			dn_fullname(np, namebuf, sizeof(namebuf)), idx);

	rcount = dt_get_rcount(sdt, np, "constraint", 0);
	if (idx < rcount) {
		*constraint = dt_get_string(sdt, np, "constraint", 0, idx);
		if (!*constraint)
			dt_fatal(dt, "Can't get constraint\n");
		*nprule = np;
		return np;
	}
	idx -= rcount;

	/* constraints of the properties */
	list_for_each_entry(child, &np->children, node) {
		if (strcmp(child->name, "properties"))
			continue;
		list_for_each_entry(npp, &child->children, node) {
			rcount = dt_get_rcount(sdt, npp, "constraint", 0);
			if (idx < rcount) {
				*constraint = dt_get_string(sdt, npp, "constraint", 0, idx);
				if (!*constraint)
					dt_fatal(dt, "Can't get constraint\n");
				*nprule = np;
				return npp;
			}
			idx -= rcount;
		}
	}
	return NULL;
}

static struct node *
__get_constraint_property(struct yaml_dt_state *dt,
				   struct node **npstack, int top, int stacksz,
				   int idx, const char **constraint,
				   struct node **nprule,
				   enum constraint_type type)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *sdt = dtbchk->sdt;
	char namebuf[NODE_FULLNAME_MAX];
	struct node *np = npstack[top];
	struct node *npp;
	int rcount, scount, j;

	dt_debug(dt, "%s:", __func__);
	dt_debug(dt, " this=%s#%d",
			dn_fullname(np, namebuf, sizeof(namebuf)), idx);
	dt_debug(dt, "\n");

	/* try selected on this node */
	if (type == t_select) {
		rcount = count_selected_single(dt, np);
		if (idx < rcount)
			return __get_selected_constraint_property_single(dt, npstack,
					top, stacksz, idx, constraint, nprule);
	} else {
		rcount = count_constraints_single(dt, np);
		if (idx < rcount)
			return __get_check_constraint_property_single(dt, npstack,
					top, stacksz, idx, constraint, nprule);
	}
	idx -= rcount;

	/* go for each inherit in sequence */
	rcount = dt_get_rcount(sdt, np, "inherits", 0);
	for (j = 0; j < rcount; j++) {
		npp = dt_get_noderef(sdt, np, "inherits", 0, j);
		if (!npp)
			dt_fatal(dt, "Bad inherits\n");
		scount = 0;
		count_selected(dt, npp, &scount);
		if (idx < scount) {
			assert(top + 1 < stacksz);
			npstack[++top] = npp;
			return __get_constraint_property(dt, npstack,
					top, stacksz, idx, constraint, nprule, type);
		}
		idx -= scount;
	}

	return NULL;
}

static struct node *
get_constraint_property(struct yaml_dt_state *dt, struct node *np,
				 int idx, const char **constraint,
				 struct node **nprule,
				 enum constraint_type type)
{
	struct node *npstack[32];

	*constraint = NULL;
	*nprule = NULL;
	npstack[0] = np;
	return __get_constraint_property(dt,
			npstack, 0, ARRAY_SIZE(npstack), idx,
			constraint, nprule, type);
}

static void save_file(struct yaml_dt_state *dt, const char *base,
		      enum constraint_type type, const char *ext,
		      void *data, size_t size)
{
	FILE *fp;
	char *filename;
	int ret;
	size_t nwrite;

	ret = asprintf(&filename, "%s%s%s", base,
			type == t_select ? "-select" : "-check",
			ext);
	if (ret == -1)
		dt_fatal(dt, "Failed to allocate string %s%s%s\n", base,
				type == t_select ? "-select" : "-check", ext);

	fp = fopen(filename, "wb");
	if (!fp)
		dt_fatal(dt, "Failed to open %s%s%s\n", base,
				type == t_select ? "-select" : "-check", ext);

	nwrite = fwrite(data, 1, size, fp);
	if (nwrite != size)
		dt_fatal(dt, "Failed to write %s%s%s\n", base,
				type == t_select ? "-select" : "-check", ext);

	fclose(fp);
	free(filename);
}

static int prepare_schema_node(struct yaml_dt_state *dt,
		struct yaml_dt_state *sdt, struct node *np,
		enum constraint_type type)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct property *prop;
	struct ref *ref;
	/* char namebuf[NODE_FULLNAME_MAX]; */
	const char *cnst;
	int i, idx, err;
	struct node *npp, *nprule;
	char idxbuf[9];
#define NODE_NAME_IDX 0
#define PROPERTY_NAME_IDX 1
#define PROPERTY_INDEX_IDX 2
#define RULE_NAME_IDX 3
#define VARS_COUNT 4
	struct var vars[VARS_COUNT + 1];
	char *buf;
	size_t size;
	FILE *fp;
	void *output;
	size_t output_size;
	void *b64_output;
	size_t b64_output_size;
	const char *source_name;
	const char *output_name;;
	const char *epilog;
	struct constraint_desc *cd;

	switch (type) {
	case t_select:
		source_name = "selected-rule-source";
		output_name = "selected-rule-output";
		epilog = dtbchk->cg_node_select_epilog;
		break;
	case t_check:
		source_name = "check-rule-source";
		output_name = "check-rule-output";
		epilog = dtbchk->cg_node_check_epilog;
		break;
	default:
		return -1;
	}

	/* open memstream */
	fp = open_memstream(&buf, &size);
	assert(fp);

	/* setup the variables to expand */
	snprintf(idxbuf, sizeof(idxbuf) - 1, "%d", -1);
	idxbuf[sizeof(idxbuf) - 1] = '\0';

	vars[NODE_NAME_IDX].name = "NODE_NAME";
	vars[NODE_NAME_IDX].value = np->name;
	vars[PROPERTY_NAME_IDX].name = "PROPERTY_NAME";
	vars[PROPERTY_NAME_IDX].value = "";
	vars[PROPERTY_INDEX_IDX].name = "PROPERTY_INDEX";
	vars[PROPERTY_INDEX_IDX].value = idxbuf;
	vars[RULE_NAME_IDX].name = "RULE_NAME";
	vars[RULE_NAME_IDX].value = "";
	vars[VARS_COUNT].name = NULL;
	vars[VARS_COUNT].value = NULL;

	/* try specific constraints */
	idx = 0;
	for (i = 0;
	     (npp = get_constraint_property(dt, np, i, &cnst, &nprule, type)) != NULL;
	     i++) {

		/* it can happen for non-instantiated rules */
		if (!cnst)
			continue;

		dt_debug(dt, "Appending constraint for %s prop %s: %s\n",
				np->name, npp->name, cnst);

		/* update variables */
		snprintf(idxbuf, sizeof(idxbuf) - 1, "%d", idx);
		idxbuf[sizeof(idxbuf) - 1] = '\0';
		vars[PROPERTY_INDEX_IDX].value = idxbuf;
		vars[PROPERTY_NAME_IDX].value = npp->name;
		vars[RULE_NAME_IDX].value = nprule->name;

		append_constraint(dt, sdt, np, npp, fp, cnst, vars, type, idx);

		/* add the constraint desc entry */
		cd = malloc(sizeof(*cd));
		assert(cd);
		memset(cd, 0, sizeof(*cd));
		cd->type = type;
		cd->idx = idx;
		cd->np = np;
		cd->npp = npp;
		list_add_tail(&cd->node, &dtbchk->clist);

		idx++;
	}

	/* mark end */
	snprintf(idxbuf, sizeof(idxbuf) - 1, "%d", -1);
	idxbuf[sizeof(idxbuf) - 1] = '\0';
	vars[PROPERTY_INDEX_IDX].value = idxbuf;
	vars[PROPERTY_NAME_IDX].value = "";
	vars[RULE_NAME_IDX].value = "";

	/* it output was generated tack on epilog */
	if (ftell(fp) != 0) {
		output_frag(dt, vars, fp, epilog, 0);
		output_frag(dt, vars, fp, dtbchk->cg_common_epilog, 0);
	}
	fclose(fp);

	err = 0;
	if (size) {
		/* add the source */
		prop = prop_alloc(to_tree(sdt), source_name);
		prop->np = np;
		list_add_tail(&prop->node, &np->properties);

		ref = ref_alloc(to_tree(sdt), r_scalar, buf, size,
				dtbchk->input_tag);
		ref->prop = prop;
		list_add_tail(&ref->node, &prop->refs);

		dt_resolve_ref(sdt, ref);

		if (dtbchk->save_temps)
			save_file(dt, np->name, type, dtbchk->input_ext,
				  buf, size);

		/* and compile it */
		err = compile(ref->data, ref->len,
				dtbchk->compiler,
				dtbchk->cflags,
				&output, &output_size);
		if (err) {
			tree_error_at_ref(to_tree(sdt), ref,
				"Failed to compile %s:\n%s %s\n",
				to_dt_ref(ref)->tag,
				dtbchk->compiler, dtbchk->cflags);
			goto out_err;
		}

		b64_output = base64_encode(output, output_size,
					   &b64_output_size);

		if (dtbchk->save_temps)
			save_file(dt, np->name, type, dtbchk->output_ext,
					output, output_size);

		if (!b64_output) {
			tree_error_at_ref(to_tree(sdt), ref,
				"Failed to encode to base64\n");
			err = -ENOMEM;
			goto out_err;
		}

		/* add the output */
		prop = prop_alloc(to_tree(sdt), output_name);
		prop->np = np;
		list_add_tail(&prop->node, &np->properties);

		ref = ref_alloc(to_tree(sdt), r_scalar,
				b64_output, b64_output_size,
				dtbchk->output_tag);
		ref->prop = prop;
		list_add_tail(&ref->node, &prop->refs);

		dt_resolve_ref(sdt, ref);

		/* save to ref */
		to_dt_ref(ref)->binary = output;
		to_dt_ref(ref)->binary_size = output_size;

		free(b64_output);

	}

out_err:

	free(buf);

	return err;
}

static int prepare_schema(struct yaml_dt_state *dt)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *sdt = dtbchk->sdt;
	struct node *root, *np;
	int ret;

	root = tree_root(to_tree(sdt));

	list_for_each_entry(np, &root->children, node) {
		ret = prepare_schema_node(dt, sdt, np, t_select);
		if (ret)
			dt_fatal(dt, "Failed to prepare selector %s\n",
					np->name);

		ret = prepare_schema_node(dt, sdt, np, t_check);
		if (ret)
			dt_fatal(dt, "Failed to prepare checker %s\n",
					np->name);
	}

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
	dtbchk->save_temps = dt->cfg.save_temps;

	INIT_LIST_HEAD(&dtbchk->clist);

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
	dtbchk->input_ext = dt_get_string(cgdt, cgroot, "input-extension", 0, 0);
	dtbchk->output_tag = dt_get_string(cgdt, cgroot, "output-tag", 0, 0);
	dtbchk->output_ext = dt_get_string(cgdt, cgroot, "output-extension", 0, 0);
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
	struct constraint_desc *cd, *cdn;
	struct dtb_check_state *dtbchk = to_dtbchk(dt);

	/* the children parsers are automatically cleaned */

	/* clean constraint descriptors */
	list_for_each_entry_safe(cd, cdn, &dtbchk->clist, node) {
		list_del(&cd->node);
		free(cd);
	}

	free(dtbchk);
}

#ifdef CAN_RUN_EBPF

/* find the constraint entry by error code */
static struct constraint_desc *lookup_constraint_by_ret(struct yaml_dt_state *dt,
		struct node *np, struct node *snp, uint64_t vmret)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct constraint_desc *cd;
	int idx;
	long long ret = (int64_t)vmret;

	if (ret >= 0 || ret < -3000)
		return NULL;

	if (ret < -2000) 		/* exist check */
		idx = -(ret + 2000);
	else if (ret < -1000) 		/* property check */
		idx = -(ret + 1000);
	else if (ret == -1)		/* node constraint */
		return NULL;
	else
		return NULL;

	list_for_each_entry(cd, &dtbchk->clist, node) {
		if (cd->type == t_check && cd->np == snp && cd->idx == idx)
			return cd;
	}
	return NULL;
}

static void check_node_single(struct yaml_dt_state *dt,
		       struct node *np, struct node *snp,
		       struct ebpf_dt_ctx *select_ctx,
		       struct ebpf_dt_ctx *check_ctx)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *sdt = dtbchk->sdt;
	struct node *child;
	char namebuf[NODE_FULLNAME_MAX];
	int err;
	uint64_t vmret;
	struct constraint_desc *cd;
	struct property *prop;
	struct ref *ref;

	dt_debug(dt, "%s: against %s - running select\n",
			dn_fullname(np, namebuf, sizeof(namebuf)),
			snp->name ? : "/");

	vmret = ebpf_exec(&select_ctx->vm, np, 0, &err);
	if (err)
		dt_fatal(dt, "exec failed with code %d (%s)\n",
				err, strerror(-err));

	if (vmret == 0) {
		dt_debug(dt, "select match at node %s\n",
			dn_fullname(np, namebuf, sizeof(namebuf)));

		/* now running check */
		vmret = ebpf_exec(&check_ctx->vm, np, 0, &err);
		if (err)
			dt_fatal(dt, "exec failed with code %d (%s)\n",
					err, strerror(-err));
		if (vmret == 0)
			dt_debug(dt, "node %s is correct\n",
				dn_fullname(np, namebuf, sizeof(namebuf)));
		else {
			cd = lookup_constraint_by_ret(dt, np, snp, vmret);
			if (cd) {
				if ((prop = dt_get_property(dt, np, cd->npp->name, 0)) &&
				    (ref = dt_get_ref(dt, prop, 0))) {
					tree_error_at_ref(to_tree(dt), ref,
						"illegal property value\n");
				}

				/* tree_error_at_node(to_tree(sdt), cd->npp,
					"property was defined at %s\n",
					dn_fullname(cd->npp, namebuf, sizeof(namebuf))); */

				if ((prop = dt_get_property(sdt, cd->npp, "constraint", 0)) &&
				    (ref = dt_get_ref(sdt, prop, 0)))
					tree_error_at_ref(to_tree(sdt), ref,
						"constraint that fails was defined here\n");
			} else {
				tree_error_at_node(to_tree(dt), np,
					"node %s has failed verification (code=%lld)\n",
					dn_fullname(np, namebuf, sizeof(namebuf)),
					(long long)vmret);

			}
		}
	}

	list_for_each_entry(child, &np->children, node)
		check_node_single(dt, child, snp, select_ctx, check_ctx);
}

int dtbchk_check(struct yaml_dt_state *dt)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *sdt = dtbchk->sdt;
	struct node *snp, *sroot = tree_root(to_tree(sdt));
	size_t check_size, select_size;
	const char *check, *select;
	struct ebpf_dt_ctx select_ctx;
	struct ebpf_dt_ctx check_ctx;
	struct ebpf_vm *select_vm;
	struct ebpf_vm *check_vm;
	int ret;

	/* check each rule in the root */
	list_for_each_entry(snp, &sroot->children, node) {

		select = dt_get_binary(sdt, snp, "selected-rule-output",
				0, 0, &select_size);
		check = dt_get_binary(sdt, snp, "check-rule-output",
				0, 0, &check_size);

		/* can't check this node */
		if (!select || !check)
			continue;

		select_vm = &select_ctx.vm;
		select_ctx.dt = dt;
		check_ctx.dt = dt;
		check_vm = &check_ctx.vm;

		/* setup the select and check vms */
		ret = ebpf_setup(select_vm, bpf_dt_cb, NULL, NULL, NULL);
		if (ret)
			dt_fatal(dt, "Failed to setup select vm ebpf\n");

		ret = ebpf_load_elf(select_vm, select, select_size);
		if (ret)
			dt_fatal(dt, "Failed to load select vm ebpf\n");

		ret = ebpf_setup(check_vm, bpf_dt_cb, NULL, NULL, NULL);
		if (ret)
			dt_fatal(dt, "Failed to setup check vm ebpf\n");

		ret = ebpf_load_elf(check_vm, check, check_size);
		if (ret)
			dt_fatal(dt, "Failed to load check vm ebpf\n");

		check_node_single(dt, tree_root(to_tree(dt)), snp,
				&select_ctx, &check_ctx);

		ebpf_cleanup(select_vm);
		ebpf_cleanup(check_vm);
	}

	return 0;
}

#endif

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
#ifdef CAN_RUN_EBPF
	.check		= dtbchk_check,
#endif
};

struct yaml_dt_checker dtb_checker = {
	.name		= "dtbchk",
	.cops		= &dtb_checker_ops,
};
