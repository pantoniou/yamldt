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

#define NPSTACK_SIZE	8

#define SELECT_BASE	100000
#define ERROR_BASE	4000
#define BADTYPE_BASE	3000
#define EXISTS_BASE	2000
#define PROPC_BASE	1000
#define NODEC_BASE	0

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

enum constraint_subtype {
	st_select_ref,
	st_select_prop,
	st_check_category,
	st_check_type,
	st_check_rule,
};

struct constraint_desc {
	struct list_head node;
	struct constraint_desc *parent;
	struct list_head children;	/* constraints that operate on the same properties */
	enum constraint_type type;
	enum constraint_subtype subtype;
	int idx;		/* index in the code gen */
	struct node *np;	/* schema node */
	struct node *npp;	/* schema property node (that has the constraint) */
	const char *constraint;	/* if available */
	const char *propname;	/* propname */
	int npstacksz;		/* size of the stack */
	struct node *npstack[];	/* the actual stack */
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
	const char *cg_property_check_badtype_prolog;
	const char *cg_property_check_badtype_epilog;
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

static inline bool constraint_should_skip_content(struct yaml_dt_state *dt,
		const struct constraint_desc *cd)
{
	return cd->type == t_check && (cd->subtype == st_check_type ||
				       cd->subtype == st_check_category);
}

static int append_constraint(struct yaml_dt_state *dt,
			     struct constraint_desc *cd,
			     FILE *fp, const struct var *vars)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *cgdt = dtbchk->cgdt;
	struct node *property_np = cd->npp;
	const char *type_prolog, *type_epilog;
	const char *category_prolog, *category_epilog;
	struct node *nptype, *npcategory;
	struct constraint_desc *cdt;

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

	output_frag(dt, vars, fp, type_prolog, 1);
	output_frag(dt, vars, fp, dtbchk->cg_property_check_badtype_prolog, 1);
	output_frag(dt, vars, fp, category_prolog, 1);

	if (!constraint_should_skip_content(dt, cd)) {

		output_frag(dt, vars, fp, dtbchk->cg_property_check_prolog, 1);
		output_frag(dt, vars, fp, cd->constraint, 2);
		output_frag(dt, vars, fp, dtbchk->cg_property_check_epilog, 1);
	}

	list_for_each_entry(cdt, &cd->children, node) {
		if (constraint_should_skip_content(dt, cdt))
			continue;

		output_frag(dt, vars, fp, dtbchk->cg_property_check_prolog, 1);
		output_frag(dt, vars, fp, cdt->constraint, 2);
		output_frag(dt, vars, fp, dtbchk->cg_property_check_epilog, 1);
	}

	output_frag(dt, vars, fp, category_epilog, 1);
	output_frag(dt, vars, fp, dtbchk->cg_property_check_badtype_epilog, 1);
	output_frag(dt, vars, fp, type_epilog, 1);

	return 0;
}

static int append_constraint_prop(struct yaml_dt_state *dt, struct node *npc,
				  const char *name, const void *data, int size,
				  const char *tag)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *sdt = dtbchk->sdt;
	struct property *prop;
	struct ref *ref;

	if (!data)
		return 0;

	prop = prop_alloc(to_tree(sdt), name);
	prop->np = npc;
	list_add_tail(&prop->node, &npc->properties);

	ref = ref_alloc(to_tree(sdt), r_scalar, data, size, tag);
	ref->prop = prop;
	list_add_tail(&ref->node, &prop->refs);

	return dt_resolve_ref(sdt, ref);
}

static int append_constraint_to_schema(struct yaml_dt_state *dt,
				       struct node *np,
				       const char *npname,
				       struct constraint_desc *cd)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *sdt = dtbchk->sdt;
	struct constraint_desc *cdt;
	struct node *npt, *npc;
	char namebuf[NODE_FULLNAME_MAX];
	const char *typetxt, *subtypetxt;
	struct property *prop;
	const char *constraint_propname;
	struct ref *ref;
	int i;

	/* add the contraint node if not there  */
	npt = node_get_child_by_name(to_tree(sdt), np, npname, 0);
	if (!npt) {
		npt = node_alloc(to_tree(sdt), npname, NULL);
		list_add_tail(&npt->node, &np->children);
	}

	snprintf(namebuf, sizeof(namebuf), "c-%d", cd->idx);
	npc = node_alloc(to_tree(sdt), namebuf, NULL);
	list_add_tail(&npc->node, &npt->children);

	snprintf(namebuf, sizeof(namebuf), "%d", cd->idx);
	append_constraint_prop(dt, npc, "id",
			namebuf, strlen(namebuf), NULL);

	switch (cd->type) {
	case t_select:
		typetxt = "select";
		break;
	case t_check:
		typetxt = "check";
		break;
	default:
		typetxt = NULL;
		break;
	}
	if (typetxt)
		append_constraint_prop(dt, npc, "type",
			       typetxt, strlen(typetxt), "!str");

	switch (cd->subtype) {
	case st_select_ref:
		subtypetxt = "select-ref";
		constraint_propname = "constraint";
		break;
	case st_select_prop:
		subtypetxt = "select-prop";
		constraint_propname = "constraint";
		break;
	case st_check_category:
		subtypetxt = "check-category";
		constraint_propname = "category";
		break;
	case st_check_type:
		subtypetxt = "check-type";
		constraint_propname = "type";
		break;
	case st_check_rule:
		subtypetxt = "check-rule";
		constraint_propname = "constraint";
		break;
	default:
		subtypetxt = NULL;
		constraint_propname = NULL;
		break;
	}
	if (subtypetxt)
		append_constraint_prop(dt, npc, "subtype",
			       subtypetxt, strlen(subtypetxt), "!str");

	if (cd->propname)
		append_constraint_prop(dt, npc, "propname",
				cd->propname, strlen(cd->propname),
				"!str");
	if (cd->constraint) {
		append_constraint_prop(dt, npc, constraint_propname,
				cd->constraint, strlen(cd->constraint),
				"!str");
	}

	if (cd->np) {
		dn_fullname(cd->np, namebuf, sizeof(namebuf));
		append_constraint_prop(dt, npc, "rule-originator",
				namebuf, strlen(namebuf),
				"!str");
	}

	if (cd->npp) {
		dn_fullname(cd->npp, namebuf, sizeof(namebuf));
		append_constraint_prop(dt, npc, "rule-provider",
				namebuf, strlen(namebuf),
				"!str");
	}

	if (cd->npstacksz > 0) {
		prop = prop_alloc(to_tree(sdt), "rule-stack");
		prop->np = npc;
		list_add_tail(&prop->node, &npc->properties);

		for (i = 0; i < cd->npstacksz; i++) {

			dn_fullname(cd->npstack[i], namebuf, sizeof(namebuf));

			ref = ref_alloc(to_tree(sdt), r_scalar,
					namebuf, strlen(namebuf), "!str");
			ref->prop = prop;
			list_add_tail(&ref->node, &prop->refs);

			dt_resolve_ref(sdt, ref);
		}
	}

	list_for_each_entry(cdt, &cd->children, node)
		append_constraint_to_schema(dt, npc, "subconstraints", cdt);

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
	int count, constraint_count;

	/* constraints of the node */
	count = dt_get_rcount(sdt, np, "constraint", 0);

	/* constraints of the properties */
	for_each_child_of_node(np, child) {
		if (strcmp(child->name, "properties"))
			continue;
		for_each_child_of_node(child, npp) {
			constraint_count = dt_get_rcount(sdt, npp, "constraint", 0);
			if (dt_get_string(sdt, npp, "type", 0, 0))
				constraint_count++;
			count += constraint_count;
		}
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

	fprintf(stderr, "%*s", depth * 4, "");
	fprintf(stderr, "%s - selected#=%d constraints#=%d\n",
			dn_fullname(np, namebuf, sizeof(namebuf)),
			scount, ccount);

	rcount = dt_get_rcount(sdt, np, "inherits", 0);
	for (i = 0; i < rcount; i++) {
		npp = dt_get_noderef(sdt, np, "inherits", 0, i);
		if (!npp) {
			fprintf(stderr, "%*s", depth * 4, "");
			fprintf(stderr, "#%d of inherits not a ref\n", i); 
			continue;
		}
		print_inherits(dt, npp, depth + 1);
	}
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

static bool constraint_eq(const struct constraint_desc *cd1,
		const struct constraint_desc *cd2)
{
	return cd1->type == cd2->type && cd1->subtype == cd2->subtype &&
	       !strcmp(cd1->constraint, cd2->constraint);
}

static void add_constraint(struct yaml_dt_state *dt,
	struct list_head *clist,
	enum constraint_type type, enum constraint_subtype subtype, int *idxp,
	struct node **npstack, int top, int stacksz,
	struct node *npp, const char *constraint,
	const char *propname)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *cgdt = dtbchk->cgdt;
	struct node *np = npstack[top];
	struct constraint_desc *cd, *cdt, *cdn;
	struct node *nptype, *npcategory;
	struct list_head *lh;
	size_t size;

	/* constraint must have type and category properties */
	nptype = dt_get_node(cgdt, dtbchk->cg_property_check_types,
			dt_get_string(cgdt, npp, "type", 0, 0), 0);
	if (!nptype)
		return;

	npcategory = dt_get_node(cgdt, dtbchk->cg_property_check_categories,
			dt_get_string(cgdt, npp, "category", 0, 0), 0);
	if (!npcategory)
		return;

	size = sizeof(*cd) + sizeof(*npstack) * (top + 1);
	cd = malloc(size);
	assert(cd);
	memset(cd, 0, size);
	cd->type = type;
	cd->subtype = subtype;
	cd->idx = *idxp;
	cd->np = np;
	cd->npp = npp;
	cd->constraint = constraint;
	cd->propname = propname;
	cd->npstacksz = top + 1;
	memcpy(cd->npstack, npstack, sizeof(*npstack) * cd->npstacksz);
	INIT_LIST_HEAD(&cd->children);
	cd->parent = NULL;

	/* if a property constraint exist with that name */
	list_for_each_entry(cdt, clist, node) {
		if (cdt->type == cd->type && !strcmp(cdt->propname, cd->propname)) {
			cd->parent = cdt;
			break;
		}
	}

	lh = cd->parent ? &cdt->children : clist;

	if (cd->parent) {
		if (constraint_eq(cd->parent, cd)) {
			free(cd);
			return;
		}

		/* detect duplicate constraints */
		list_for_each_entry(cdn, lh, node) {
			if (constraint_eq(cdn, cd)) {
				free(cd);
				return;
			}
		}

	}

	list_add_tail(&cd->node, lh);

	(*idxp)++;

	/*
	{
	char namebuf[NODE_FULLNAME_MAX];
	const char *typename;
	const char *subtypename;
	int i;

	switch (type) {
	case t_select:
		typename = "select";
		break;
	case t_check:
		typename = "check";
		break;
	default:
		typename = "*unknown*";
		break;
	}

	switch (subtype) {
	case st_select_ref:
		subtypename = "ref";
		break;
	case st_select_prop:
		subtypename = "prop";
		break;
	case st_check_category:
		subtypename = "category";
		break;
	case st_check_type:
		subtypename = "type";
		break;
	case st_check_rule:
		subtypename = "rule";
		break;
	default:
		subtypename = "*unknown*";
		break;
	}

	fprintf(stderr, "%s type=%s, subtype=%s idx=%d\n", __func__, typename, subtypename, *idxp - 1);
	fprintf(stderr, "    np=%s\n", dn_fullname(np, namebuf, sizeof(namebuf)));
	fprintf(stderr, "    npp=%s\n", dn_fullname(npp, namebuf, sizeof(namebuf)));
	fprintf(stderr, "    constraint=%s\n", constraint ? : "<NULL>");
	fprintf(stderr, "    propname=%s\n", propname ? : "<NULL>");
	for (i = 0; i < cd->npstacksz; i++)
		fprintf(stderr, "    npstack[%d]=%s\n", i,
				dn_fullname(cd->npstack[i], namebuf, sizeof(namebuf)));
	fprintf(stderr, "    nptype=%s\n", dn_fullname(nptype, namebuf, sizeof(namebuf)));
	fprintf(stderr, "    npcategory=%s\n", dn_fullname(npcategory, namebuf, sizeof(namebuf)));
	}
	*/
}

static void free_constraint(struct yaml_dt_state *dt, struct constraint_desc *cd)
{
	struct constraint_desc *cdc, *cdcn;

	list_del(&cd->node);
	list_for_each_entry_safe(cdc, cdcn, &cd->children, node)
		free_constraint(dt, cdc);
	free(cd);
}

static void collect_constraint_prop(struct yaml_dt_state *dt,
		struct node **npstack, int top, int stacksz,
		enum constraint_type type, enum constraint_subtype subtype,
		struct list_head *clist, int *idxp, struct node *npp,
		const char *propname)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *sdt = dtbchk->sdt;
	struct property *cprop;
	const char *constraint;
	struct ref *cref;
	int k, l;

	/* iterate over all constraints */
	for (k = 0; (cprop = dt_get_property(sdt, npp, "constraint", k)); k++) {
		/* iterate over all refs in the "constraints" property */
		for (l = 0; (cref = dt_get_ref(sdt, cprop, l)); l++) {
			constraint = dt_get_string(sdt, npp, "constraint", k, l);
			if (!constraint) {
				tree_error_at_ref(to_tree(sdt), cref,
					"not a string\n");
				continue;
			}
			add_constraint(dt, clist, type, subtype, idxp,
					npstack, top, stacksz, npp, constraint,
					propname);
		}
	}
}

static void collect_constraint_check_default(struct yaml_dt_state *dt,
		struct node **npstack, int top, int stacksz,
		struct list_head *clist, int *idxp, struct node *npp,
		const char *propname)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *sdt = dtbchk->sdt;
	const char *category;
	const char *ptype;

	/* those may not exist if the rule is not defining properties */
	category = dt_get_string(sdt, npp, "category", 0, 0);
	if (category)
		add_constraint(dt, clist, t_check, st_check_category, idxp,
				npstack, top, stacksz, npp, category,
				propname);

	ptype = dt_get_string(sdt, npp, "type", 0, 0);
	if (!ptype)
		add_constraint(dt, clist, t_check, st_check_type, idxp,
				npstack, top, stacksz, npp, ptype,
				propname);
}

static void collect_constraint_node(struct yaml_dt_state *dt,
		struct node **npstack, int top, int stacksz,
		enum constraint_type type, struct list_head *clist, int *idxp)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *sdt = dtbchk->sdt;
	struct node *np = npstack[top];
	struct node *npp, *npt, *nppt;
	const char *propname;
	struct property *prop;
	struct ref *ref;
	int i, j, m, n, rcount;

	if (type == t_select) {
		/* iterate over all selected properties */
		for (i = 0; (prop = dt_get_property(sdt, np, "selected", i)); i++) {

			/* iterate over all refs in the "selected" property */
			for (j = 0; (ref = dt_get_ref(sdt, prop, j)); j++) {

				/* try *ref first */
				npp = dt_ref_noderef(sdt, ref);
				if (npp) {
					collect_constraint_prop(dt, npstack, top, stacksz,
							type, st_select_ref, clist, idxp,
							npp, npp->name);
					continue;
				}

				/* try property name */
				propname = dt_ref_string(sdt, ref);
				if (!propname) {
					tree_error_at_ref(to_tree(sdt), ref,
						"Not a constraint reference or property\n");
					continue;
				}

				/* now collect all the constraints for that property name */
				for (m = top; m >= 0 && (npt = npstack[m]); m--) {
					for (n = 0; (npp = dt_get_node(sdt, npt, "properties", n)); n++) {

						for_each_child_of_node(npp, nppt) {

							/* property name must match */
							if (strcmp(nppt->name, propname))
								continue;

							collect_constraint_prop(dt, npstack, top, stacksz,
									t_select, st_select_prop, clist, idxp,
									nppt, propname);
						}
					}
				}
			}
		}
	} else if (type == t_check) {
		/* now collect all the constraints for that property name */
		for (m = top; m >= 0 && (npt = npstack[m]); m--) {
			for (n = 0; (npp = dt_get_node(sdt, npt, "properties", n)); n++) {

				for_each_child_of_node(npp, nppt) {

					collect_constraint_check_default(dt, npstack, top, stacksz,
							clist, idxp, nppt, nppt->name);

					/* collect the rule constraints */
					collect_constraint_prop(dt, npstack, top, stacksz,
							t_check, st_check_rule, clist, idxp,
							nppt, nppt->name);
				}
			}


		}
	} else
		return;

	/* collect constraints we've inherited */
	rcount = dt_get_rcount(sdt, np, "inherits", 0);
	for (i = 0; i < rcount; i++) {
		npp = dt_get_noderef(sdt, np, "inherits", 0, i);
		if (npp) {
			assert(top + 1 < stacksz);
			npstack[++top] = npp;
			collect_constraint_node(dt, npstack, top, stacksz, type, clist, idxp);
		}
	}
}

static int prepare_schema_node(struct yaml_dt_state *dt,
		struct yaml_dt_state *sdt, struct node *np,
		int *idxp)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct property *prop;
	struct ref *ref;
	int err;
	char idxbuf[9];
#define NODE_NAME_IDX 0
#define PROPERTY_NAME_IDX 1
#define PROPERTY_INDEX_IDX 2
#define RULE_NAME_IDX 3
#define VARS_COUNT 4
	struct var vars[VARS_COUNT + 1];
	char *buf = NULL;
	size_t size;
	FILE *fp;
	void *output;
	size_t output_size;
	void *b64_output;
	size_t b64_output_size;
	const char *source_name;
	const char *output_name;;
	const char *prolog;
	const char *epilog;
	struct list_head clist;
	struct constraint_desc *cd, *cdn;
	struct node *npstack[NPSTACK_SIZE];
	struct node *npt;
	int idx, ret;

	source_name = "check-rule-source";
	output_name = "check-rule-output";
	prolog = dtbchk->cg_node_check_prolog;
	epilog = dtbchk->cg_node_check_epilog;

	INIT_LIST_HEAD(&clist);
	npstack[0] = np;
	collect_constraint_node(dt, npstack, 0, ARRAY_SIZE(npstack), t_select, &clist, idxp);
	collect_constraint_node(dt, npstack, 0, ARRAY_SIZE(npstack), t_check, &clist, idxp);

	/* nothing to do */
	if (list_empty(&clist))
		return 0;

	if (!dtbchk->codegen)
		dt_fatal(dt, "required codegen is missing\n");

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

	output_frag(dt, vars, fp, dtbchk->cg_common_prolog, 0);
	output_frag(dt, vars, fp, prolog, 0);

	/* iterate over all constraints */
	list_for_each_entry_safe(cd, cdn, &clist, node) {

		/* update variables */
		idx = cd->idx;
		if (cd->type == t_select)
			idx += SELECT_BASE;	/* select errors return values under 100000 */
		snprintf(idxbuf, sizeof(idxbuf) - 1, "%d", idx);
		idxbuf[sizeof(idxbuf) - 1] = '\0';
		vars[PROPERTY_INDEX_IDX].value = idxbuf;

		vars[PROPERTY_NAME_IDX].value = cd->propname;
		vars[RULE_NAME_IDX].value = cd->np->name;

		dt_debug(dt, "Appending constraint for %s prop %s (%s): %s\n",
				cd->np->name, cd->npp->name, cd->propname, cd->constraint);

		append_constraint(dt, cd, fp, vars);
		append_constraint_to_schema(dt, np, "constraints", cd);

		list_del(&cd->node);
		list_add_tail(&cd->node, &dtbchk->clist);
	}

	/* mark end */
	snprintf(idxbuf, sizeof(idxbuf) - 1, "%d", -1);
	idxbuf[sizeof(idxbuf) - 1] = '\0';
	vars[PROPERTY_INDEX_IDX].value = idxbuf;
	vars[PROPERTY_NAME_IDX].value = "";
	vars[RULE_NAME_IDX].value = "";

	output_frag(dt, vars, fp, epilog, 0);
	output_frag(dt, vars, fp, dtbchk->cg_common_epilog, 0);
	fclose(fp);

	err = 0;
	if (!size)
		goto out;

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
		save_file(dt, np->name, t_check, dtbchk->input_ext,
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
		goto out;
	}

	b64_output = base64_encode(output, output_size,
					&b64_output_size);

	if (dtbchk->save_temps)
		save_file(dt, np->name, t_check, dtbchk->output_ext,
				output, output_size);

	if (!b64_output) {
		tree_error_at_ref(to_tree(sdt), ref,
			"Failed to encode to base64\n");
		err = -ENOMEM;
		goto out;
	}

	/* add the output */
	npt = node_alloc(to_tree(sdt), output_name, NULL);
	list_add_tail(&npt->node, &np->children);

	prop = prop_alloc(to_tree(sdt), "ebpf");
	prop->np = npt;
	list_add_tail(&prop->node, &npt->properties);

	ref = ref_alloc(to_tree(sdt), r_scalar,
			b64_output, b64_output_size,
			"!base64");

	ref->prop = prop;
	list_add_tail(&ref->node, &prop->refs);

	ret = dt_resolve_ref(sdt, ref);

	assert(!ret || to_dt_ref(ref)->binary);

	free(output);
	free(b64_output);

	if (ret) {
		tree_error_at_ref(to_tree(sdt), ref,
			"Failed to encode to base64\n");
		err = -ENOMEM;
	}

out:

	if (buf)
		free(buf);

	assert(list_empty(&clist));

	return err;
}

static int prepare_schema(struct yaml_dt_state *dt)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *sdt = dtbchk->sdt;
	struct node *root, *np;
	int ret, idx;
	const char *check;
	size_t check_size;
	struct node *npchk;

	root = tree_root(to_tree(sdt));
	if (!root)
		return 0;

	dt_debug(dt, "preparing schema\n");

	idx = 1;
	for_each_child_of_node(root, np) {

		/* never generate checkers for virtuals */
		ret = dt_get_bool(sdt, np, "virtual", 0, 0);
		if (ret == 1)
			continue;

		npchk = node_get_child_by_name(to_tree(sdt), np,
				"check-rule-output", 0);
		check = dt_get_binary(sdt, npchk, "ebpf", 0, 0, &check_size);

		if (check) {
			dt_debug(dt, "skipping schema_node %s:\n", np->name);
			continue;
		}

		dt_debug(dt, "preparing schema_node %s:\n", np->name);

		ret = prepare_schema_node(dt, sdt, np, &idx);
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

	if (!dtbchk->schema_save && dtbchk->save_temps)
		dtbchk->schema_save = "schema.yaml";

	INIT_LIST_HEAD(&dtbchk->clist);

	dt->checker_state = dtbchk;

	if (!dtbchk->schema)
		dt_fatal(dt, "No schema file provided\n");

	/* if codegen is available use it */
	if (dtbchk->codegen) {

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
		dtbchk->cg_property_check_badtype_prolog = dt_get_string(cgdt, dtbchk->cg_property_check, "badtype-prolog", 0, 0);
		dtbchk->cg_property_check_badtype_epilog = dt_get_string(cgdt, dtbchk->cg_property_check, "badtype-epilog", 0, 0);

		dtbchk->cg_property_check_types = dt_get_node(cgdt, dtbchk->cg_property_check, "types", 0);
		dtbchk->cg_property_check_categories = dt_get_node(cgdt, dtbchk->cg_property_check, "categories", 0);

		if (cgdt->error_flag)
			dt_fatal(cgdt, "Could not find codegen data\n");

		dt_set_error_on_failed_get(cgdt, false);
	}

	/* schema is parsed after codegen */
	dtbchk->sdt = dt_parse_single(dt, dtbchk->schema, dtbchk->schema_save,
				      "schema");
	if (!dtbchk->sdt)
		dt_fatal(dt, "Couldn't parse schema file %s\n", dtbchk->schema);

	err = prepare_schema(dt);
	if (err)
		dt_fatal(dt, "Failed to prepare schema\n");

	if (dtbchk->schema_save)
		dt_emitter_emit(dtbchk->sdt);

	dt_debug(dt, "DTB checker configuration:\n");
	dt_debug(dt, " schema      = %s\n", dtbchk->schema);
	dt_debug(dt, " schema-save = %s\n", dtbchk->schema_save);
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
	list_for_each_entry_safe(cd, cdn, &dtbchk->clist, node)
		free_constraint(dt, cd);

	free(dtbchk);
}

#ifdef CAN_RUN_EBPF

enum constraint_error_type {
	cet_no_error,
	cet_bad_property_type,
	cet_missing_property,
	cet_property_constraint_failed,
	cet_node_constraint_failed,
};

static const char *constraint_error_txt(enum constraint_error_type errtype)
{
	switch (errtype) {
	case cet_no_error:
		return "no error";
	case cet_bad_property_type:
		return "bad property type";
	case cet_missing_property:
		return "missing property";
	case cet_property_constraint_failed:
		return "constraint failed";
	case cet_node_constraint_failed:
		return "node constraint failed";
	default:
		break;
	}
	return "<NULL>";
}

static int parse_constraint_ret(uint64_t vmret,
		enum constraint_error_type *errtype, const char **errmsg)
{
	long long ret = (int64_t)vmret;
	const char *tmp_errmsg;
	enum constraint_error_type tmp_errtype;
	int idx;

	if (!errtype)
		errtype = &tmp_errtype;
	else
		*errtype = cet_no_error;
	if (!errmsg)
		errmsg = &tmp_errmsg;
	else
		*errmsg = "";

	if (ret >= 0 || ret < -4000)
		return 0;

	if (ret < -3000) { 		/* badtype check */
		idx = -(ret + 3000);
		*errtype = cet_bad_property_type;
	} else if (ret < -2000) {	/* exists check */
		idx = -(ret + 2000);
		*errtype = cet_missing_property;
	} else if (ret < -1000) { 	/* property check */
		idx = -(ret + 1000);
		*errtype = cet_property_constraint_failed;
	} else {	 		/* node constraint */
		idx = -ret;
		*errtype = cet_node_constraint_failed;
	}
	*errmsg = constraint_error_txt(*errtype);
	return idx;
}

static void check_node_single(struct yaml_dt_state *dt,
		       struct node *np, struct node *snp,
		       struct ebpf_dt_ctx *check_ctx)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *sdt = dtbchk->sdt;
	struct node *child;
	char namebuf[NODE_FULLNAME_MAX];
	int err, idx, count;
	uint64_t vmret;
	struct node *npc, *npt, *npcc;
	struct property *prop;
	struct ref *ref;
	const char *errmsg, *propname, *constraint, *category, *subtype;
	enum constraint_error_type errtype;
	const char *good = "", *bad = "", *emph = "", *marker = "";
	const char *reset = "", *constr = "";

	if ((dt->cfg.color == -1 && isatty(STDERR_FILENO)) ||
	     dt->cfg.color == 1) {
		good = GREEN;
		bad = RED;
		emph = WHITE;
		marker = YELLOW;
		constr = MAGENTA;
		reset = RESET;
	}

	/* now running check */
	vmret = ebpf_exec(&check_ctx->vm, np, 0, &err);
	if (err)
		dt_fatal(dt, "exec failed with code %d (%s)\n",
				err, strerror(-err));

	/* select errors means the node was not selected */
	if ((long long)vmret < -SELECT_BASE)
		goto cont;

	/* success; node passes validation */
	if (vmret == 0) {
		dt_info(dt, "%s%s:%s %s%s%s %sOK%s\n",
			marker, snp->name, reset,
			emph, dn_fullname(np, namebuf, sizeof(namebuf)),
			reset, good, reset);
		goto cont;
	}

	/* it's an error alright */
	idx = parse_constraint_ret(vmret, &errtype, &errmsg);

	dt_info(dt, "%s%s:%s %s%s%s %sFAIL (%lld)%s\n",
		marker, snp->name, reset,
		emph, dn_fullname(np, namebuf, sizeof(namebuf)),
		reset, bad, (long long)vmret, reset);

	snprintf(namebuf, sizeof(namebuf), "c-%d", idx);
	npt = node_get_child_by_name(to_tree(sdt), snp, "constraints", 0);
	npc = node_get_child_by_name(to_tree(sdt), npt, namebuf, 0);
	propname = dt_get_string(sdt, npc, "propname", 0, 0);
	constraint = dt_get_string(sdt, npc, "constraint", 0, 0);
	category = dt_get_string(sdt, npc, "category", 0, 0);
	(void)category;

	prop = dt_get_property(dt, np, propname, 0);
	ref = dt_get_ref(dt, prop, 0);

	switch (errtype) {
	case cet_no_error:
		break;
	case cet_bad_property_type:
		if (!ref || !propname)
			break;
		tree_warning_at_ref(to_tree(dt), ref,
				"property %s%s%s has bad type\n",
				marker, propname, reset);
		break;
	case cet_missing_property:
		if (!np || !propname)
			break;
		tree_warning_at_node(to_tree(dt), np,
				"property %s%s%s is missing\n",
				marker, propname, reset);
		break;
	case cet_property_constraint_failed:
		if (!ref || !propname || !npc)
			break;

		/* it's a rule, so count rule subconstraints */
		if (!constraint) {
			npcc = node_get_child_by_name(to_tree(sdt), npc,
					"subconstraints", 0);
			count = 0;
			if (!npcc)
				break;

			for_each_child_of_node(npcc, npt) {
				subtype = dt_get_string(sdt,
						npt, "subtype", 0, 0);
				if (subtype && !strcmp(subtype, "check-rule"))
					count++;
			}

			for_each_child_of_node(npcc, npt) {

				subtype = dt_get_string(sdt,
						npt, "subtype", 0, 0);
				if (!subtype || strcmp(subtype, "check-rule"))
					continue;
				constraint = dt_get_string(sdt,
						npt, "constraint", 0, 0);
				if (!constraint)
					continue;

				tree_warning_at_ref(to_tree(dt), ref,
						"%s%s%s %s constraint:%s%s%s%s\n",
						marker, propname, reset,
						count == 1 ? "failed" : "possibly-failed",
						!strchr(constraint, '\n') ? " " : "\n",
						constr, constraint, reset);
			}

		} else {
			tree_warning_at_ref(to_tree(dt), ref,
					"%s%s%s failed constraint:%s%s%s%s\n",
					marker, propname, reset,
					!strchr(constraint, '\n') ? " " : "\n",
					constr, constraint, reset);
		}
		break;
	case cet_node_constraint_failed:
		if (!np || !constraint)
			break;
		tree_warning_at_node(to_tree(dt), np,
				"%s%s%s failed constraint:%s%s%s%s\n",
				marker, np->name, reset,
				!strchr(constraint, '\n') ? " " : "\n",
				constr, constraint, reset);
		break;
	default:
		break;
	}

cont:
	for_each_child_of_node(np, child)
		check_node_single(dt, child, snp, check_ctx);
}

int dtbchk_check(struct yaml_dt_state *dt)
{
	struct dtb_check_state *dtbchk = to_dtbchk(dt);
	struct yaml_dt_state *sdt = dtbchk->sdt;
	struct node *snp, *sroot = tree_root(to_tree(sdt));
	size_t check_size;
	const char *check;
	struct ebpf_dt_ctx check_ctx;
	struct ebpf_vm *check_vm;
	struct node *npchk;
	int ret;

	if (!sroot)
		return 0;

	/* check each rule in the root */
	for_each_child_of_node(sroot, snp) {

		npchk = node_get_child_by_name(to_tree(sdt), snp,
				"check-rule-output", 0);
		check = dt_get_binary(sdt, npchk, "ebpf", 0, 0, &check_size);

		/* can't check this node */
		if (!check)
			continue;

		check_ctx.dt = dt;
		check_vm = &check_ctx.vm;

		ret = ebpf_setup(check_vm, bpf_dt_cb, NULL, NULL, NULL);
		if (ret)
			dt_fatal(dt, "Failed to setup check vm ebpf\n");

		ret = ebpf_load_elf(check_vm, check, check_size);
		if (ret)
			dt_fatal(dt, "Failed to load check vm ebpf\n");

		check_node_single(dt, tree_root(to_tree(dt)), snp,
				&check_ctx);

		ebpf_cleanup(check_vm);

	}

	return 0;
}

#endif

static const struct yaml_dt_checker_ops dtb_checker_ops = {
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
