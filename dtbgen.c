/*
 * dtbgen.c - DTB generation
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

#ifdef __linux__
#define _GNU_SOURCE
#endif

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
#include <stdint.h>
#include <sys/time.h>
#ifdef __linux__
#include <linux/limits.h>
#else
#include <limits.h>
#endif

#include "list.h"

#include "utils.h"
#include "syexpr.h"

#include "dt.h"

#include "dtbgen.h"

struct dtb_node {
	struct dt_node dt;
	/* DTB generation */
	unsigned int phandle;
	bool marker : 1;	/* generic marker */
};
#define to_dtb_node(_n) 	\
	container_of(container_of(_n, struct dt_node, n), struct dtb_node, dt)

struct dtb_property {
	struct dt_property dt;
	void *data;
	int size;
	unsigned int offset;		/* DTB offset to the string table */
};
#define to_dtb_prop(_p) 	\
	container_of(container_of(_p, struct dt_property, p), struct dtb_property, dt)

struct dtb_ref {
	struct dt_ref dt;
	unsigned int offset;
	struct list_head ovnode;	/* when resolving overlays */
};
#define to_dtb_ref(_r) 	\
	container_of(container_of(_r, struct dt_ref, r), struct dtb_ref, dt)

enum dt_data_area {
	dt_struct,
	dt_strings,
	dt_mem_rsvmap,
	dt_area_max = dt_mem_rsvmap,
};

/* all refs in the list contain exact match for ref->data */
struct fixup {
	struct list_head node;
	struct list_head refs;
};

struct dtb_emit_state {
	/* DTB generation state */
	unsigned int next_phandle;
	struct property *memreserve_prop;

	struct {
		void *data;
		unsigned int alloc;
		unsigned int size;
	} area[dt_area_max + 1];

	struct list_head fixups;
};

#define to_dtb(_dt) ((struct dtb_emit_state *)(_dt)->emitter_state)

static void dtb_dump(struct yaml_dt_state *dt);

static struct ref *dtb_ref_alloc(struct tree *t, enum ref_type type,
				 const void *data, int len, const char *xtag)
{
	struct ref *ref;

	ref = yaml_dt_ref_alloc(t, type, data, len, xtag,
			sizeof(struct dtb_ref));
	to_dtb_ref(ref)->offset = -1;

	return ref;
}

static void dtb_ref_free(struct tree *t, struct ref *ref)
{
	yaml_dt_ref_free(t, ref);
}

static struct property *dtb_prop_alloc(struct tree *t, const char *name)
{
	struct dtb_property *dtbprop;
	struct property *prop;

	prop = yaml_dt_prop_alloc(t, name, sizeof(*dtbprop));

	dtbprop = to_dtb_prop(prop);
	dtbprop->offset = -1;

	return prop;
}

static void dtb_prop_free(struct tree *t, struct property *prop)
{
	if (to_dtb_prop(prop)->data)
		free(to_dtb_prop(prop)->data);

	yaml_dt_prop_free(t, prop);
}

static struct label *dtb_label_alloc(struct tree *t, const char *name)
{
	return yaml_dt_label_alloc(t, name, sizeof(struct dt_label));
}

static void dtb_label_free(struct tree *t, struct label *l)
{
	yaml_dt_label_free(t, l);
}

static struct node *dtb_node_alloc(struct tree *t, const char *name,
				   const char *label)
{
	struct node *np;
	struct dtb_node *dtbnp;

	np = yaml_dt_node_alloc(t, name, label, sizeof(*dtbnp));

	dtbnp = to_dtb_node(np);
	dtbnp->phandle = 0;
	dtbnp->marker = false;

	return np;
}

static void dtb_node_free(struct tree *t, struct node *np)
{
	yaml_dt_node_free(t, np);
}

static const struct tree_ops dtb_tree_ops = {
	.ref_alloc		= dtb_ref_alloc,
	.ref_free		= dtb_ref_free,
	.prop_alloc		= dtb_prop_alloc,
	.prop_free		= dtb_prop_free,
	.label_alloc		= dtb_label_alloc,
	.label_free		= dtb_label_free,
	.node_alloc		= dtb_node_alloc,
	.node_free		= dtb_node_free,
	.debugf			= yaml_dt_tree_debugf,
	.error_at_node		= yaml_dt_tree_error_at_node,
	.error_at_property	= yaml_dt_tree_error_at_property,
	.error_at_ref		= yaml_dt_tree_error_at_ref,
	.error_at_label		= yaml_dt_tree_error_at_label,
};

static void prop_set_data(struct property *prop, bool append,
			    const void *data, int size,
			    bool append_zero, int offset)
{
	struct dtb_property *dtbprop = to_dtb_prop(prop);
	void *newdata;
	int newsize;

	/* direct set data */
	if (offset >= 0) {
		assert(offset + size <= dtbprop->size);
		assert(dtbprop->data);
		memcpy(dtbprop->data + offset, data, size);
		return;
	}

	if (!append && dtbprop->data) {
		free(dtbprop->data);
		dtbprop->size = 0;
	}

	newsize = dtbprop->size + size + (append_zero ? 1 : 0);
	if (newsize > 0) {
		newdata = malloc(newsize);
		assert(newdata);
		if (dtbprop->data && dtbprop->size)
			memcpy(newdata, dtbprop->data, dtbprop->size);
		memcpy(newdata + dtbprop->size, data, size);
		if (append_zero)
			*((char *)newdata + dtbprop->size + size) = '\0';
		if (dtbprop->data)
			free(dtbprop->data);
		dtbprop->data = newdata;
		dtbprop->size = newsize;
	} else {
		dtbprop->data = NULL;
		dtbprop->size = 0;
	}
}

static void prop_append(struct property *prop, const void *data,
			  int size, bool append_zero)
{
	prop_set_data(prop, true, data, size, append_zero, -1);
}

static void prop_replace(struct property *prop, const void *data,
			   int size, int offset)
{
	prop_set_data(prop, false, data, size, false, offset);
}

#define RF_LABELS	(1 << 0)
#define RF_PHANDLES	(1 << 1)
#define RF_PATHS	(1 << 2)
#define RF_CONTENT	(1 << 3)

static void ref_resolve(struct yaml_dt_state *dt, struct ref *ref)
{
	struct node *np;
	struct property *prop;
	struct dtb_property *dtbprop;
	uint8_t val8;
	fdt16_t val16;
	fdt32_t val32;
	fdt64_t val64;
	const void *data = NULL;
	int size = 0;
	bool append_0 = false;
	fdt32_t phandlet = 0;
	char namebuf[NODE_FULLNAME_MAX];
	const char *tag = NULL;
	char *refname;
	int refnamelen;
	void *output_data = NULL;
	int err;

	prop = ref->prop;
	assert(prop);
	dtbprop = to_dtb_prop(prop);

	data = NULL;
	size = 0;

	/* get tag */
	tag = ref->xtag;
	if (!tag)
		tag = ref->xtag_builtin;

	/* 60 bytes for a display purposes should be enough */
	refnamelen = ref->len > 60 ? 60 : ref->len;
	refname = alloca(refnamelen + 1);
	memcpy(refname, ref->data, refnamelen);
	refname[refnamelen] = '\0';

	err = dt_resolve_ref(dt, ref);
	if (err != 0) {
		if (ref->type == r_anchor || ref->type == r_path) {
			tree_error_at_ref(to_tree(dt), ref,
				"can't resolve reference to %s %s\n",
				refname[0] == '/' ? "path" : "label",
				refname);
			return;
		}
		if (err == -EINVAL) {
			tree_error_at_ref(to_tree(dt), ref, "Invalid %s\n",
				refname);
			return;
		}
		if (err == -ERANGE) {
			tree_error_at_ref(to_tree(dt), ref, "Invalid range on %s\n",
				refname);
			return;
		}
	}

	switch (ref->type) {
	case r_anchor:
		np = to_dt_ref(ref)->npref;
		phandlet = np ? cpu_to_fdt32(to_dtb_node(np)->phandle) :
				0xffffffff;
		data = &phandlet;
		size = sizeof(phandlet);
		break;

	case r_path:
		np = to_dt_ref(ref)->npref;
		if (np) {
			data = dn_fullname(np, namebuf, sizeof(namebuf));
			size = strlen(data) + 1;
		} else {
			data = NULL;
			size = 0;
		}
		break;

	case r_scalar:
		tag = to_dt_ref(ref)->tag;

		/* special memreserve handling */
		if (!strcmp(prop->name, "/memreserve/")) {
			if (!to_dt_ref(ref)->is_int) {
				tree_error_at_ref(to_tree(dt), ref,
					"Invalid /memreserve/ property %s\n",
					refname);
				return;
			}
			tag = "!uint64";
		}

		if (!strcmp(tag,  "!int") || !strcmp(tag,  "!int32") ||
		    !strcmp(tag, "!uint") || !strcmp(tag, "!uint32")) {
			val32 = cpu_to_fdt32((uint32_t)to_dt_ref(ref)->val);
			data = &val32;
			size = sizeof(val32);
		} else if (!strcmp(tag, "!int8") || !strcmp(tag, "!uint8")) {
			val8 = (uint8_t)to_dt_ref(ref)->val;
			data = &val8;
			size = sizeof(val8);
		} else if (!strcmp(tag, "!int16") || !strcmp(tag, "!uint16")) {
			val16 = cpu_to_fdt16((uint16_t)to_dt_ref(ref)->val);
			data = &val16;
			size = sizeof(val16);
		} else if (!strcmp(tag, "!int64") || !strcmp(tag, "!uint64")) {
			val64 = cpu_to_fdt64((uint64_t)to_dt_ref(ref)->val);
			data = &val64;
			size = sizeof(val64);
		} else if (!strcmp(tag, "!str")) {
			data = ref->data;
			size = ref->len;
			append_0 = true;
		} else if (!strcmp(tag, "!bool")) {
			data = NULL;
			size = 0;
			if (!to_dt_ref(ref)->val)
				dt_warning_at(dt, &to_dt_ref(ref)->m,
					      "False boolean will not be"
					      " present in DTB output; %s\n",
					      refname);
		} else if (!strcmp(tag, "!null")) {
			data = NULL;
			size = 0;
		} else if (!strcmp(tag, "!char")) {
			val32 = cpu_to_fdt32((uint32_t)to_dt_ref(ref)->val);
			data = &val32;
			size = sizeof(val32);
		} else {
			tree_error_at_ref(to_tree(dt), ref,
				"Unsupported tag %s: %s\n", tag,
				refname);
			return;
		}

		break;

	default:
		/* nothing */
		break;
	}

	assert(tag != NULL);
	to_dtb_ref(ref)->offset = dtbprop->size;

	prop_append(prop, data, size, append_0);

	if (output_data)
		free(output_data);
}

static void resolve(struct yaml_dt_state *dt, struct node *npt,
		  unsigned int flags)
{
	struct dtb_emit_state *dtb = to_dtb(dt);
	struct node *child;
	struct ref *ref, *refn;
	struct node *np;
	struct property *prop;
	struct label *l;
	fdt32_t phandlet;
	char namebuf[2][NODE_FULLNAME_MAX];
	char refname[60 + 1];
	int refnamelen;

	if ((flags & RF_LABELS) && !to_dtb_node(npt)->phandle &&
			!list_empty(&npt->labels)) {

		for_each_label_of_node(npt, l)
			dt_debug(dt, "label: assigned phandle %u at @%s label %s\n",
					to_dtb_node(npt)->phandle,
					dn_fullname(npt, &namebuf[0][0], sizeof(namebuf[0])),
					l->label);
		to_dtb_node(npt)->phandle = dtb->next_phandle++;
		assert(dtb->next_phandle != 0 && dtb->next_phandle != -1);
	}

	for_each_property_of_node(npt, prop) {

		for_each_ref_of_property_safe(prop, ref, refn) {

			if (flags & RF_CONTENT)
				ref_resolve(dt, ref);

			/* only handle anchors here */
			if (!((flags & RF_PHANDLES) && ref->type == r_anchor))
				continue;

			if (ref->len > 0 && *(char *)ref->data == '/')
				np = node_lookup_by_path(to_tree(dt), ref->data, ref->len);
			else
				np = node_lookup_by_label(to_tree(dt), ref->data, ref->len);

			if (!np && !dt->cfg.object) {
				refnamelen = ref->len > sizeof(refname) ? sizeof(refname) : ref->len;
				memcpy(refname, ref->data, refnamelen);
				refname[refnamelen] = '\0';

				tree_error_at_ref(to_tree(dt), ref,
					"can't lookup %s %s\n",
					refname[0] == '/' ? "path" : "label",
					refname);

				continue;
			}

			if (np) {
				if (!to_dtb_node(np)->phandle) {
					to_dtb_node(np)->phandle = dtb->next_phandle++;
					assert(dtb->next_phandle != 0 && dtb->next_phandle != -1);
					for_each_label_of_node(np, l)
						dt_debug(dt, "assigned phandle %u at @%s label %s (@%s prop %s offset=%u)\n",
							to_dtb_node(np)->phandle,
							dn_fullname(np, &namebuf[0][0], sizeof(namebuf[0])),
							l->label,
							dn_fullname(npt, &namebuf[1][0], sizeof(namebuf[1])),
							prop->name, to_dtb_prop(prop)->offset);
				}

				phandlet = to_dtb_node(np)->phandle;

				dt_debug(dt, "resolved reference %s at @%s (%u)\n",
					prop->name,
					dn_fullname(prop->np, &namebuf[0][0], sizeof(namebuf[0])),
					to_dtb_node(np)->phandle);
			} else {
				phandlet = 0xffffffff;

				dt_debug(dt, "unresolved external reference %s at @%s\n",
					prop->name,
					dn_fullname(prop->np, &namebuf[0][0], sizeof(namebuf[0])));
			}

			phandlet = cpu_to_fdt32(phandlet);
			assert(to_dtb_prop(prop)->size >=
					to_dtb_ref(ref)->offset + sizeof(fdt32_t));
			prop_replace(prop, &phandlet, sizeof(fdt32_t),
					to_dtb_ref(ref)->offset);

		}
	}

	for_each_child_of_node(npt, child)
		resolve(dt, child, flags);
}

static bool is_node_referenced(struct yaml_dt_state *dt,
				struct node *np, struct node *npref)
{
	struct node *child;
	struct property *prop;
	struct ref *ref;
	bool ret;

	for_each_property_of_node(np, prop) {

		for_each_ref_of_property(prop, ref) {
			if (ref->type != r_anchor ||
			    !to_dt_ref(ref)->is_resolved)
				continue;
			if (to_dt_ref(ref)->npref == npref)
				return true;
		}
	}

	for_each_child_of_node(np, child) {
		ret = is_node_referenced(dt, child, npref);
		if (ret)
			return true;
	}
	return false;
}

static void append_auto_properties(struct yaml_dt_state *dt, struct node *np)
{
	struct dtb_node *dtbnp = to_dtb_node(np);
	struct node *child;
	struct property *prop;
	fdt32_t phandle;

	if (dtbnp->phandle != 0 &&
	   (dt->cfg.object || dt->cfg.symbols ||
	    is_node_referenced(dt, tree_root(to_tree(dt)), np))) {
		prop = prop_alloc(to_tree(dt), "phandle");

		phandle = cpu_to_fdt32(dtbnp->phandle);

		prop_append(prop, &phandle, sizeof(fdt32_t), false);

		prop->np = np;
		list_add_tail(&prop->node, &np->properties);
	}

	for_each_child_of_node(np, child)
		append_auto_properties(dt, child);
}

static void dtb_append_auto_properties(struct yaml_dt_state *dt)
{
	if (!tree_root(to_tree(dt)))
		return;

	append_auto_properties(dt, tree_root(to_tree(dt)));
}

static void add_symbols(struct yaml_dt_state *dt, struct node *np,
		struct node **symbols_np)
{
	struct node *child;
	struct property *prop;
	struct label *l;
	char namebuf[NODE_FULLNAME_MAX];
	const char *name;

	for_each_label_of_node(np, l) {

		/* do not output autogenerated labels */
		if (!strncmp(l->label, "yaml_pseudo__",
		    strlen("yaml_pseudo__")))
			continue;

		prop = prop_alloc(to_tree(dt), l->label);

		name = dn_fullname(np, namebuf, sizeof(namebuf));

		prop_append(prop, name, strlen(name), true);

		/* if it doesn't exist add __symbols__ */
		if (!*symbols_np) {
			*symbols_np = node_alloc(to_tree(dt), "__symbols__", NULL);
			(*symbols_np)->parent = tree_root(to_tree(dt));
			list_add_tail(&(*symbols_np)->node, &tree_root(to_tree(dt))->children);
		}

		prop->np = *symbols_np;
		list_add_tail(&prop->node, &(*symbols_np)->properties);
	}

	for_each_child_of_node(np, child) {

		/* do not enter generated nodes */
		if (!strcmp(child->name, "__symbols__") ||
		    !strcmp(child->name, "__fixups__") ||
		    !strcmp(child->name, "__local_fixups__"))
		    continue;

		add_symbols(dt, child, symbols_np);
	}
}

static void dtb_add_symbols(struct yaml_dt_state *dt)
{
	struct node *symbols_np = NULL;

	if (!tree_root(to_tree(dt)))
		return;

	add_symbols(dt, tree_root(to_tree(dt)), &symbols_np);
}

static void add_fixup(struct yaml_dt_state *dt, struct ref *ref)
{
	struct dtb_emit_state *dtb = to_dtb(dt);
	struct fixup *f;
	struct ref *reft;
	struct dtb_ref *dtbref = to_dtb_ref(ref);
	struct dtb_ref *dtbreft;

	/* first try to reuse */
	list_for_each_entry(f, &dtb->fixups, node) {
		list_for_each_entry(dtbreft, &f->refs, ovnode) {
			reft = &dtbreft->dt.r;
			if (ref->len == reft->len &&
			    !memcmp(ref->data, reft->data, ref->len)) {
				list_add_tail(&dtbref->ovnode, &f->refs);
				return;
			}
		}
	}

	f = malloc(sizeof(*f));
	assert(f);
	memset(f, 0, sizeof(*f));
	INIT_LIST_HEAD(&f->refs);
	list_add_tail(&dtbref->ovnode, &f->refs);
	list_add_tail(&f->node, &dtb->fixups);
}

static void add_fixups(struct yaml_dt_state *dt, struct node *np)
{
	struct node *child;
	struct property *prop;
	struct ref *ref;
	char refname[60 + 1];
	int refnamelen;

	for_each_property_of_node(np, prop) {

		for_each_ref_of_property(prop, ref) {

			/* adding anchors that were unresolved only */
			if (ref->type != r_anchor || to_dt_ref(ref)->is_resolved)
				continue;

			add_fixup(dt, ref);

			/* 60 bytes for a display purposes should be enough */
			refnamelen = ref->len > sizeof(refname) ? sizeof(refname) : ref->len;
			memcpy(refname, ref->data, refnamelen);
			refname[refnamelen] = '\0';

			dt_debug(dt, "generate fixup for %s (prop %s, offset %u)\n",
				refname, ref->prop->name, to_dtb_ref(ref)->offset);

		}
	}

	for_each_child_of_node(np, child) {

		/* do not enter generated nodes */
		if (!strcmp(child->name, "__symbols__") ||
		    !strcmp(child->name, "__fixups__") ||
		    !strcmp(child->name, "__local_fixups__"))
		    continue;

		add_fixups(dt, child);
	}
}

static void dtb_add_fixups(struct yaml_dt_state *dt)
{
	struct dtb_emit_state *dtb = to_dtb(dt);
	struct node *np;
	struct property *prop;
	struct dtb_ref *dtbref;
	struct ref *ref, *reft;
	struct fixup *f;
	int ret;
	char *name;
	char namebuf[NODE_FULLNAME_MAX];

	if (!tree_root(to_tree(dt)))
		return;

	add_fixups(dt, tree_root(to_tree(dt)));

	if (list_empty(&dtb->fixups))
		return;

	/* we have fixups to add, add them */
	np = node_alloc(to_tree(dt), "__fixups__", NULL);
	np->parent = tree_root(to_tree(dt));
	list_add_tail(&np->node, &tree_root(to_tree(dt))->children);

	list_for_each_entry(f, &dtb->fixups, node) {

		prop = NULL;
		list_for_each_entry(dtbref, &f->refs, ovnode) {

			ref = &dtbref->dt.r;

			/* create property if fist */
			if (!prop) {
				name = malloc(ref->len + 1);
				assert(name);
				memcpy(name, ref->data, ref->len);
				name[ref->len] = '\0';

				prop = prop_alloc(to_tree(dt), name);
				prop->np = np;
				list_add_tail(&prop->node, &np->properties);

				free(name);
				name = NULL;
			}

			ret = asprintf(&name, "%s:%s:%d",
				dn_fullname(ref->prop->np, namebuf, sizeof(namebuf)),
				ref->prop->name, dtbref->offset);
			assert(ret > 0);

			reft = ref_alloc(to_tree(dt), r_scalar, name, strlen(name), "!str");
			reft->prop = prop;
			list_add_tail(&reft->node, &prop->refs);

			prop_append(prop, reft->data, reft->len, true);

			free(name);
		}
	}
}

static void add_local_fixup(struct yaml_dt_state *dt, struct ref *ref,
			    struct node **fixups_np)
{
	struct dtb_emit_state *dtb = to_dtb(dt);
	struct node *np, *npt;
	struct property *prop;
	struct ref *reft;
	char namebuf[NODE_FULLNAME_MAX];
	char *s, *sn;
	bool found;
	char numbuf[16];
	fdt32_t offset;

	(void)dtb;

	/* start by the fixups node */
	np = *fixups_np;
	if (!np) {
		/* create the local fixups node */
		np = node_alloc(to_tree(dt), "__local_fixups__", NULL);
		np->parent = tree_root(to_tree(dt));
		list_add_tail(&np->node, &tree_root(to_tree(dt))->children);
		*fixups_np = np;
	}

	/* get the full name */
	dn_fullname(ref->prop->np, namebuf, sizeof(namebuf));

	/* build nodes if not found */
	for (s = namebuf + 1; *s; s = sn ? sn : s + strlen(s)) {

		sn = strchr(s, '/');
		if (sn)
			*sn++ = '\0';

		found = false;
		for_each_child_of_node(np, npt) {
			if (!strcmp(npt->name, s)) {
				found = true;
				break;
			}
		}

		/* not found? create */
		if (!found) {
			npt = node_alloc(to_tree(dt), s, NULL);
			npt->parent = np;
			list_add_tail(&npt->node, &np->children);
		}

		np = npt;
	}

	found = false;
	for_each_property_of_node(np, prop) {

		if (!strcmp(prop->name, ref->prop->name)) {
			found = true;
			break;
		}
	}

	/* not found? create */
	if (!found) {
		prop = prop_alloc(to_tree(dt), ref->prop->name);
		prop->np = np;
		list_add_tail(&prop->node, &np->properties);
	}

	/* create ref */
	snprintf(numbuf, sizeof(numbuf), "%u", to_dtb_ref(ref)->offset);
	reft = ref_alloc(to_tree(dt), r_scalar, numbuf, strlen(numbuf), "!int");
	reft->prop = prop;
	list_add_tail(&reft->node, &prop->refs);

	/* append offset */
	offset = cpu_to_fdt32(to_dtb_ref(ref)->offset);
	prop_append(prop, &offset, sizeof(fdt32_t), false);
}

static void add_local_fixups(struct yaml_dt_state *dt, struct node *np,
		struct node **fixups_np)
{
	struct node *child;
	struct property *prop;
	struct ref *ref;
	char refname[60 + 1];
	int refnamelen;

	for_each_property_of_node(np, prop) {

		for_each_ref_of_property(prop, ref) {

			/* adding anchors that were unresolved only */
			if (ref->type != r_anchor || !to_dt_ref(ref)->is_resolved)
				continue;

			add_local_fixup(dt, ref, fixups_np);

			/* 60 bytes for a display purposes should be enough */
			refnamelen = ref->len > sizeof(refname) ? sizeof(refname) : ref->len;
			memcpy(refname, ref->data, refnamelen);
			refname[refnamelen] = '\0';

			dt_debug(dt, "generate local fixup for %s (prop %s, offset %u)\n",
				refname, ref->prop->name, to_dtb_ref(ref)->offset);

		}
	}

	for_each_child_of_node(np, child) {

		/* do not enter generated nodes */
		if (!strcmp(child->name, "__symbols__") ||
		    !strcmp(child->name, "__fixups__") ||
		    !strcmp(child->name, "__local_fixups__"))
		    continue;

		add_local_fixups(dt, child, fixups_np);
	}
}

static void dtb_add_local_fixups(struct yaml_dt_state *dt)
{
	struct node *np;

	if (!tree_root(to_tree(dt)))
		return;

	np = NULL;
	add_local_fixups(dt, tree_root(to_tree(dt)), &np);
}

static void move_tree_contents(struct yaml_dt_state *dt,
			       struct node *tonp, struct node *fromnp)
{
	struct node *child, *childn;
	struct property *prop, *propn;

	for_each_property_of_node_safe_withdel(fromnp, prop, propn) {
		list_del(&prop->node);
		prop->np = tonp;
		list_add_tail(&prop->node, &tonp->properties);
	}

	for_each_child_of_node_safe_withdel(fromnp, child, childn) {
		list_del(&child->node);
		child->parent = tonp;
		list_add_tail(&child->node, &tonp->children);
	}
}

static void dtb_create_overlay_structure(struct yaml_dt_state *dt)
{
	struct node *old_root, *root, *ov, *ovin;
	struct node *np, *npn, *npref;
	struct list_head *ref_nodes = tree_ref_nodes(to_tree(dt));
	struct property *prop;
	struct ref *ref;
	char namebuf[32];
	int next_frag = 1;

	/* keep old root */
	old_root = tree_root(to_tree(dt));

	/* create empty new root */
	root = node_alloc(to_tree(dt), "", NULL);
	tree_set_root(to_tree(dt), root);

	/* create an overlay fragment for the root */
	if (old_root && (!list_empty(&old_root->children) ||
			 !list_empty(&old_root->properties))) {

		snprintf(namebuf, sizeof(namebuf), "fragment@%d", next_frag++);
		ov = node_alloc(to_tree(dt), namebuf, NULL);
		ov->parent = root;
		list_add_tail(&ov->node, &ov->parent->children);

		prop = prop_alloc(to_tree(dt), "target-path");
		prop->np = ov;
		list_add_tail(&prop->node, &ov->properties);

		ref = ref_alloc(to_tree(dt), r_scalar, "/", 1, "!str");
		ref->prop = prop;
		list_add_tail(&ref->node, &prop->refs);

		ovin = node_alloc(to_tree(dt), "__overlay__", NULL);

		ovin->parent = ov;
		list_add_tail(&ovin->node, &ovin->parent->children);

		move_tree_contents(dt, ovin, old_root);
	}

	/* move all unresolved references to new overlay fragments */

	ref_nodes = tree_ref_nodes(to_tree(dt));
	list_for_each_entry_safe(np, npn, ref_nodes, node) {

		npref = node_lookup(to_tree(dt), np->name, -1);
		/* if it is found, no need to do anything */
		if (npref)
			continue;

		snprintf(namebuf, sizeof(namebuf), "fragment@%d", next_frag++);
		ov = node_alloc(to_tree(dt), namebuf, NULL);
		ov->parent = root;
		list_add_tail(&ov->node, &ov->parent->children);

		if (np->name[0] == '*') {
			prop = prop_alloc(to_tree(dt), "target");
			ref = ref_alloc(to_tree(dt), r_anchor, np->name + 1,
					strlen(np->name) - 1, "!anchor");
		} else {
			prop = prop_alloc(to_tree(dt), "target-path");
			ref = ref_alloc(to_tree(dt), r_scalar, np->name,
					strlen(np->name), "!str");
		}
		prop->np = ov;
		list_add_tail(&prop->node, &ov->properties);

		ref->prop = prop;
		list_add_tail(&ref->node, &prop->refs);

		ovin = node_alloc(to_tree(dt), "__overlay__", NULL);

		ovin->parent = ov;
		list_add_tail(&ovin->node, &ovin->parent->children);

		move_tree_contents(dt, ovin, np);

		list_del(&np->node);
		node_free(to_tree(dt), np);
	}

	if (old_root)
		node_free(to_tree(dt), old_root);
}

static void dtb_handle_special_properties(struct yaml_dt_state *dt,
					  struct node *np)
{
	struct dtb_emit_state *dtb = to_dtb(dt);
	struct property *prop, *propn;
	struct dtb_property *dtbprop;
	struct node *child;
	struct ref *ref;
	struct node *root;
	bool resolve_error;
	bool is_memreserve;
	bool is_name;

	if (!np)
		return;

	assert(dt);

	root = tree_root(to_tree(dt));

	for_each_property_of_node_safe(np, prop, propn) {

		is_memreserve = np == root &&
				!strcmp(prop->name, "/memreserve/");
		is_name = dt->cfg.compatible && !strcmp(prop->name, "name");

		dtbprop = to_dtb_prop(prop);

		resolve_error = false;
		if (is_memreserve || is_name) {
			for_each_ref_of_property(prop, ref) {
				ref_resolve(dt, ref);
				if (!to_dt_ref(ref)->is_resolved)
					resolve_error = true;
			}
		}

		/* detach and keep memreserve property */
		if (is_memreserve) {

			list_del(&prop->node);
			prop->np = NULL;

			if (resolve_error ||
			    dtbprop->size % (2 * sizeof(uint64_t))) {
				tree_error_at_property(to_tree(dt), prop,
						"Invalid memreserve property\n");
				prop_free(to_tree(dt), prop);
				continue;
			}

			if (dtb->memreserve_prop) {
				prop_append(dtb->memreserve_prop,
					    dtbprop->data, dtbprop->size,
					    false);
				prop_free(to_tree(dt), prop);
			} else
				dtb->memreserve_prop = prop;
		} else if (is_name) {
			list_del(&prop->node);
			prop->np = NULL;
		}
	}

	for_each_child_of_node(np, child)
		dtb_handle_special_properties(dt, child);
}

static void dtb_resolve_phandle_refs(struct yaml_dt_state *dt)
{
	struct node *root;

	assert(dt);

	root = tree_root(to_tree(dt));
	if (!root)
		return;

	if (dt->cfg.compatible) {
		resolve(dt, root, RF_CONTENT);
		resolve(dt, root, RF_PHANDLES);
		resolve(dt, root, RF_LABELS);
		resolve(dt, root, RF_PATHS);
	} else
		resolve(dt, root, RF_CONTENT | RF_LABELS |
				  RF_PHANDLES | RF_PATHS);
}

static void dt_emit_data(struct yaml_dt_state *dt,
		enum dt_data_area area, const void *data,
		unsigned int size, unsigned int align)
{
	struct dtb_emit_state *dtb = to_dtb(dt);
	unsigned int asize = ALIGN(size, align);
	unsigned int *sizep, *allocp;
	void **datap;
	void *p;

	assert(area <= dt_area_max);

	sizep  = &dtb->area[area].size;
	allocp = &dtb->area[area].alloc;
	datap  = &dtb->area[area].data;

	if (align > 0)
		asize = ALIGN(size, align);
	else
		asize = size;

	/* loop to work even with huge emit sizes */
	while (*sizep + asize >= *allocp) {
		/* start allocation at 2K*2 = 4K (minimum) */
		if (!*allocp)
			*allocp = 2048;
		*datap = realloc(*datap, *allocp * 2);
		assert(*datap);
		*allocp *= 2;
	}
	p = *datap + *sizep;
	if (size > 0) {
		memcpy(p, data, size);
		p += size;
	}
	if (asize > size) {
		memset(p, 0, asize - size);
		p += asize - size;
	}
	*sizep = p - *datap;
}

unsigned int dt_emit_get_size(struct yaml_dt_state *dt,
		enum dt_data_area area)
{
	struct dtb_emit_state *dtb = to_dtb(dt);

	assert(area <= dt_area_max);
	return dtb->area[area].size;
}

static void dt_emit_32(struct yaml_dt_state *dt,
		enum dt_data_area area,
		uint32_t val, bool align)
{
	fdt32_t fdt32 = cpu_to_fdt32(val);

	dt_emit_data(dt, area, &fdt32, sizeof(fdt32),
		     align ? sizeof(fdt32_t) : 0);
}

static void dt_emit_64(struct yaml_dt_state *dt,
		enum dt_data_area area,
		uint64_t val, bool align)
{
	fdt64_t fdt64 = cpu_to_fdt64(val);

	dt_emit_data(dt, area, &fdt64, sizeof(fdt64),
		     align ? sizeof(fdt64_t) : 0);
}

static void dt_emit_str(struct yaml_dt_state *dt,
		enum dt_data_area area,
		const char *str, bool align)
{
	unsigned int len = strlen(str) + 1;

	dt_emit_data(dt, area, str, len,
		     align ? sizeof(fdt32_t) : 0);
}

static int count_properties(struct yaml_dt_state *dt, struct node *np)
{
	struct property *prop;
	struct node *child;
	int count;

	count = 0;
	for_each_property_of_node(np, prop)
		count++;

	for_each_child_of_node(np, child)
		count += count_properties(dt, child);

	return count;
}

static int fill_prop_table(struct yaml_dt_state *dt, struct node *np,
			   struct property **propp, int pos)
{
	struct property *prop;
	struct node *child;

	for_each_property_of_node(np, prop)
		propp[pos++] = prop;

	for_each_child_of_node(np, child)
		pos = fill_prop_table(dt, child, propp, pos);

	return pos;
}

static int qsort_proplencmp(const void *arg1, const void *arg2)
{
	const struct property * const *propp1 = arg1;
	const struct property * const *propp2 = arg2;
	int len1, len2;

	len1 = strlen((*propp1)->name);
	len2 = strlen((*propp2)->name);
	return len1 > len2 ? -1 : (len1 < len2 ? 1 : 0);
}

static void dtb_build_string_table_minimal(struct yaml_dt_state *dt)
{
	struct node *root;
	int i, j, count, l1, l2;
	struct property **propt, *prop, *prop2;
	const char *s1, *s2;

	root = tree_root(to_tree(dt));
	/* count how many properties we have and get an array of pointers */
	count = count_properties(dt, root);
	if (count == 0)
		return;

	propt = malloc(count * sizeof(*propt));
	assert(propt);
	memset(propt, 0, count * sizeof(*propt));
	fill_prop_table(dt, root, propt, 0);

	dt_debug(dt, "#%d properties found\n", count);

	/* sort in ascending length order */
	qsort(propt, count, sizeof(*propt), qsort_proplencmp);

	for (i = 0; i < count; i++) {
		prop = propt[i];

		s1 = prop->name;
		l1 = strlen(s1);

		/* look for matching suffix */
		for (j = 0; j < i; j++) {
			prop2 = propt[j];

			s2 = prop2->name;
			l2 = strlen(s2);

			assert(l2 >= l1);

			/* matched? record offset */
			if (!strcmp(s1, s2 + l2 - l1)) {
				to_dtb_prop(prop)->offset =
					to_dtb_prop(prop2)->offset + l2 - l1;
				dt_debug(dt, "%s offset %d (reusing %s)\n",
					prop->name, to_dtb_prop(prop)->offset,
					prop2->name);
				break;
			}
		}

		/* no match */
		if (j >= i) {
			to_dtb_prop(prop)->offset = dt_emit_get_size(dt, dt_strings);
			dt_emit_str(dt, dt_strings, prop->name, false);

			dt_debug(dt, "%s offset %d\n", prop->name,
					to_dtb_prop(prop)->offset);
		}
	}

	free(propt);
}

static void build_string_table_compatible(struct yaml_dt_state *dt,
		struct node *np)
{
	struct dtb_emit_state *dtb = to_dtb(dt);
	struct node *child;
	struct property *prop;
	void *s, *e, *data;
	int l1, l2;

	if (!np)
		return;

	for_each_property_of_node(np, prop) {

		data = dtb->area[dt_strings].data;
		s = data;
		e = s + dtb->area[dt_strings].size;

		l1 = strlen(prop->name);
		while (s < e) {
			l2 = strlen(s);
			if (l1 <= l2 && !strcmp(s + l2 - l1, prop->name)) {
				s += l2 - l1;
				break;
			}
			s += strlen(s) + 1;
		}

		if (s >= e)
			s = e;

		to_dtb_prop(prop)->offset = (unsigned int)(s - data);

		if (to_dtb_prop(prop)->offset == dt_emit_get_size(dt, dt_strings))
			dt_emit_str(dt, dt_strings, prop->name, false);

		dt_debug(dt, "%s offset %d\n", prop->name, to_dtb_prop(prop)->offset);
	}

	for_each_child_of_node(np, child)
		build_string_table_compatible(dt, child);
}

static void dtb_build_string_table_compatible(struct yaml_dt_state *dt)
{
	build_string_table_compatible(dt, tree_root(to_tree(dt)));
}

static void dtb_build_string_table(struct yaml_dt_state *dt)
{
	if (!tree_root(to_tree(dt)))
		return;

	if (!dt->cfg.compatible)
		dtb_build_string_table_minimal(dt);
	else
		dtb_build_string_table_compatible(dt);
}

static void flatten_node(struct yaml_dt_state *dt, struct node *np)
{
	struct node *child;
	struct property *prop;
	struct dtb_property *dtbprop;

	dt_emit_32(dt, dt_struct, FDT_BEGIN_NODE, false);
	dt_emit_str(dt, dt_struct, np->name, true);

	for_each_property_of_node(np, prop) {

		dtbprop = to_dtb_prop(prop);

		dt_emit_32(dt, dt_struct, FDT_PROP, false);
		dt_emit_32(dt, dt_struct, dtbprop->size, false);

		assert(dtbprop->offset >= 0);
		dt_emit_32(dt, dt_struct, dtbprop->offset, false);

		dt_emit_data(dt, dt_struct, dtbprop->data, dtbprop->size,
			     sizeof(fdt32_t));
	}

	for_each_child_of_node(np, child)
		flatten_node(dt, child);

	dt_emit_32(dt, dt_struct, FDT_END_NODE, false);
}

static void dtb_flatten_node(struct yaml_dt_state *dt)
{
	if (!tree_root(to_tree(dt)))
		return;

	flatten_node(dt, tree_root(to_tree(dt)));
	dt_emit_32(dt, dt_struct, FDT_END, false);
}

static fdt32_t guess_boot_cpuid(struct yaml_dt_state *dt)
{
	struct node *root, *np, *child;
	struct property *prop;
	struct dtb_property *dtbprop;
	fdt32_t val;

	root = tree_root(to_tree(dt));
	if (!root)
		return 0;

	for_each_child_of_node(root, np) {
		if (strcmp(np->name, "cpus"))
			continue;

		for_each_child_of_node(np, child) {

			for_each_property_of_node(child, prop) {

				dtbprop = to_dtb_prop(prop);
				if (!strcmp(prop->name, "reg") &&
					dtbprop->size >= sizeof(fdt32_t)) {
					memcpy(&val, dtbprop->data, sizeof(val));
					return fdt32_to_cpu(val);
				}
			}

			/* compatible mode is wrong, but whatever */
			if (dt->cfg.compatible)
				return 0;
		}
	}

	return 0;
}

int dtb_setup(struct yaml_dt_state *dt)
{
	struct dtb_emit_state *dtb;

	dtb = malloc(sizeof(*dtb));
	assert(dtb);
	memset(dtb, 0, sizeof(*dtb));

	dtb->next_phandle = 1;
	dt->emitter_state = dtb;

	INIT_LIST_HEAD(&dtb->fixups);

	dt_debug(dt, "DTB emitter configuration:\n");
	dt_debug(dt, " compatible = %s\n", dt->cfg.compatible ? "true" : "false");
	dt_debug(dt, " object     = %s\n", dt->cfg.object ? "true" : "false");
	dt_debug(dt, " dts        = %s\n", dt->cfg.dts ? "true" : "false");
	dt_debug(dt, " symbols    = %s\n", dt->cfg.symbols ? "true" : "false");
	dt_debug(dt, " reserve    = %u\n", dt->cfg.reserve);
	dt_debug(dt, " space      = %u\n", dt->cfg.space);
	dt_debug(dt, " align      = %u\n", dt->cfg.align);
	dt_debug(dt, " pad        = %u\n", dt->cfg.pad);
	return 0;
}

void dtb_cleanup(struct yaml_dt_state *dt)
{
	struct dtb_emit_state *dtb = to_dtb(dt);
	enum dt_data_area area;
	struct fixup *f, *fn;

	/* cleanup local fixups */
	list_for_each_entry_safe(f, fn, &dtb->fixups, node) {
		list_del(&f->node);
		free(f);
	}

	for (area = 0; area <= dt_area_max; area++) {
		if (dtb->area[area].data)
			free(dtb->area[area].data);
	}

	if (dtb->memreserve_prop)
		prop_free(to_tree(dt), dtb->memreserve_prop);

	memset(dtb, 0, sizeof(*dtb));
	free(dtb);
}

static char *depth_pfx(struct yaml_dt_state *dt, char *buf, int size, int depth)
{
	snprintf(buf, size, "%*s", depth * 4, "");
	buf[size - 1] = '\0';
	return buf;
}

static int depth_pfx_size(struct yaml_dt_state *dt, int depth)
{
	return depth * 4 + 2;
}

static int depth_pfx_col(struct yaml_dt_state *dt, int depth)
{
	return depth * 4;
}

static bool is_cell_tag(const char *tag)
{
	return !strcmp(tag, "!int")   || !strcmp(tag, "!uint") ||
	       !strcmp(tag, "!int32") || !strcmp(tag, "!uint32");
}

static void dts_emit_prop(struct yaml_dt_state *dt, struct property *prop, int depth)
{
	FILE *fp = dt->output;
	struct ref *ref, *refn, *reft;
	int i, col, pos, count;
	const char *tag, *stag;
	bool output_name = false;
	bool found_true_bool = false;
	char *pfx;

	/* no data, don't print */
	if (list_empty(&prop->refs))
		return;

	pfx = depth_pfx(dt, alloca(depth_pfx_size(dt, depth)),
			depth_pfx_size(dt, depth), depth);

	col = depth_pfx_col(dt, depth) + strlen(prop->name);

	pos = 0;
	ref = first_ref_of_property(prop);
	for_each_ref_of_property_continue(prop, ref) {

		if (ref->type == r_seq_start ||
		    ref->type == r_seq_end ||
		    ref->type == r_null)
			continue;

		if (ref->type == r_anchor)
			stag = "!int";		/* paths are strings */
		else if (ref->type == r_path)
			stag = "!str";		/* paths are strings */
		else
			stag = to_dt_ref(ref)->tag;
		assert(stag != NULL);

		/* get run of the same type */
		count = 1;
		refn = ref;
		for_each_ref_of_property_continue(prop, refn) {

			if (ref == refn)
				continue;
			if (refn->type == r_seq_start ||
			    refn->type == r_seq_end ||
			    refn->type == r_null)
				continue;

			if (refn->type == r_anchor)
				tag = "!int";		/* paths are strings */
			else if (refn->type == r_path)
				tag = "!str";		/* paths are strings */
			else
				tag = to_dt_ref(refn)->tag;
			assert(tag != NULL);

			/* we're out? rewind back a bit */
			if ((!is_cell_tag(tag) || !is_cell_tag(stag)) &&
					strcmp(tag, stag))
				break;

			count++;
		}

		if (!strcmp(stag, "!bool")) {
			if (to_dt_ref(ref)->val)
				found_true_bool = true;
			goto skip;
		}

		if (!output_name) {
			fprintf(fp, "%s%s", pfx, prop->name);
			fprintf(fp, " =");
			col += strlen(" =");
			output_name = true;
		}

		if (pos > 0)
			fputc(',', fp);

		fputc(' ', fp);

		/* TODO handle !int<X> tags in the middle */
		if (!strcmp(stag, "!int16") || !strcmp(stag, "!uint16"))
			fprintf(fp, "/bits/ %d ", 16);
		else if (!strcmp(stag, "!int32") || !strcmp(stag, "!uint32"))
			fprintf(fp, "/bits/ %d ", 32);
		else if (!strcmp(stag, "!int64") || !strcmp(stag, "!uint64"))
			fprintf(fp, "/bits/ %d ", 64);

		if (!strcmp(stag, "!int") || !strcmp(stag, "!uint") ||
		    !strcmp(stag, "!int16") || !strcmp(stag, "!uint16") ||
		    !strcmp(stag, "!int32") || !strcmp(stag, "!uint32") ||
		    !strcmp(stag, "!int64") || !strcmp(stag, "!uint64") ||
		    !strcmp(stag, "!char"))
			fputc('<', fp);
		else if (!strcmp(stag, "!int8") || !strcmp(stag, "!uint8"))
			fputc('[', fp);

		i = 0;
		reft = list_entry(ref->node.prev, struct ref, node);
		for_each_ref_of_property_continue(prop, reft) {
			if (reft == refn)
				break;

			if (i > 0)
				fputc(' ', fp);

			if (reft->type == r_anchor || !strcmp(to_dt_ref(ref)->tag, "!pathref"))
				fputc('&', fp);

			if (reft->type == r_anchor && reft->len > 0 && *(char *)reft->data == '/')
				fputc('{', fp);

			if (!strcmp(stag, "!str") && strcmp(to_dt_ref(ref)->tag, "!pathref"))
				fputc('"', fp);

			if (!strcmp(stag, "!char"))
				fputc('\'', fp);

			if (!strcmp(stag, "!int8") || !strcmp(stag, "!uint8"))
				fprintf(fp, "%02x", to_dt_ref(reft)->is_int ?
					    (unsigned int)to_dt_ref(reft)->val & 0xff : 0);
			else
				fwrite(reft->data, reft->len, 1, fp);

			if (!strcmp(stag, "!char"))
				fputc('\'', fp);

			if (!strcmp(stag, "!str") && strcmp(to_dt_ref(ref)->tag, "!pathref"))
				fputc('"', fp);

			if (reft->type == r_anchor && reft->len > 0 && *(char *)reft->data == '/')
				fputc('}', fp);

			if ((!strcmp(stag, "!str") || !strcmp(stag, "!pathref")) &&
			    (i + 1) < count)
				fputc(',', fp);

			i++;
		}

		if (!strcmp(stag, "!int") || !strcmp(stag, "!uint") ||
		    !strcmp(stag, "!int16") || !strcmp(stag, "!uint16") ||
		    !strcmp(stag, "!int32") || !strcmp(stag, "!uint32") ||
		    !strcmp(stag, "!int64") || !strcmp(stag, "!uint64") ||
		    !strcmp(stag, "!char"))
			fputc('>', fp);
		else if (!strcmp(stag, "!int8") || !strcmp(stag, "!uint8"))
			fputc(']', fp);

              skip:
		pos += count;

		/* last one? break */
		if (&refn->node == &prop->refs)
			break;

		ref = list_entry(refn->node.prev, struct ref, node);
	}

	/* found a true boolean without any properties? */
	if (!output_name && found_true_bool) {
		fprintf(fp, "%s%s", pfx, prop->name);
		output_name = true;
	}

	if (output_name)
		fprintf(fp, ";\n");
}

static void dts_emit_node(struct yaml_dt_state *dt, struct node *np, int depth)
{
	FILE *fp = dt->output;
	struct node *child;
	struct property *prop;
	struct label *l;
	const char *name;
	int count;
	char *pfx;

	pfx = depth_pfx(dt, alloca(depth_pfx_size(dt, depth)),
			depth_pfx_size(dt, depth), depth);

	name = np->name;
	if (!name || strlen(name) == 0)
		name = "/";

	fprintf(fp, "%s", pfx);
	count = 0;
	for_each_label_of_node(np, l) {
		fprintf(fp, "%s%s:", count > 0 ? " " : "", l->label);
		count++;
	}
	fprintf(fp, "%s%s {\n", count > 0 ? " " : "", name);

	for_each_property_of_node(np, prop)
		dts_emit_prop(dt, prop, depth + 1);

	for_each_child_of_node(np, child)
		dts_emit_node(dt, child, depth + 1);

	fprintf(fp, "%s};\n", pfx);
}

static int dts_emit(struct yaml_dt_state *dt)
{
	struct dtb_emit_state *dtb = to_dtb(dt);
	FILE *fp = dt->output;
	struct property *prop;
	struct ref *ref;
	unsigned long long start, size;

	fprintf(fp, "/dts-v1/;\n");

	if (dt->cfg.object)
		fprintf(fp, "/plugin/;\n");

	prop = dtb->memreserve_prop;
	if (prop) {
		ref = first_ref_of_property(prop);
		for_each_ref_of_property_continue(prop, ref) {
			/* must have been already put into place */
			if (!to_dt_ref(ref)->is_int)
				dt_fatal(dt, "Illegal /memreserve/ property\n");
			start = to_dt_ref(ref)->val;

			/* get next */
			ref = list_entry(ref->node.next, struct ref, node);
			if (&ref->node == &prop->refs)
				dt_fatal(dt, "Illegal /memreserve/ property\n");

			/* must have been already put into place */
			if (!to_dt_ref(ref)->is_int)
				dt_fatal(dt, "Illegal /memreserve/ property\n");
			size = to_dt_ref(ref)->val;

			fprintf(fp, "/memreserve/ %08llx %08llx\n", start, size);
		}
	}

	if (tree_root(to_tree(dt)))
		dts_emit_node(dt, tree_root(to_tree(dt)), 0);

	return !ferror(dt->output) ? 0 : -1;
}

int dtb_emit(struct yaml_dt_state *dt)
{
	struct dtb_emit_state *dtb = to_dtb(dt);
	struct fdt_header fdth;
	struct property *prop;
	unsigned int totalsize, size_fdt_hdr, size_dt_strings, size_dt_struct,
		     size_mem_rsvmap;
	int size;
	unsigned int i, padsize;
	void *zeropad = NULL;

	dtb_handle_special_properties(dt, tree_root(to_tree(dt)));

	if (dt->cfg.object)
		dtb_create_overlay_structure(dt);

	tree_apply_ref_nodes(to_tree(dt), dt->cfg.object, dt->cfg.compatible);
	if (!dt->cfg.object)
		tree_detect_duplicate_labels(to_tree(dt), tree_root(to_tree(dt)));
	dtb_resolve_phandle_refs(dt);

	/* we can output the DTS here (we don't want the extra nodes) */
	if (dt->cfg.dts)
		return dts_emit(dt);

	dtb_append_auto_properties(dt);

	if (dt->cfg.object || dt->cfg.symbols)
		dtb_add_symbols(dt);

	if (dt->cfg.object) {
		dtb_add_fixups(dt);
		dtb_add_local_fixups(dt);
	}

	if (dt->cfg.debug)
		dtb_dump(dt);

	dtb_build_string_table(dt);
	dtb_flatten_node(dt);

	/* generate reserve entry */
	prop = dtb->memreserve_prop;
	if (prop && (size = to_dtb_prop(prop)->size) > 0)
		dt_emit_data(dt, dt_mem_rsvmap,
				to_dtb_prop(prop)->data, size, false);
	/* add extra memreserves */
	for (i = 0; i < dt->cfg.reserve; i++) {
		dt_emit_64(dt, dt_mem_rsvmap, 0, false);
		dt_emit_64(dt, dt_mem_rsvmap, 0, false);
	}

	/* terminate reserve entry */
	dt_emit_64(dt, dt_mem_rsvmap, 0, false);
	dt_emit_64(dt, dt_mem_rsvmap, 0, false);

	size_fdt_hdr = sizeof(struct fdt_header);
	size_dt_strings = dt_emit_get_size(dt, dt_strings);
	size_dt_struct = dt_emit_get_size(dt, dt_struct);
	size_mem_rsvmap = dt_emit_get_size(dt, dt_mem_rsvmap);

	totalsize = size_fdt_hdr + size_mem_rsvmap +
		    size_dt_struct + size_dt_strings;

	/* perform padding, minimum size and alignment */
	padsize = 0;
	if (dt->cfg.space > 0 && totalsize < dt->cfg.space)
		padsize = dt->cfg.space - totalsize;
	if (!padsize && dt->cfg.pad > 0)
		padsize = dt->cfg.pad;
	if (dt->cfg.align > 0)
		padsize = ALIGN(totalsize + padsize, dt->cfg.align) - totalsize;
	if (padsize > 0) {
		totalsize += padsize;
		zeropad = alloca(padsize);
		memset(zeropad, 0, padsize);
	}

	memset(&fdth, 0, sizeof(fdth));
	fdth.magic = cpu_to_fdt32(FDT_MAGIC);
	fdth.totalsize = cpu_to_fdt32(totalsize);
	fdth.off_dt_struct = cpu_to_fdt32(size_fdt_hdr + size_mem_rsvmap);
	fdth.off_dt_strings = cpu_to_fdt32(size_fdt_hdr + size_mem_rsvmap +
					   size_dt_struct);
	fdth.off_mem_rsvmap = cpu_to_fdt32(size_fdt_hdr);
	fdth.version = cpu_to_fdt32(17);
	fdth.last_comp_version = cpu_to_fdt32(16);
	fdth.boot_cpuid_phys = cpu_to_fdt32(guess_boot_cpuid(dt));
	fdth.size_dt_strings = cpu_to_fdt32(size_dt_strings);
	fdth.size_dt_struct = cpu_to_fdt32(size_dt_struct);

	fwrite(&fdth, size_fdt_hdr, 1, dt->output);
	fwrite(dtb->area[dt_mem_rsvmap].data,
	       dtb->area[dt_mem_rsvmap].size, 1, dt->output);
	fwrite(dtb->area[dt_struct].data,
	       dtb->area[dt_struct].size, 1, dt->output);
	fwrite(dtb->area[dt_strings].data,
	       dtb->area[dt_strings].size, 1, dt->output);
	if (zeropad)
		fwrite(zeropad, padsize, 1, dt->output);

	return !ferror(dt->output) ? 0 : -1;
}

static void print_prop(int col, int width, const char *data, int len)
{
	int i, j, qlen, span, fit;
	const char *s;
	char c, buf[C2STR_BUF_MAX];

	/* no data, don't print */
	if (len == 0)
		return;

	printf(" = ");
	col += strlen(" = ");

	if (is_printable_string(data, len)) {
		s = data;
		j = col;
		do {
			qlen = quoted_strlen(s);
			if (s > data) {
				printf(",");
				j++;

				if (j + qlen > width - 1) {
					j = col;
					printf("\n%*s", col, "");
				} else {
					printf(" ");
					j++;
				}
			}

			/* print quoted string */
			putchar('\"');
			while ((c = *s++) != '\0' && c2str(c, buf, sizeof(buf)))
				printf("%s", buf);
			putchar('\"');

			j += qlen;
		} while (s < data + len);

	} else if ((len % 4) == 0) {
		const fdt32_t *cell = (const fdt32_t *)data;

		len /= 4;

		/* how many words can we fit? */
		fit = (width - 1 - col - 2) / 11;

		do {
			printf("<");
			span = len > fit ? fit : len;
			for (i = 0; i < span; i++)
				printf("0x%08x%s", fdt32_to_cpu(cell[i]),
						i < (span - 1) ? " " : "");
			cell += span;
			len -= span;
			printf(">");
			if (len > 0)
				printf(",\n%*s", col, "");
		} while (len > 0);
	} else {
		const unsigned char *p = (const unsigned char *)data;

		/* how many bytes can we fit? */
		fit = (width - 1 - col - 2) / 3;

		do {
			printf("[");
			span = len > fit ? fit : len;
			for (i = 0; i < span; i++)
				printf("%02x%s", *p++,
						i < span - 1 ? " " : "");
			len -= span;
			printf("]");
			if (len > 0)
				printf(",\n%*s", col, "");
		} while (len > 0);
	}
}

static void __dn_dump(struct yaml_dt_state *dt, struct node *np, int depth)
{
	struct node *child;
	struct property *prop;
	struct dtb_property *dtbprop;
	struct label *l;
	const char *name;
	int count;
	const void *p;
	int size;

	name = np->name;
	if (!name || strlen(name) == 0)
		name = "/";

	printf("%*s", depth * 4, "");
	count = 0;
	for_each_label_of_node(np, l) {
		if (count == 1)
			printf(" /*");
		printf("%s%s:", count > 0 ? " " : "", l->label);
		count++;
	}
	if (count > 1)
		printf(" */");
	printf("%s%s {\n", count > 0 ? " " : "", name);

	for_each_property_of_node(np, prop) {
		dtbprop = to_dtb_prop(prop);
		printf("%*s%s", (depth + 1) * 4, "", prop->name);
		p = dtbprop->data;
		size = dtbprop->size;
		print_prop((depth + 1) * 4 + strlen(prop->name), 80, p, size);
		printf(";\n");
	}

	for_each_child_of_node(np, child)
		__dn_dump(dt, child, depth + 1);

	printf("%*s};\n", depth * 4, "");
}

static void dtb_dump(struct yaml_dt_state *dt)
{
	struct node *np;
	struct list_head *ref_nodes;

	if (!tree_root(to_tree(dt)))
		return;

	if (!dt->cfg.debug)
		return;

	np = tree_root(to_tree(dt));
	if (np) {
		printf("dump of /\n");
		__dn_dump(dt, np, 0);
	}

	ref_nodes = tree_ref_nodes(to_tree(dt));
	list_for_each_entry(np, ref_nodes, node) {
		printf("dump for ref %s\n", np->name);
		__dn_dump(dt, np, 0);
	}
}

static const struct yaml_dt_emitter_ops dtb_emitter_ops = {
	.setup		= dtb_setup,
	.cleanup	= dtb_cleanup,
	.emit		= dtb_emit,
};

static const char *dtb_suffixes[] = {
	".dtb",
	".dts",
	".dtbo",
	NULL
};

struct yaml_dt_emitter dtb_emitter = {
	.name		= "dtb",
	.suffixes	= dtb_suffixes,
	.tops		= &dtb_tree_ops,
	.eops		= &dtb_emitter_ops,
};
