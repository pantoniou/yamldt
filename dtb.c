/*
 * dtb.c - DTB generation
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

#include "utils.h"
#include "syexpr.h"

#include "yamldt.h"

static void dt_dump(struct yaml_dt_state *dt);

static void __prop_set_data(struct property *prop, bool append,
			    const void *data, int size,
			    bool append_zero, int offset)
{
	void *newdata;
	int newsize;

	/* direct set data */
	if (offset >= 0) {
		assert(offset + size <= prop->size);
		assert(prop->data);
		memcpy(prop->data + offset, data, size);
		return;
	}

	if (!append && prop->data) {
		free(prop->data);
		prop->size = 0;
	}

	newsize = prop->size + size + (append_zero ? 1 : 0);
	if (newsize > 0) {
		newdata = malloc(newsize);
		assert(newdata);
		if (prop->data && prop->size)
			memcpy(newdata, prop->data, prop->size);
		memcpy(newdata + prop->size, data, size);
		if (append_zero)
			*((char *)newdata + prop->size + size) = '\0';
		if (prop->data)
			free(prop->data);
		prop->data = newdata;
		prop->size = newsize;
	} else {
		prop->data = NULL;
		prop->size = 0;
	}
}

static void __prop_append(struct property *prop, const void *data,
			  int size, bool append_zero)
{
	__prop_set_data(prop, true, data, size, append_zero, -1);
}

static void __prop_replace(struct property *prop, const void *data,
			   int size, int offset)
{
	__prop_set_data(prop, false, data, size, false, offset);
}

static void __dn_append_auto_properties(struct yaml_dt_state *dt, struct device_node *np)
{
	struct device_node *child;
	struct property *prop;
	fdt32_t phandle;

	if (np->phandle != 0) {
		prop = prop_alloc(to_tree(dt), "phandle");

		phandle = cpu_to_fdt32(np->phandle);

		__prop_append(prop, &phandle, sizeof(fdt32_t), false);

		prop->np = np;
		list_add_tail(&prop->node, &np->properties);
	}

	list_for_each_entry(child, &np->children, node)
		__dn_append_auto_properties(dt, child);
}

static void dt_append_auto_properties(struct yaml_dt_state *dt)
{
	__dn_append_auto_properties(dt, tree_root(to_tree(dt)));
}

static void __dn_add_symbols(struct yaml_dt_state *dt, struct device_node *np,
		struct device_node **symbols_np)
{
	struct device_node *child;
	struct property *prop;
	struct label *l;
	char namebuf[NODE_FULLNAME_MAX];

	list_for_each_entry(l, &np->labels, node) {

		/* do not output autogenerated labels */
		if (!strncmp(l->label, "yaml_pseudo__",
		    strlen("yaml_pseudo__")))
			continue;

		prop = prop_alloc(to_tree(dt), l->label);

		dn_fullname(np, namebuf, sizeof(namebuf));
		assert(strlen(namebuf) > 0);

		__prop_append(prop, namebuf, strlen(namebuf), true);

		/* if it doesn't exist add __symbols__ */
		if (!*symbols_np) {
			*symbols_np = node_alloc(to_tree(dt), "__symbols__", NULL);
			(*symbols_np)->parent = tree_root(to_tree(dt));
			list_add_tail(&(*symbols_np)->node, &tree_root(to_tree(dt))->children);
		}

		prop->np = *symbols_np;
		list_add_tail(&prop->node, &(*symbols_np)->properties);
	}

	list_for_each_entry(child, &np->children, node) {
		/* do not enter the generated node */
		if (*symbols_np == child)
			continue;
		__dn_add_symbols(dt, child, symbols_np);
	}
}

static void dt_add_symbols(struct yaml_dt_state *dt)
{
	struct device_node *symbols_np = NULL;

	__dn_add_symbols(dt, tree_root(to_tree(dt)), &symbols_np);
}

static int parse_int(const char *str, int len, unsigned long long *valp, bool *unsignedp)
{
	int ret;
	sy_val_t val;
	struct sy_state state, *sy = &state;
	struct sy_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.size = sy_workbuf_size_max(len);
	cfg.workbuf = alloca(cfg.size);

	sy_init(sy, &cfg);

	assert(len > 0);
	ret = sy_eval(sy, str, len, &val);
	if (ret == 0) {
		*valp = val.v;
		*unsignedp = val.u;
	}

	return ret;
}

#define RF_LABELS	(1 << 0)
#define RF_PHANDLES	(1 << 1)
#define RF_PATHS	(1 << 2)
#define RF_CONTENT	(1 << 3)

static void ref_resolve(struct yaml_dt_state *dt, struct ref *ref)
{
	struct device_node *np;
	struct property *prop;
	int ret, len;
	uint8_t val8;
	fdt16_t val16;
	fdt32_t val32;
	fdt64_t val64;
	unsigned long long val = 0;
	const void *data = NULL;
	int size = 0;
	bool is_delete = false;
	bool is_unsigned;
	bool is_int;
	bool append_0 = false;
	fdt32_t phandlet;
	char namebuf[NODE_FULLNAME_MAX];
	const char *tag = NULL;
	const char *p;

	prop = ref->prop;
	assert(prop);

	if (ref->offset < 0)
		return;

	data = NULL;
	size = 0;

	/* get tag */
	tag = ref->xtag;
	if (!tag)
		tag = ref->xtag_builtin;

	switch (ref->type) {
	case r_anchor:
		np = node_lookup_by_label(to_tree(dt),
				ref->data, ref->len);
		if (!np) {
			strncat(namebuf, ref->data, sizeof(namebuf) - 1);
			namebuf[sizeof(namebuf) - 1] = '\0';
			dt_error_at(dt, ref->line, ref->column,
				    ref->end_line, ref->end_column,
				    "Can't resolve reference to label %s\n",
				    namebuf);
			return;
		}

		phandlet = cpu_to_fdt32(np->phandle);

		data = &phandlet;
		size = sizeof(phandlet);
		break;

	case r_path:
		np = node_lookup_by_label(to_tree(dt),
				ref->data, ref->len);
		if (!np) {
			strncat(namebuf, ref->data, sizeof(namebuf) - 1);
			namebuf[sizeof(namebuf) - 1] = '\0';
			dt_error_at(dt, ref->line, ref->column,
				    ref->end_line, ref->end_column,
				    "Can't resolve reference to label %s\n",
				    namebuf);
			return;
		}

		dn_fullname(np, namebuf, sizeof(namebuf));

		data = namebuf;
		size = strlen(namebuf) + 1;
		break;

	case r_scalar:
		np = prop->np;
		assert(np);

		p = ref->data;
		len = ref->len;

		ret = parse_int(p, len, &val, &is_unsigned);
		is_int = ret == 0;

		/* special memreserve handling */
		if (!tag && !strcmp(prop->name, "/memreserve/"))
			tag = "!uint64";

		/* TODO type checking/conversion here */
		if (!tag && is_int)
			tag = "!int";
		else if (!tag && ((len == 4 && !memcmp(p,  "true", 4)) ||
		                  (len == 5 && !memcmp(p, "false", 5)) ))
			tag = "!bool";
		else if (!tag && (len == 0 ||
		                 (len == 4 && !memcmp(p, "null", 4)) ||
				 (len == 1 && *(char *)p == '~')) )
			tag = "!null";
		else if (!tag)
			tag = "!str";

		if (!strcmp(tag,  "!int") || !strcmp(tag,  "!int32") ||
		    !strcmp(tag, "!uint") || !strcmp(tag, "!uint32")) {
			if (!is_int) {
				dt_error_at(dt, ref->line, ref->column,
					ref->end_line, ref->end_column,
					    "Tagged int is invalid: %s\n", p);
				return;
			}
			val32 = cpu_to_fdt32((uint32_t)val);
			data = &val32;
			size = sizeof(val32);
		} else if (!strcmp(tag, "!int8") || !strcmp(tag, "!uint8")) {
			if (!is_int) {
				dt_error_at(dt, ref->line, ref->column,
					ref->end_line, ref->end_column,
					    "Tagged int is invalid: %s\n", p);
				return;
			}
			val8 = (uint8_t)val;
			data = &val8;
			size = sizeof(val8);
		} else if (!strcmp(tag, "!int16") || !strcmp(tag, "!uint16")) {
			if (!is_int) {
				dt_error_at(dt, ref->line, ref->column,
					ref->end_line, ref->end_column,
					    "Tagged int is invalid: %s\n", p);
				return;
			}
			val16 = cpu_to_fdt16((uint16_t)val);
			data = &val16;
			size = sizeof(val16);
		} else if (!strcmp(tag, "!int64") || !strcmp(tag, "!uint64")) {
			if (!is_int) {
				dt_error_at(dt, ref->line, ref->column,
					ref->end_line, ref->end_column,
					    "Tagged int is invalid: %s\n", p);
				return;
			}
			val64 = cpu_to_fdt64((uint64_t)val);
			data = &val64;
			size = sizeof(val64);
		} else if (!strcmp(tag, "!str")) {
			data = ref->data;
			size = ref->len;
			append_0 = true;
		} else if (!strcmp(tag, "!bool")) {
			if (len == 4 && !memcmp(p,  "true", 4)) {
				data = NULL;
				size = 0;
			} else {
				dt_error_at(dt, ref->line, ref->column,
					ref->end_line, ref->end_column,
					    "We don't support false booleans\n");
				return;
			}
		} else if (!strcmp(tag, "!null")) {
			data = NULL;
			size = 0;
			is_delete = true;
		} else {
			dt_error_at(dt, ref->line, ref->column,
				ref->end_line, ref->end_column,
				"Unsupported tag %s\n", tag);
			return;
		}

		break;

	default:
		/* nothing */
		break;
	}

	ref->offset = prop->size;
	__prop_append(prop, data, size, append_0);

	if (is_delete)
		prop->is_delete = is_delete;
	else if (prop->size > 0)
		prop->is_delete = false;

	np = prop->np;
}

static void __dn_resolve(struct yaml_dt_state *dt, struct device_node *npt,
		  unsigned int flags)
{
	struct device_node *child;
	struct ref *ref, *refn;
	struct device_node *np;
	struct property *prop;
	struct label *l;
	fdt32_t phandlet;
	char namebuf[2][NODE_FULLNAME_MAX];

	if ((flags & RF_LABELS) && !npt->phandle && !list_empty(&npt->labels)) {
		list_for_each_entry(l, &npt->labels, node)
			dt_debug(dt, "label: assigned phandle %u at @%s label %s\n",
					npt->phandle,
					dn_fullname(npt, &namebuf[0][0], sizeof(namebuf[0])),
					l->label);
		npt->phandle = dt->dtb.next_phandle++;
		assert(dt->dtb.next_phandle != 0 && dt->dtb.next_phandle != -1);
	}

	list_for_each_entry(prop, &npt->properties, node) {

		list_for_each_entry_safe(ref, refn, &prop->refs, node) {

			if (flags & RF_CONTENT)
				ref_resolve(dt, ref);

			/* only handle anchors here */
			if (!((flags & RF_PHANDLES) && ref->type == r_anchor))
				continue;

			np = node_lookup_by_label(to_tree(dt), ref->data, ref->len);
			if (!np) {
				strncat(&namebuf[0][0], ref->data, sizeof(namebuf[0]) - 1);
				namebuf[0][sizeof(namebuf[0]) - 1] = '\0';
				dt_fatal(dt, "Can't resolve reference to label %s\n", namebuf);
			}

			if (!np->phandle) {
				np->phandle = dt->dtb.next_phandle++;
				assert(dt->dtb.next_phandle != 0 && dt->dtb.next_phandle != -1);
				list_for_each_entry(l, &np->labels, node)
					dt_debug(dt, "assigned phandle %u at @%s label %s (@%s prop %s offset=%u)\n",
						np->phandle,
						dn_fullname(np, &namebuf[0][0], sizeof(namebuf[0])),
						l->label,
						dn_fullname(npt, &namebuf[1][0], sizeof(namebuf[1])),
						prop->name, prop->offset);
			}

			assert (prop->size >= ref->offset + sizeof(fdt32_t));

			phandlet = cpu_to_fdt32(np->phandle);
			__prop_replace(prop, &phandlet, sizeof(fdt32_t), ref->offset);

			dt_debug(dt, "resolved property %s at @%s (%u)\n",
				prop->name,
				dn_fullname(prop->np, &namebuf[0][0], sizeof(namebuf[0])),
				np->phandle);
		}
	}

	list_for_each_entry(child, &npt->children, node)
		__dn_resolve(dt, child, flags);
}

static void dt_handle_special_properties(struct yaml_dt_state *dt)
{
	struct property *prop, *propn;
	struct ref *ref;
	struct device_node *root;

	assert(dt);

	root = tree_root(to_tree(dt)); 
	if (!root)
		return;

	list_for_each_entry_safe(prop, propn, &root->properties, node) {

		/* detach and keep memreserve property */
		if (!strcmp(prop->name, "/memreserve/")) {

			list_for_each_entry(ref, &prop->refs, node)
				ref_resolve(dt, ref);

			/* must be aligned */
			if (prop->size % (2 * sizeof(uint64_t)))
				dt_fatal(dt, "Invalid memreserve size (%d)\n",
						prop->size);
			list_del(&prop->node);
			prop->np = NULL;

			if (dt->dtb.memreserve_prop) {
				__prop_append(dt->dtb.memreserve_prop, prop->data,
					      prop->size, false);
				prop_free(to_tree(dt), prop);
			} else
				dt->dtb.memreserve_prop = prop;
		}
	}
}

static void dt_resolve_phandle_refs(struct yaml_dt_state *dt)
{
	struct device_node *root;

	assert(dt);

	root = tree_root(to_tree(dt));

	if (dt->compatible) {
		__dn_resolve(dt, root, RF_CONTENT);
		__dn_resolve(dt, root, RF_PHANDLES);
		__dn_resolve(dt, root, RF_LABELS);
		__dn_resolve(dt, root, RF_PATHS);
	} else
		__dn_resolve(dt, root, RF_CONTENT | RF_LABELS |
				       RF_PHANDLES | RF_PATHS);
}

/* clear any crud that shouldn't be part of the base tree */
void __dn_sanitize_base(struct yaml_dt_state *dt, struct device_node *np)
{
	struct device_node *child;
	struct property *prop, *propn;
	char namebuf[NODE_FULLNAME_MAX];

	list_for_each_entry_safe(prop, propn, &np->properties, node) {
		if (prop->is_delete || !strcmp(prop->name, "~")) {
			dt_debug(dt, "removing property %s @%s\n",
				prop->name, dn_fullname(np, namebuf, sizeof(namebuf)));
			prop_del(to_tree(dt), prop);
		}
	}

	list_for_each_entry(child, &np->children, node)
		__dn_sanitize_base(dt, child);
}

void __dn_apply_ref_node(struct yaml_dt_state *dt,
		struct device_node *npref,
		struct device_node *np)
{
	struct property *prop, *propn;
	struct property *propref, *proprefn;
	struct label *l, *ln;
	struct device_node *child, *childn, *childref, *childrefn;
	bool found;
	char namebuf[2][NODE_FULLNAME_MAX];

	/* add label to noderef */
	list_for_each_entry_safe(l, ln, &np->labels, node)
		label_add(to_tree(dt), npref, l->label);

	list_for_each_entry_safe(prop, propn, &np->properties, node) {

		if (prop->is_delete) {

			dt_debug(dt, "using delete property %s @%s\n",
				prop->name,
				dn_fullname(np, &namebuf[0][0], sizeof(namebuf[0])));

			list_for_each_entry_safe(propref, proprefn, &npref->properties, node) {
				if (strcmp(propref->name, prop->name))
					continue;
				dt_debug(dt, "deleting property %s at %s\n",
					propref->name,
					dn_fullname(npref, &namebuf[0][0], sizeof(namebuf[0])));
				prop_del(to_tree(dt), propref);
			}

			list_for_each_entry_safe(childref, childrefn, &npref->children, node) {
				if (strcmp(childref->name, prop->name))
					continue;

				dt_debug(dt, "deleting child %s at %s\n",
					dn_fullname(childref, &namebuf[0][0], sizeof(namebuf[0])),
					dn_fullname(npref, &namebuf[1][0], sizeof(namebuf[1])));
				node_free(to_tree(dt), childref);
			}

			prop_del(to_tree(dt), prop);
			continue;
		}

		found = false;
		list_for_each_entry_safe(propref, proprefn, &npref->properties, node) {
			if (!strcmp(propref->name, prop->name)) {
				found = true;
				break;
			}
		}

		list_del(&prop->node);
		prop->np = npref;

		/* if found, free old copy */
		if (found) {
			/* carefully put it at the same point in the list */
			list_add(&prop->node, &propref->node);
			list_del(&propref->node);
			propref->np = NULL;
			prop_del(to_tree(dt), propref);
		} else /* move property over to new parent */
			list_add_tail(&prop->node, &npref->properties);
	}

	list_for_each_entry_safe(child, childn, &np->children, node) {

		/* find matching child */
		found = false;
		list_for_each_entry(childref, &npref->children, node) {
			if (!strcmp(childref->name, child->name)) {
				found = true;
				break;
			}
		}

		/* if found, apply recursively */
		if (found) {
			__dn_apply_ref_node(dt, childref, child);
			continue;
		}

		/* child at ref does not exist, just move self over */
		list_del(&child->node);
		child->parent = npref;
		list_add_tail(&child->node, &npref->children);
		__dn_sanitize_base(dt, child);
	}
}

static void dt_apply_ref_nodes(struct yaml_dt_state *dt)
{
	struct device_node *np, *npn, *npref;
	struct list_head *ref_nodes = tree_ref_nodes(to_tree(dt));

	list_for_each_entry_safe(np, npn, ref_nodes, node) {
		list_del(&np->node);

		/* lookup for node (skip *) */
		npref = node_lookup_by_label(to_tree(dt), np->name + 1,
				strlen(np->name + 1));
		if (npref == NULL)
			dt_fatal(dt, "reference to unknown label %s\n",
					np->name + 1);
		__dn_apply_ref_node(dt, npref, np);

		/* free everything now */
		node_free(to_tree(dt), np);
	}
}

static void dt_emit_data(struct yaml_dt_state *dt,
		enum dt_data_area area, const void *data,
		unsigned int size, unsigned int align)
{
	unsigned int asize = ALIGN(size, align);
	unsigned int *sizep, *allocp;
	void **datap;
	void *p;

	assert(area <= dt_area_max);

	sizep  = &dt->dtb.area[area].size;
	allocp = &dt->dtb.area[area].alloc;
	datap  = &dt->dtb.area[area].data;

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
	assert(area <= dt_area_max);

	return dt->dtb.area[area].size;
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

static int __dn_count_properties(struct yaml_dt_state *dt, struct device_node *np)
{
	struct property *prop;
	struct device_node *child;
	int count;

	count = 0;
	list_for_each_entry(prop, &np->properties, node)
		count++;

	list_for_each_entry(child, &np->children, node)
		count += __dn_count_properties(dt, child);

	return count;
}

static int __dn_fill_prop_table(struct yaml_dt_state *dt, struct device_node *np,
			   struct property **propp, int pos)
{
	struct property *prop;
	struct device_node *child;

	list_for_each_entry(prop, &np->properties, node)
		propp[pos++] = prop;

	list_for_each_entry(child, &np->children, node)
		pos = __dn_fill_prop_table(dt, child, propp, pos);

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

static void dt_build_string_table_minimal(struct yaml_dt_state *dt)
{
	struct device_node *root;
	int i, j, count, l1, l2;
	struct property **propt, *prop, *prop2;
	const char *s1, *s2;

	root = tree_root(to_tree(dt));
	/* count how many properties we have and get an array of pointers */
	count = __dn_count_properties(dt, root);
	if (count == 0)
		return;

	propt = malloc(count * sizeof(*propt));
	assert(propt);
	memset(propt, 0, count * sizeof(*propt));
	__dn_fill_prop_table(dt, root, propt, 0);

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
				prop->offset = prop2->offset + l2 - l1;
				dt_debug(dt, "%s offset %d (reusing %s)\n",
					prop->name, prop->offset,
					prop2->name);
				break;
			}
		}

		/* no match */
		if (j >= i) {
			prop->offset = dt_emit_get_size(dt, dt_strings);
			dt_emit_str(dt, dt_strings, prop->name, false);

			dt_debug(dt, "%s offset %d\n", prop->name, prop->offset);
		}
	}

	free(propt);
}

static void __dn_build_string_table_compatible(struct yaml_dt_state *dt,
		struct device_node *np)
{
	struct device_node *child;
	struct property *prop;
	void *s, *e, *data;
	int l1, l2;

	list_for_each_entry(prop, &np->properties, node) {

		data = dt->dtb.area[dt_strings].data;
		s = data;
		e = s + dt->dtb.area[dt_strings].size;

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

		prop->offset = (unsigned int)(s - data);

		if (prop->offset == dt_emit_get_size(dt, dt_strings))
			dt_emit_str(dt, dt_strings, prop->name, false);

		dt_debug(dt, "%s offset %d\n", prop->name, prop->offset);
	}

	list_for_each_entry(child, &np->children, node)
		__dn_build_string_table_compatible(dt, child);
}

static void dt_build_string_table_compatible(struct yaml_dt_state *dt)
{
	__dn_build_string_table_compatible(dt, tree_root(to_tree(dt)));
}

static void dt_build_string_table(struct yaml_dt_state *dt)
{
	if (!dt->compatible)
		dt_build_string_table_minimal(dt);
	else
		dt_build_string_table_compatible(dt);
}

void __dn_flatten_node(struct yaml_dt_state *dt, struct device_node *np)
{
	struct device_node *child;
	struct property *prop;

	dt_emit_32(dt, dt_struct, FDT_BEGIN_NODE, false);
	dt_emit_str(dt, dt_struct, np->name, true);

	list_for_each_entry(prop, &np->properties, node) {
		dt_emit_32(dt, dt_struct, FDT_PROP, false);
		dt_emit_32(dt, dt_struct, prop->size, false);

		assert(prop->offset >= 0);
		dt_emit_32(dt, dt_struct, prop->offset, false);

		dt_emit_data(dt, dt_struct, prop->data, prop->size,
			     sizeof(fdt32_t));
	}

	list_for_each_entry(child, &np->children, node)
		__dn_flatten_node(dt, child);

	dt_emit_32(dt, dt_struct, FDT_END_NODE, false);
}

static void dt_flatten_node(struct yaml_dt_state *dt)
{
	__dn_flatten_node(dt, tree_root(to_tree(dt)));
	dt_emit_32(dt, dt_struct, FDT_END, false);
}

static fdt32_t guess_boot_cpuid(struct yaml_dt_state *dt)
{
	struct device_node *root, *np, *child;
	struct property *prop;
	fdt32_t val;

	root = tree_root(to_tree(dt));
	if (!root)
		return 0;

	list_for_each_entry(np, &root->children, node) {
		if (strcmp(np->name, "cpus"))
			continue;

		list_for_each_entry(child, &np->children, node) {

			list_for_each_entry(prop, &child->properties, node) {
				if (!strcmp(prop->name, "reg") &&
					prop->size >= sizeof(fdt32_t)) {
					memcpy(&val, prop->data, sizeof(val));
					return fdt32_to_cpu(val);
				}
			}

			/* compatible mode is wrong, but whatever */
			if (dt->compatible)
				return 0;
		}
	}

	return 0;
}

void dtb_init(struct yaml_dt_state *dt)
{
	memset(&dt->dtb, 0, sizeof(dt->dtb));
	dt->dtb.next_phandle = 1;
}

void dtb_cleanup(struct yaml_dt_state *dt)
{
	enum dt_data_area area;

	for (area = 0; area <= dt_area_max; area++) {
		if (dt->dtb.area[area].data)
			free(dt->dtb.area[area].data);
	}

	if (dt->dtb.memreserve_prop)
		prop_free(to_tree(dt), dt->dtb.memreserve_prop);

	memset(&dt->dtb, 0, sizeof(dt->dtb));
	dt->dtb.next_phandle = 1;
}

void dtb_emit(struct yaml_dt_state *dt)
{
	struct fdt_header fdth;
	struct property *prop;
	unsigned int totalsize, size_fdt_hdr, size_dt_strings, size_dt_struct,
		     size_mem_rsvmap;
	int size;

	dt_handle_special_properties(dt);
	dt_apply_ref_nodes(dt);
	dt_resolve_phandle_refs(dt);

	dt_append_auto_properties(dt);
	dt_add_symbols(dt);

	if (dt->debug)
		dt_dump(dt);

	dt_build_string_table(dt);
	dt_flatten_node(dt);

	/* generate reserve entry */
	if ((prop = dt->dtb.memreserve_prop) && (size = prop->size) > 0)
		dt_emit_data(dt, dt_mem_rsvmap, prop->data, size, false);

	/* terminate reserve entry */
	dt_emit_64(dt, dt_mem_rsvmap, 0, false);
	dt_emit_64(dt, dt_mem_rsvmap, 0, false);

	size_fdt_hdr = sizeof(struct fdt_header);
	size_dt_strings = dt_emit_get_size(dt, dt_strings);
	size_dt_struct = dt_emit_get_size(dt, dt_struct);
	size_mem_rsvmap = dt_emit_get_size(dt, dt_mem_rsvmap);

	totalsize = size_fdt_hdr + size_mem_rsvmap +
		    size_dt_struct + size_dt_strings;

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
	fwrite(dt->dtb.area[dt_mem_rsvmap].data,
	       dt->dtb.area[dt_mem_rsvmap].size, 1, dt->output);
	fwrite(dt->dtb.area[dt_struct].data,
	       dt->dtb.area[dt_struct].size, 1, dt->output);
	fwrite(dt->dtb.area[dt_strings].data,
	       dt->dtb.area[dt_strings].size, 1, dt->output);
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

static void __dn_dump(struct yaml_dt_state *dt, struct device_node *np, int depth)
{
	struct device_node *child;
	struct property *prop;
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
	list_for_each_entry(l, &np->labels, node) {
		if (count == 1)
			printf(" /*");
		printf("%s%s:", count > 0 ? " " : "", l->label);
		count++;
	}
	if (count > 1)
		printf(" */");
	printf("%s%s {\n", count > 0 ? " " : "", name);

	list_for_each_entry(prop, &np->properties, node) {
		printf("%*s%s", (depth + 1) * 4, "", prop->name);
		p = prop->data;
		size = prop->size;
		print_prop((depth + 1) * 4 + strlen(prop->name), 80, p, size);
		printf(";\n");
	}

	list_for_each_entry(child, &np->children, node)
		__dn_dump(dt, child, depth + 1);

	printf("%*s};\n", depth * 4, "");
}

void dt_dump(struct yaml_dt_state *dt)
{
	struct device_node *np;
	struct list_head *ref_nodes;

	if (!dt->debug)
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
