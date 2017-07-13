/*
 * yamldt.h - YAML DT header
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

#ifndef YAMLDT_H
#define YAMLDT_H

#include "config.h"

#include <stdint.h>
#include <sys/time.h>
#include <linux/limits.h>

#include <yaml.h>

#include "list.h"
#include "libfdt_env.h"
#include "fdt.h"

#include "tree.h"
#include "dtb.h"

/* should be enough */
#define YAMLDL_PROP_SEQ_TAG_DEPTH_MAX	128

struct yaml_dt_state {
	/* yaml parser state */
	const char *input_file;
	const char *output_file;
	bool debug;
	bool compatible;	/* bit exact mode */
	FILE *input;
	FILE *output;

	unsigned char *buffer;
	size_t buffer_pos;
	size_t buffer_read;
	size_t buffer_alloc;
	char current_file[PATH_MAX + 1];
	long current_line;
	long current_col;
	long global_line;
	bool last_was_marker;

	void *input_file_contents;
	size_t input_file_size;

	yaml_parser_t parser;
	yaml_event_t *current_event;
	yaml_mark_t current_start_mark;
	yaml_mark_t current_end_mark;

	struct device_node *current_np;
	bool current_np_isref;
	struct property *current_prop;
	bool current_prop_existed; 
	char *map_key;
	int depth;
	int prop_seq_depth;
	char *prop_seq_tag[YAMLDL_PROP_SEQ_TAG_DEPTH_MAX];
	bool current_np_ref;

	bool error_flag;

	/* tree build state */
	struct tree tree;

	/* DTB generation state */
	struct dtb_emit_state dtb;
};

#define to_dt(_t) 	container_of(_t, struct yaml_dt_state, tree)
#define to_tree(_dt)	(&(_dt)->tree)

void dt_debug(struct yaml_dt_state  *dt, const char *fmt, ...)
		__attribute__ ((__format__ (__printf__, 2, 0)));

void dt_fatal(struct yaml_dt_state  *dt, const char *fmt, ...)
		__attribute__ ((__format__ (__printf__, 2, 0)))
		__attribute__ ((noreturn));

void dt_error_at(struct yaml_dt_state *dt,
		size_t line, size_t column,
		size_t end_line, size_t end_column,
		 const char *fmt, ...)
		 __attribute__ ((__format__ (__printf__, 6, 0)));

#endif
