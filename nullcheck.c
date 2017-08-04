/*
 * nullcheck.c - NULL sink checker
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

#include "nullcheck.h"

int nullchk_setup(struct yaml_dt_state *dt)
{
	return 0;
}

void nullchk_cleanup(struct yaml_dt_state *dt)
{
}

int nullchk_check(struct yaml_dt_state *dt)
{
	return 0;
}

static bool nullchk_select(int argc, char **argv)
{
	return false;
}

static const struct yaml_dt_checker_ops null_checker_ops = {
	.select		= nullchk_select,
	.setup		= nullchk_setup,
	.cleanup	= nullchk_cleanup,
	.check		= nullchk_check,
};

struct yaml_dt_checker null_checker = {
	.name		= "nullchk",
	.cops		= &null_checker_ops,
};
