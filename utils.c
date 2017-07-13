/*
 * utils.c
 *
 * Generic utilities
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

#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "utils.h"

bool isesc(char c)
{
	return c == '\a' || c == '\b' || c == '\t' || c == '\n' || c == '\v' ||
	       c == '\f' || c == '\r' || c == '\\' || c == '\"';
}

bool is_printable_string(const void *data, int len)
{
	const char *s = data;
	const char *ss, *se;
	char c;

	/* zero length is not */
	if (len == 0)
		return 0;

	/* must terminate with zero */
	if (s[len - 1] != '\0')
		return 0;

	se = s + len;

	while (s < se) {
		ss = s;
		while (s < se && *s) {
			c = *s;
			if (!(isprint(c) || isesc(c)))
				break;
			s++;
		}


		/* not zero, or not done yet */
		if (*s != '\0' || s == ss)
			return 0;

		s++;
	}

	return 1;
}

char *c2str(char c, char *buf, int bufsz)
{
	char *s = buf;

	if (isesc(c)) {

		if (bufsz < 3)
			return NULL;

		/* escape case */
		*s++ = '\\';
		switch (c) {
		case '\a': *s++ =  'a'; break;
		case '\b': *s++ =  'b'; break;
		case '\t': *s++ =  't'; break;
		case '\n': *s++ =  'n'; break;
		case '\v': *s++ =  'v'; break;
		case '\f': *s++ =  'f'; break;
		case '\r': *s++ =  'r'; break;
		case '\\': *s++ = '\\'; break;
		case '\"': *s++ = '\"'; break;
		}
	} else if (!isprint(c)) {
		static const char *hexb = "0123456789abcdef";

		if (bufsz < 5)
			return NULL;

		/* hexadecimal escape case */
		*s++ = '\\';
		*s++ = 'x';
		*s++ = hexb[(((unsigned int)c >> 4) & 0xf)];
		*s++ = hexb[  (unsigned int)c       & 0xf ];
	} else {
		if (bufsz < 2)
			return NULL;

		*s++ = c;	/* normal printable */
	}

	*s = '\0';

	return buf;
}

int quoted_strlen(const char *str)
{
	int len;
	char c, buf[C2STR_BUF_MAX];

	len = 1;
	while ((c = *str++) != '\0' && c2str(c, buf, sizeof(buf)))
		len += strlen(buf);
	return len + 1;
}

/*
 * Parse a octal encoded character starting at index i in string s.  The
 * resulting character will be returned and the index i will be updated to
 * point at the character directly after the end of the encoding, this may be
 * the '\0' terminator of the string.
 */
static char get_oct_char(const char *s, int *i)
{
	char x[4];
	char *endx;
	long val;

	x[3] = '\0';
	strncpy(x, s + *i, 3);

	val = strtol(x, &endx, 8);
	if (endx <= x)
		return 0;

	(*i) += endx - x;
	return val;
}

/*
 * Parse a hexadecimal encoded character starting at index i in string s.  The
 * resulting character will be returned and the index i will be updated to
 * point at the character directly after the end of the encoding, this may be
 * the '\0' terminator of the string.
 */
static char get_hex_char(const char *s, int *i)
{
	char x[3];
	char *endx;
	long val;

	x[2] = '\0';
	strncpy(x, s + *i, 2);

	val = strtol(x, &endx, 16);
	if (endx <= x)
		return 0;

	(*i) += endx - x;
	return val;
}

char get_escape_char(const char *s, int *i)
{
	char	c = s[*i];
	int	j = *i + 1;
	char	val;

	switch (c) {
	case 'a':
		val = '\a';
		break;
	case 'b':
		val = '\b';
		break;
	case 't':
		val = '\t';
		break;
	case 'n':
		val = '\n';
		break;
	case 'v':
		val = '\v';
		break;
	case 'f':
		val = '\f';
		break;
	case 'r':
		val = '\r';
		break;
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
		j--; /* need to re-read the first digit as
		      * part of the octal value */
		val = get_oct_char(s, &j);
		break;
	case 'x':
		val = get_hex_char(s, &j);
		break;
	default:
		val = c;
	}

	(*i) = j;
	return val;
}
