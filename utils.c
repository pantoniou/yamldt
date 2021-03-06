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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

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

int esc_getc(const char **sp)
{
	const char *s = *sp;
	char c, c1;
	int outc = -1, i;

	if (!*s)
		return 0;

	c = *s++;
	if (c != '\\') {
		outc = c;
		goto out;
	}

	c = *s++;
	if (!c)
		return -2;
	switch (c) {
	case 'a':
		outc = '\a';
		break;
	case 'b':
		outc = '\b';
		break;
	case 't':
		outc = '\t';
		break;
	case 'n':
		outc = '\n';
		break;
	case 'v':
		outc = '\v';
		break;
	case 'f':
		outc = '\f';
		break;
	case 'r':
		outc = '\r';
		break;
	case '?':
	case '\'':
	case '\"':
		outc = c;
		break;
	case 'x':
	case 'X':
		/* hex */
		outc = 0;
		i = 0;
		c1 = '\0';
		for (;;) {
			c1 = *s;
			if (c1 >= '0' && c1 <= '9')
				outc = (outc << 4) | (c1 - '0');
			else if (c1 >= 'A' && c1 <= 'F')
				outc = (outc << 4) | (10 + c1 - 'A');
			else if (c1 >= 'a' && c1 <= 'f')
				outc = (outc << 4) | (10 + c1 - 'a');
			else
				break;
			s++;
			i++;
		}

		/* bad hex escape sequence */
		if (i == 0 || i > 2)
			return (c1 || i > 2) ? -1 : -2;
		break;
	case '0':
		/* octal */
		outc = 0;
		i = 0;
		c1 = '\0';
		for (;;) {
			c1 = *s;
			if (c1 >= '0' && c1 <= '7')
				outc = (outc << 3) | (c1 - '0');
			else
				break;
			s++;
			i++;
		}
		/* bad octal escape sequence */
		if (i == 0 || i > 3)
			return (c1 || i > 3) ? -1 : -2;
		break;
	default:
		return -1;
	}
out:
	*sp = s;
	return outc;
}

/* count the number of characters in an escaped string (with the given quote) */
int esc_strlen(const char *s)
{
	int c;
	int count;

	count = 0;
	c = 0;
	while (*s && (c = esc_getc(&s)) > 0)
		count++;

	if (!*s && c >= 0)
		return count;

	return c;
}

char *esc_getstr(const char *s, char *buf, int bufsz)
{
	int c, len;
	char *p;

	len = esc_strlen(s);
	if (len + 1 < bufsz)
		return NULL;

	p = buf;
	while (*s && (c = esc_getc(&s)) >= 0)
		*p++ = (char)c;
	*p = '\0';
	return buf;
}

char **str_to_argv(const char *binary, const char *str)
{
	const char *s, *start;
	char c;
	int pass, count, total, len;
	enum tokenizer_state {
		normal,
		spaces,
		single_quotes,
		double_quotes,
	} state;
	char **argv = NULL;
	char *copy = NULL;

	for (pass = 1; pass <= 2; pass++) {
		state = normal;
		s = str;
		start = str;
		count = 1;
		total = strlen(binary) + 1;
		while ((c = *s++) != '\0') {

			switch (state) {
			case normal:
				if (!isspace(c))
					break;

				if (start) {
					len = s - 1 - start;
					if (argv) {
						argv[count] = copy;
						memcpy(copy, start, len);
						copy[len] = '\0';
						copy += len + 1;
					}
					total += len + 1;
					count++;
				}

				state = spaces;
				start = NULL;
				break;

			case spaces:
				if (isspace(c))
					break;
				if (c == '\'') {
					state = single_quotes;
					start = s;
				} else if (c == '"') {
					state = double_quotes;
					start = s;
				} else {
					state = normal;
					start = s - 1;
				}
				break;
			case single_quotes:
			case double_quotes:
				if ((state == single_quotes && c != '\'') ||
				    (state == double_quotes && c != '"') )
					break;

				len = s - 1 - start;

				if (argv) {
					argv[count] = copy;
					memcpy(copy, start, len);
					copy[len] = '\0';
					copy += len + 1;
				}
				total += len + 1;
				count++;

				start = NULL;
				state = normal;
				break;
			}
		}

		if (pass == 1) {
			if (start) {
				len = s - start;
				total += len + 1;
				count++;
			}
			argv = malloc((count + 1) * sizeof(*argv) + total);
			if (!argv)
				return NULL;
			copy = (char *)(argv + count + 1);

			argv[0] = copy;
			strcpy(copy, binary);
			copy += strlen(binary) + 1;
		}
	}

	/* final */
	if (start) {
		len = s - start;
		argv[count] = copy;
		memcpy(copy, start, len);
		copy[len] = '\0';
		count++;
	}

	argv[count] = NULL;

	return argv;
}

int compile(const char *text, size_t size,
	    const char *compiler, const char *flags,
	    void **output, size_t *output_size)
{
	char intemplate[11] = "tmp-XXXXXX";
	char outtemplate[11] = "tmp-XXXXXX";
	int infd, outfd, ret, status;
	struct stat st;
	ssize_t nwrite, nread;
	size_t filesz;
	pid_t pid;
	off_t off;
	char *buf;
	char **argv = NULL;

	infd = -1;
	outfd = -1;

	infd = mkstemp(intemplate);
	if (infd == -1) {
		fprintf(stderr, "Failed to mkstemp()\n");
		goto out_close;
	}

	outfd = mkstemp(outtemplate);
	if (outfd == -1) {
		fprintf(stderr, "Failed to mkstemp()\n");
		goto out_close;
	}

	if (size == 0)
		size = strlen(text);
	nwrite = write(infd, text, size);
	if (nwrite != size) {
		fprintf(stderr, "Failed to write to temporary file\n");
		goto out_close;
	}
	off = lseek(infd, 0, SEEK_SET);
	if (off != 0) {
		fprintf(stderr, "Failed to rewind temporary file\n");
		goto out_close;
	}

	pid = fork();
	if (pid == -1) {
		fprintf(stderr, "Failed to fork()\n");
		goto out_close;
	}

	if (!pid) {
		/* child */
		dup2(infd, STDIN_FILENO);
		off = lseek(STDIN_FILENO, 0, SEEK_SET);

		dup2(outfd, STDOUT_FILENO);
		off = lseek(STDOUT_FILENO, 0, SEEK_SET);

		argv = str_to_argv(compiler, flags);
		if (!argv) {
			fprintf(stderr, "Failed to parse command line args\n");
			exit(1);
		}

		execvp(compiler, argv);
		/* error always if here */
		exit(1);
	}

	/* parent */
	ret = wait(&status);
	if (ret == -1) {
		fprintf(stderr, "Failed to waitpid()\n");
		goto out_close;
	}
	if (!WIFEXITED(status)) {
		fprintf(stderr, "abnormal child termination\n");
		goto out_close;
	}

	if (WEXITSTATUS(status) != 0) {
		fprintf(stderr, "child process exited with status %d\n",
			WEXITSTATUS(status));
		goto out_close;
	}

	/* get the file size if we can */
	filesz = 0;
	if (fstat(outfd, &st) != -1 && S_ISREG(st.st_mode))
		filesz = st.st_size;

	if (filesz == 0) {
		fprintf(stderr, "Not a regular file!\n");
		goto out_close;
	}

	buf = malloc(filesz);
	if (!buf) {
		fprintf(stderr, "Failed to allocate temporary buffer!\n");
		goto out_close;
	}

	do {
		off = lseek(outfd, 0, SEEK_SET);
		nread = read(outfd, buf, filesz);
	} while (nread == -1 && errno == -EAGAIN);

	*output = buf;
	*output_size = filesz;

	close(infd);
	unlink(intemplate);

	close(outfd);
	unlink(outtemplate);

	if (argv)
		free(argv);

	return 0;
out_close:
	if (infd != -1) {
		close(infd);
		unlink(intemplate);
	}
	if (outfd != -1) {
		close(outfd);
		unlink(outtemplate);
	}

	if (argv)
		free(argv);

	return -1;
}

#if defined(__APPLE__) && (_POSIX_C_SOURCE < 200809L)

/*
 * adapted from http://piumarta.com/software/memstream/
 *
 * Under the MIT license.
 */

/*
 * ----------------------------------------------------------------------------
 *
 * OPEN_MEMSTREAM(3)      BSD and Linux Library Functions     OPEN_MEMSTREAM(3)
 *
 * SYNOPSIS
 *     #include "memstream.h"
 *
 *     FILE *open_memstream(char **bufp, size_t *sizep);
 *
 * DESCRIPTION
 *     The open_memstream()  function opens a  stream for writing to  a buffer.
 *     The   buffer  is   dynamically  allocated   (as  with   malloc(3)),  and
 *     automatically grows  as required.  After closing the  stream, the caller
 *     should free(3) this buffer.
 *
 *     When  the  stream is  closed  (fclose(3))  or  flushed (fflush(3)),  the
 *     locations  pointed  to  by  bufp  and  sizep  are  updated  to  contain,
 *     respectively,  a pointer  to  the buffer  and  the current  size of  the
 *     buffer.  These values  remain valid only as long  as the caller performs
 *     no further output  on the stream.  If further  output is performed, then
 *     the  stream  must  again  be  flushed  before  trying  to  access  these
 *     variables.
 *
 *     A null byte  is maintained at the  end of the buffer.  This  byte is not
 *     included in the size value stored at sizep.
 *
 *     The stream's  file position can  be changed with fseek(3)  or fseeko(3).
 *     Moving the file position past the  end of the data already written fills
 *     the intervening space with zeros.
 *
 * RETURN VALUE
 *     Upon  successful  completion open_memstream()  returns  a FILE  pointer.
 *     Otherwise, NULL is returned and errno is set to indicate the error.
 *
 * CONFORMING TO
 *     POSIX.1-2008
 *
 * ----------------------------------------------------------------------------
 */

#ifndef min
#define min(X, Y) (((X) < (Y)) ? (X) : (Y))
#endif

struct memstream {
	size_t position;
	size_t size;
	size_t capacity;
	char *contents;
	char **ptr;
	size_t *sizeloc;
};

static int memstream_grow(struct memstream *ms, size_t minsize)
{
	size_t newcap;
	char *newcontents;

	newcap = ms->capacity * 2;
	while (newcap <= minsize + 1)
		newcap *= 2;
	newcontents = realloc(ms->contents, newcap);
	if (!newcontents)
		return -1;
	ms->contents = newcontents;
	memset(ms->contents + ms->capacity, 0, newcap - ms->capacity);
	ms->capacity = newcap;
	*ms->ptr = ms->contents;
	return 0;
}

static int memstream_read(void *cookie, char *buf, int count)
{
	struct memstream *ms = cookie;
	size_t n;

	n = min(ms->size - ms->position, count);
	if (n < 1)
		return 0;
	memcpy(buf, ms->contents, n);
	ms->position += n;
	return n;
}

static int memstream_write(void *cookie, const char *buf, int count)
{
	struct memstream *ms = cookie;

	if (ms->capacity <= ms->position + count &&
	    memstream_grow(ms, ms->position + count) < 0)
		return -1;
	memcpy(ms->contents + ms->position, buf, count);
	ms->position += count;
	ms->contents[ms->position] = '\0';
	if (ms->size < ms->position)
		*ms->sizeloc = ms->size = ms->position;

	return count;
}

static fpos_t memstream_seek(void *cookie, fpos_t offset, int whence)
{
	struct memstream *ms = cookie;
	fpos_t pos= 0;

	switch (whence) {
	case SEEK_SET:
		pos = offset;
		break;
	case SEEK_CUR:
		pos = ms->position + offset;
		break;
	case SEEK_END:
		pos = ms->size + offset;
		break;
	default:
		errno= EINVAL;
		return -1;
	}
	if (pos >= ms->capacity && memstream_grow(ms, pos) < 0)
		return -1;
	ms->position = pos;
	if (ms->size < ms->position)
		*ms->sizeloc = ms->size = ms->position;
	return pos;
}

static int memstream_close(void *cookie)
{
	struct memstream *ms = cookie;

	ms->size = min(ms->size, ms->position);
	*ms->ptr = ms->contents;
	*ms->sizeloc = ms->size;
	ms->contents[ms->size]= 0;
	/* ms->contents is what's returned */
	free(ms);
	return 0;
}

FILE *open_memstream(char **ptr, size_t *sizeloc)
{
	struct memstream *ms;
	FILE *fp;

	if (!ptr || !sizeloc) {
		errno= EINVAL;
		goto err_out;
	}

	ms = calloc(1, sizeof(struct memstream));
	if (!ms)
		goto err_out;

	ms->position = ms->size= 0;
	ms->capacity = 4096;
	ms->contents = calloc(ms->capacity, 1);
	if (!ms->contents)
		goto err_free_ms;
	ms->ptr = ptr;
	ms->sizeloc = sizeloc;
	fp= funopen(ms, memstream_read, memstream_write,
			memstream_seek, memstream_close);
	if (!fp)
		goto err_free_all;
	*ptr = ms->contents;
	*sizeloc = ms->size;
	return fp;

err_free_all:
	free(ms->contents);
err_free_ms:
	free(ms);
err_out:
	return NULL;
}

void *memrchr(const void *s, int c, size_t n)
{
	const unsigned char *ss;

	for (ss = s + n; n > 0; n++) {
		if (*--ss == (unsigned char)c)
			return (void *)ss;
	}
	return NULL;
}

#endif /* __APPLE__ && _POSIX_C_SOURCE < 200809L */

int acc_add(struct acc_state *acc, char c)
{
	char *new_buf;
	size_t new_alloc;

	if (acc->size >= acc->alloc) {
		new_alloc = acc->alloc;
		if (new_alloc == 0)
			new_alloc = 128;	/* start at 128 bytes */
		else
			new_alloc *= 2;
		/* space for +1 */
		new_buf = realloc(acc->buf, new_alloc + 1);
		if (!new_buf)
			return -1;
		acc->buf = new_buf;
		acc->alloc = new_alloc;
	}
	acc->buf[acc->size++] = c;
	acc->buf[acc->size] = '\0';
	return 0;
}
