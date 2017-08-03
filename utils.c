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

#include <stdio.h>

bool long_opt_consume(int *argcp, char **argv, 
		      const struct option *opts, int *optindp,
		      const char *optarg, int val, int option_index)
{
	int argc = *argcp;
	int optind = *optindp;
	const struct option *opt;
	int consume;

	/* find out whether to consume one or two args */
	if (option_index < 0) {
		/* short option, find long option */
		for (opt = opts; opt->name; opt++)
			if (opt->val == val) {
				option_index = opt - opts;
				break;
			}
	}

	/* don't consume unrecognized option */
	if (option_index < 0)
		return false;

	consume = 1;
	if (opts[option_index].has_arg == required_argument &&
		optind > 0 && optarg && !strcmp(optarg, argv[optind-1]))
		consume++;

	memmove(&argv[optind - consume], &argv[optind],
			(argc - optind + 1) * sizeof(*argv));

	argc -= consume;
	optind -= consume;

	*argcp = argc;
	*optindp = optind;

	return true;
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
	char **argv;

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

