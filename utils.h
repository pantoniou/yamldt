#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <stdio.h>

/* maximum buffer for c2str */
#define C2STR_BUF_MAX	5

bool isesc(char c);
bool is_printable_string(const void *data, int len);
char *c2str(char c, char *buf, int bufsz);
int quoted_strlen(const char *str);

/* negative on error, \0 on EOF */
int esc_getc(const char **sp);
/* -1 on error, -2 on unterminated escape */
int esc_strlen(const char *s);
char *esc_getstr(const char *s, char *buf, int bufsz);

/* from linux kernel */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(_x) (sizeof(_x)/sizeof(_x[0]))
#endif

#ifndef ALIGN
#define ALIGN(x, a)	(((x) + ((a) - 1)) & ~((a) - 1))
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})
#endif

char **str_to_argv(const char *binary, const char *str);
int compile(const char *text, size_t size,
	    const char *compiler, const char *flags,
	    void **output, size_t *output_size);

#if defined(__APPLE__) && (_POSIX_C_SOURCE < 200809L)
FILE *open_memstream(char **ptr, size_t *sizeloc);
void *memrchr(const void *s, int c, size_t n);
#endif

/* some color escapes */
#define RED "\x1b[31;1m"
#define GREEN "\x1b[32;1m"
#define YELLOW "\x1b[33;1m"
#define BLUE "\x1b[34;1m"
#define MAGENTA "\x1b[35;1m"
#define CYAN "\x1b[36;1m"
#define WHITE "\x1b[37;1m"
#define RESET "\x1b[0m"

/* accumulator */

struct acc_state {
	char *buf;
	size_t alloc;
	size_t size;
};

static inline void acc_reset(struct acc_state *acc)
{
	acc->size = 0;
}

static inline size_t acc_get_size(struct acc_state *acc)
{
	return acc->size;
}

static inline const char *acc_get(struct acc_state *acc)
{
	/* return empty string if empty */
	if (!acc->buf || !acc->size)
		return "";
	return acc->buf;
}

static inline void acc_setup(struct acc_state *acc)
{
	acc->buf = NULL;
	acc->alloc = 0;
	acc->size = 0;
}

static inline void acc_cleanup(struct acc_state *acc)
{
	if (acc->buf)
		free(acc->buf);
}

int acc_add(struct acc_state *acc, char c);

#endif
