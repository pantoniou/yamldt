#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>

/* maximum buffer for c2str */
#define C2STR_BUF_MAX	5

bool isesc(char c);
bool is_printable_string(const void *data, int len);
char *c2str(char c, char *buf, int bufsz);
int quoted_strlen(const char *str);
char get_escape_char(const char *s, int *i);

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

#endif
