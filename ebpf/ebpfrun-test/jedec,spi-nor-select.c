/*
 * filter method for jedec,spi-nor
 *
 */
#include <stdint.h>
#include <stdbool.h>

#ifndef NULL
#define NULL 0
#endif
/* never accessed directly but the pointers are valid keys */
struct node;
struct property;
struct ref;

static int (*callback)(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4) =
        (void *) 1;

static int (*bpf_printf)(const char *fmt, ...) =
        (void *) 2;

static int64_t (*get_int)(struct node *np, const char *name, bool *existsp) = 
        (void *) 3;

static bool (*get_bool)(struct node *np, const char *name, bool *existsp) = 
        (void *) 4;

static const char *(*get_str)(struct node *np, const char *name, bool *existsp) = 
        (void *) 5;

static const char **(*get_strseq)(struct node *np, const char *name, bool *existsp) = 
        (void *) 6;

static bool (*streq)(const char *str1, const char *str2) =
        (void *) 7;

static bool (*anystreq)(const char **strv, const char *str2) =
        (void *) 8;

static struct node *(*get_parent)(struct node *np) =
        (void *) 9;

static const int64_t *(*get_intseq)(struct node *np, const char *name, int64_t *countp, bool *existsp) =
        (void *) 10;

/* prolog for jedec,spi-nor */
int select(struct node *np)
{
    bool exists;

    {
    const char **v = get_strseq(np, "compatible", &exists);
    
    if (!exists)
        return -1;
    
    /* for compatible from jedec,spi-nor rule */
    if (!(
        anystreq(v,  "at25df321a") ||
        anystreq(v,  "at25df641") ||
        anystreq(v, "at26df081a") ||
        anystreq(v,   "mr25h256") ||
        anystreq(v,    "mr25h10") ||
        anystreq(v,    "mr25h40") ||
        anystreq(v, "mx25l4005a") ||
        anystreq(v, "mx25l1606e") ||
        anystreq(v, "mx25l6405d") ||
        anystreq(v,"mx25l12805d") ||
        anystreq(v,"mx25l25635e") ||
        anystreq(v,    "n25q064") ||
        anystreq(v, "n25q128a11") ||
        anystreq(v, "n25q128a13") ||
        anystreq(v,   "n25q512a") ||
        anystreq(v, "s25fl256s1") ||
        anystreq(v,  "s25fl512s") ||
        anystreq(v, "s25sl12801") ||
        anystreq(v,  "s25fl008k") ||
        anystreq(v,  "s25fl064k") ||
        anystreq(v,"sst25vf040b") ||
        anystreq(v,     "m25p40") ||
        anystreq(v,     "m25p80") ||
        anystreq(v,     "m25p16") ||
        anystreq(v,     "m25p32") ||
        anystreq(v,     "m25p64") ||
        anystreq(v,    "m25p128") ||
        anystreq(v,     "w25x80") ||
        anystreq(v,     "w25x32") ||
        anystreq(v,     "w25q32") ||
        anystreq(v,     "w25q64") ||
        anystreq(v,   "w25q32dw") ||
        anystreq(v,   "w25q80bl") ||
        anystreq(v,    "w25q128") ||
        anystreq(v,    "w25q256")
    ))
      return -1000 - 0;
    
    }
    {
    const char *v = get_str(np, "status", &exists);
    
    if (!exists)
        goto skip_1;
    
    /* for status from device-compatible rule */
    if (!(
        !exists || streq(v, "okay") || streq(v, "ok")
    ))
      return -1000 - 1;
    skip_1:
      do { } while(0); /* fix goto that requires a statement */
    
    }

/* comment here due to YAML formatting */
    return 0;
}
/* jedec,spi-nor ends */
