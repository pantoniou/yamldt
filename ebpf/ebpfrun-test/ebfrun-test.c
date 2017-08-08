#include <stdint.h>

/* declare two methods */
static int (*callback)(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4) =
        (void *) 1;

static int (*bpf_printf)(const char *fmt, ...) =
        (void *) 2;

/* variable in .data */
uint64_t val = 101;

/* variable in .bss (compiler bug requires the section attribute) */
uint64_t in_bss __attribute__((section(".bss")));

uint64_t entry(void *foo)
{
		uint64_t i;
		uint64_t j;

		j = foo ? *(uint64_t *)foo : 10;
		for (i = 0; i < j; i++)
				bpf_printf("Hello %s %d %s %d\n", "world", 12 + i, "multiple", 14);
		return 1;
}
