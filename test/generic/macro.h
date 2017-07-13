#ifndef MACRO_H
#define MACRO_H

#if !defined(__DTS__) && !defined(__YAML__)
#error Only included from DTS or YAML
#endif

#define MUX_0 10
#define MUX_1 20

#define OPT_BIG 100
#define OPT_SMALL 200

#define MACRO(x, y) ((x) | (y))

#endif
