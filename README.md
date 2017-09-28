# yamldt

+`yamldt` is a YAML/DTS to DT blob generator/compiler and validator.
The YAML schema is functionaly equivalent to DTS and supports all DTS features,
while as a DTS compiler is bit-exact compatible with DTC.

Validation is performed against a YAML schema that defines properties
and constraints. A checker uses the schema to generate small code fragments that
are compiled to ebpf and executed for the specific validation of each
DT node the rule selects in the output tree.

`yamldt` parses a device tree description (source) file in YAML/DTS format
and outputs a device tree blob (which can be bit-exact to the one generated
from the reference dtc compiler if the -C option is used).

# dts2yaml

An automatic DTS to YAML conversion tool, that works on standard DTS
files which use the preprocessor. Capable of detecting macro usage and
advanced DTS concepts, like property/nodes deletes etc.

Conversion is accurate as long as the source file still looks like a
DTS source (i.e. not using extremely complex macros).

## Rationale

A DT aware YAML schema is a good fit as a DTS syntax alternative.

YAML is a human-readable data serialization language and is expressive
enough to cover all DTS source features.

Simple YAML files are just key value pairs that are very easy to parse, even
without using a formal YAML parser. YAML streams are containing documents
separated by the --- marker. This model is a good fit for DT since one may
simply append few lines of text in a given YAML stream to modify it.
In addition, composition of YAML files in restricted environments may be as
simple be appending a few lines of text to an existing YAML file.

The parsers of YAML are very mature, as YAML was first released in 2001.
It is currently in wide-spread use and schema validation tools are available and common.
YAML support is available for every major programming language.

The following projects currently use YAML as their configuration format:

1. [github](https://github.com/github/linguist/blob/master/lib/linguist/languages.yml)
2. [openstack](https://github.com/openstack/governance/blob/master/reference/projects.yaml)
3. [jenkins](https://wiki.jenkins.io/display/JENKINS/YAML+Project+Plugin)
4. [yedit](https://github.com/oyse/yedit/wiki)

Data in YAML can easily be converted to and from other formats making
it convertable to formats which future tools may understand.

More importantly YAML offers (an optional) type information for each
property item, which is crucial for thorough validation and checking
against device tree bindings (once the bindings are converted to a
machine readable format, preferably YAML).

yamldt implements a schema checker partly based on an RFC posted
on the mainline linux-kernel list some years ago by Rob Herring.

## Validation

`yamldt` is capable of performing validation of DT constructs using
a C-based eBPF checker. eBPF code fragments are assembled that
can perform type checking of properties and enforce arbitrary value
constraints while fully supporting inheritance.

As an example, here's how the validation of a given fragment
works using on a jedec,spi-nor node:

```yaml
m25p80@0:
  compatible: "s25fl256s1"
  spi-max-frequency: 76800000
  reg: 0
  spi-tx-bus-width: 1
  spi-rx-bus-width: 4
  "#address-cells": 1
  "#size-cells": 1
```

The binding for this is:

```yaml
%YAML 1.1
---
jedec,spi-nor:
  version: 1

  title: >
    SPI NOR flash: ST M25Pxx (and similar) serial flash chips

  maintainer:
    name: Unknown

  inherits: *spi-slave

  properties:
    reg:
      category: required
      type: int
      description: chip select address of device

    compatible: &jedec-spi-nor-compatible
      category: required
      type: strseq
      description: >
        May include a device-specific string consisting of the
        manufacturer and name of the chip. A list of supported chip
        names follows.
        Must also include "jedec,spi-nor" for any SPI NOR flash that can
        be identified by the JEDEC READ ID opcode (0x9F).
      constraint: |
        anystreq(v, "at25df321a") ||
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

    spi-max-frequency:
      category: required
      type: int
      description: Maximum frequency of the SPI bus the chip can operate at
      constraint: |
        v > 0 && v < 100000000

    m25p,fast-read:
      category: optional
      type: bool
      description: >
        Use the "fast read" opcode to read data from the chip instead
        of the usual "read" opcode. This opcode is not supported by
        all chips and support for it can not be detected at runtime.
        Refer to your chips' datasheet to check if this is supported
        by your chip.

  example:
    dts: |
      flash: m25p80@0 {
          #address-cells = <1>;
          #size-cells = <1>;
          compatible = "spansion,m25p80", "jedec,spi-nor";
          reg = <0>;
          spi-max-frequency = <40000000>;
          m25p,fast-read;
      };
    yaml: |
      m25p80@0: &flash
        "#address-cells": 1
        "#size-cells": 1
        compatible: [ "spansion,m25p80", "jedec,spi-nor" ]
        reg: 0;
        spi-max-frequency: 40000000
        m25p,fast-read: true
```

Note the constraint rule matches on any compatible string in the
given list. This binding inherits from spi-slave as indicated by the line: `inherits: *spi-slave`

`*spi-slave` is standard YAML reference notation which points to
the spi-slave binding, pasted here for convenience:

```yaml
%YAML 1.1
---
spi-slave: &spi-slave
  version: 1

  title: SPI Slave Devices

  maintainer:
    name: Mark Brown <broonie@kernel.org>

  inherits: *device-compatible

  class: spi-slave
  virtual: true

  description: >
    SPI (Serial Peripheral Interface) slave bus devices are children of
    a SPI master bus device.

  # constraint: |+
  #  class_of(parent(n), "spi")

  properties:
    reg:
      category: required
      type: int
      description: chip select address of device

    compatible:
      category: required
      type: strseq
      description: compatible strings

    spi-max-frequency:
      category: required
      type: int
      description: Maximum SPI clocking speed of device in Hz

    spi-cpol:
      category: optional
      type: bool
      description: >
        Boolean property indicating device requires
        inverse clock polarity (CPOL) mode

    spi-cpha:
      category: optional
      type: bool
      description: >
        Boolean property indicating device requires
        shifted clock phase (CPHA) mode

    spi-cs-high:
      category: optional
      type: bool
      description: >
        Boolean property indicating device requires
        chip select active high

    spi-3wire:
      category: optional
      type: bool
      description: >
        Boolean property indicating device requires
        3-wire mode.

    spi-lsb-first:
      category: optional
      type: bool
      description: >
        Boolean property indicating device requires
        LSB first mode.

    spi-tx-bus-width:
      category: optional
      type: int
      constraint: v == 1 || v == 2 || v == 4
      description: >
        The bus width(number of data wires) that
        used for MOSI. Defaults to 1 if not present.

    spi-rx-bus-width:
      category: optional
      type: int
      constraint: v == 1 || v == 2 || v == 4
      description: >
        The bus width(number of data wires) that
        used for MISO. Defaults to 1 if not present.

  notes: >
    Some SPI controllers and devices support Dual and Quad SPI transfer mode.
    It allows data in the SPI system to be transferred in 2 wires(DUAL) or
    4 wires(QUAD).
    Now the value that spi-tx-bus-width and spi-rx-bus-width can receive is
    only 1(SINGLE), 2(DUAL) and 4(QUAD). Dual/Quad mode is not allowed when
    3-wire mode is used.
    If a gpio chipselect is used for the SPI slave the gpio number will be
    passed via the SPI master node cs-gpios property.

  example:
    dts: |
      spi@f00 {
          ethernet-switch@0 {
              compatible = "micrel,ks8995m";
              spi-max-frequency = <1000000>;
              reg = <0>;
          };

          codec@1 {
              compatible = "ti,tlv320aic26";
              spi-max-frequency = <100000>;
              reg = <1>;
          };
      };
    yaml: |
      spi@f00:
        ethernet-switch@0:
          compatible: "micrel,ks8995m"
          spi-max-frequency: 1000000
          reg: 0

        codec@1:
          compatible: "ti,tlv320aic26"
          spi-max-frequency: 100000
          reg: 1
```

Note the `&spi-slave` anchor, this is what it's used to refer to
other parts of the schema.

The SPI slave binding defines a number of properties that all
inherited bindings include. This in turn inherits from `device-compatible`
which is this:

```yaml
%YAML 1.1
---
device-compatible: &device-compatible
  title: Contraint for devices with compatible properties
  # select node for checking when the compatible constraint and
  # the device status enable constraint are met.
  selected: [ "compatible", *device-status-enabled ]

  class: constraint
  virtual: true
```

Note that device-compatible is a binding that all devices
defined with the DT schema will inherit from.

The `selected` property will be used to generate a select()
method that will be used to to find out whether a node should be
checked against a given rule.

The `selected` rule defines two constraints. The first one
is the name of a variable in a derived binding that all
its constraints must satisfy; in this case it's the
jedec,spi-nor compatible constraint in the binding above.
The selected constraint is a reference to the
`device-status-enabled` constrainst defined at:

```yaml
%YAML 1.1
---
device-enabled:
  title: Contraint for enabled devices

  class: constraint
  virtual: true

  properties:
    status: &device-status-enabled
      category: optional
      type: str
      description: Marks device state as enabled
      constraint: |
        !exists || streq(v, "okay") || streq(v, "ok")
```

The `device-enabled` constraint checks where the node is
enabled in DT parlance.

Taking those two constraints together yamldt generates an enable
method filter which triggers on an enable device node that
matches any of the compatible strings defined in the jedec,spi-nor
binding.

The check method will be generated by collecting all the
property constraints (category, type and explicit value constraints).

Note how in the above example a variable (v) is used as the current property value. The
generated methods will provide it, initialized to the current value to the constraint.

Note that custom, manually written select and check methods
are possible but their usage is not recommended for simple types.

## Installation

Install libyaml-dev and the standard autoconf/automake generation tools.

Compile by the standard `./autogen.sh`, `./configure` and make cycle.

For a complete example of a port of a board DTS file to YAML take a
look in the `port/` directory

You can pass a CPP processed file to `yamldt` and everything works
as expected.

The bundled validator requires a working ebpf compiler and libelf.
Known good working clang versions with ebpf support are 4.0 and higher.

# Usage

The `yamldt` options available are:

```
yamldt [options] <input-file>
 options are:
   -q, --quiet           Suppress; -q (warnings) -qq (errors) -qqq (everything)
   -I, --in-format=X     Input format type X=[auto|yaml|dts]
   -O, --out-format=X    Output format type X=[auto|yaml|dtb|dts|null]
   -o, --out=X           Output file
   -c                    Don't resolve references (object mode)
   -g, --codegen         Code generator configuration file
       --schema          Use schema (all yaml files in dir/)
       --save-temps      Save temporary files
       --schema-save     Save schema to given file
       --color           [auto|off|on]
       --debug           Debug messages
   -h, --help            Help
   -v, --version         Display version

   DTB specific options

   -V, --out-version=X   DTB blob version to produce (only 17 supported)
   -C, --compatible      Bit-exact DTC compatibility mode
   -@, --symbols         Generate symbols node
   -A, --auto-alias      Generate aliases for all labels
   -R, --reserve=X       Make space for X reserve map entries
   -S, --space=X         Make the DTB blob at least X bytes long
   -a, --align=X         Make the DTB blob align to X bytes
   -p, --pad=X           Pad the DTB blob with X bytes
   -H, --phandle=X       Set phandle format [legacy|epapr|both]
   -W, --warning=X       Enable/disable warning (NOP)
   -E, --error=X         Enable/disable error (NOP)
   -b, --boot-cpu=X      Force boot cpuid to X
```

`-q/--quiet` suppresses message output.

The `-I/--in-format` option selects the input format type. By
default is set to auto which is capable of selecting based on
file extension and input format source patterns.

The `-O/--out-format` option selects the output format type. By
default is set to auto which uses the output file extension.

`-o/--out` set the output file.

The `-c` option causes unresolved references to remain in the
output file resuling in an object file. If the output format
is set to DTB/DTS it will generate an overlay, if set to yaml
results to a YAML file which can be subsequently recompiled
as an intermediate object file.

The `-g/--codegen` option will use the given YAML file(s)
(or dir/ as in the schema option) as input for the code generator.

The `--schema` option will use the given file(s) as
input for the checker. As an extension, if given a directory name
with a terminating slash (i.e. dir/) it will recursively collect
and use all YAML files within.

The `--save-temps` option will save all intermediate files/blobs.

`schema-save` will save the processed schema and codegen file including
all compiled validation filters. Using it speeds validation of
multiple files since it can be used as an input via the --schema option.

`--color` controls color output in the terminal, while `--debug` enables
the generation of a considerable amount of debugging messages.

The following DTB specific options are supported:

`-V/--out-version` selects the DTB blob version; currently only version 17
is supported.

The `-C/--compatible` option generates a bit-exact DTB file as the DTC
compiler.

The `-@/--symbols` and `-A/--auto-alias` options generate a __symbols__ and
alias entries for all the defined labels in the source files.

The `-R/--reserve`, `-S/--space`, `-a/--align` and `-p/--pad` options work
the same way as in DTC. `-R` add reserve memreserve entries, `-S` adds extra
space, `-a` aligns and `-p` pads extra space end of the DTB blob.

The `-H/--phandle` option selects either legacy/epapr or both phandle styles.

The `-W/--warning` and `-E/--error` options are there for command line compatibility
with dtc and are ignored.

Finally `-d/--boot-cpu` forces the boot cpuid.

Automatic suffix detection does what you expect (i.e. an output file
ending in .dtb if selecting the DTB generation option, .yaml if selecting the yaml
generation option and so on).

Given a source file in YAML `foo.yaml` you generate a dtb file
with

```yaml
# foo.yaml
foo: &foo
  bar: true
  baz:
   - 12
   - 8
   - *foo
  frob: [ "hello", "there" ]
```

Process with yamldt

```
$ yamldt -o foo.dtb foo.yaml
$ ls -l foo.dtb
-rw-rw-r-- 1 panto panto 153 Jul 27 18:50 foo.dtb
$ fdtdump foo.dtb
/dts-v1/;
// magic:		0xd00dfeed
// totalsize:		0xe1 (225)
// off_dt_struct:	0x38
// off_dt_strings:	0xc8
// off_mem_rsvmap:	0x28
// version:		17
// last_comp_version:	16
// boot_cpuid_phys:	0x0
// size_dt_strings:	0x19
// size_dt_struct:	0x90

/ {
    foo {
        bar;
        baz = <0x0000000c 0x00000008 0x00000001>;
        frob = "hello", "there";
        phandle = <0x00000001>;
    };
    __symbols__ {
        foo = "/foo";
    };
};

```

The dts2yaml tool converts an existing dts/dtsi file to YAML
format. It is capable of detecting macro usage so you can use it
on both raw DTS files as well as DTS files that use the preprocessor.

```
dts2yaml [options] [input-file]
 options are:
   -o, --output        Output file
   -t, --tabs		Set tab size (default 8)
   -s, --shift		Shift when outputing YAML (default 2)
   -l, --leading	Leading space for output
   -d, --debug		Enable debug messages
       --silent        Be really silent
       --color         [auto|off|on]
   -r, --recursive     Generate DTS/DTSI included files
   -h, --help		Help
       --color         [auto|off|on]
```

All the input files will be converted to yaml format; if no output option is
given the output will be named according to the input filename. So foo.dts will
be foo.yaml and foo.dtsi foo.yamli.

The recursive option is going to convert all included files as well that have
a dts/dtsi extension.

## Test suite

To run the test-suite you will need a relative recent DTC compiler.
YAML patches are not required anymore.

The test-suite first converts all the DTS files in the Linux kernel for
all architectures to YAML format using dts2yaml. Afterwards it compiles the YAML
files with `yamldt` and the DTS files with DTC.

The resulting dtb files are bit-exact because the `-C` option is used.

Run `make check` to run the test suite.
Run `make validate` to run the test suite and perform schema
validation checks. It is recommended to use the `--keep-going`
flag to continue checking even in the presence of validation
errors.

Currently out of 1379 DTS files, only 6 fail conversion;

```
exynos3250-monk exynos4412-trats2 exynos3250-rinato exynos5433-tm2
exynos5433-tm2e
```

All 6 use a complex pin mux macro declaration that is no possible
to be automatically converted.

# Workflow

It is expected that the first thing a user of `yamldt` would want
to do is to convert an existing DTS configuration to YAML.

The following example uses the beaglebone black and the
am335x-boneblack.dts source as located in the port/ directory.

Compile the original DTS source with DTC

```
$  cc -E  -I ./ -I ../../port -I ../../include -I ../../include/dt-bindings/input \
	-nostdinc -undef -x assembler-with-cpp -D__DTS__ am335x-boneblack.dts 
	| dtc -@ -q -I dts -O dtb - -o am335x-boneblack.dtc.dtb
```

Use dts2yaml to convert to yaml
```
$ dts2yaml -r am335x-boneblack.dts
$ ls *.yaml*
am335x-boneblack-common.yamli  am335x-bone-common.yamli  am33xx-clocks.yamli
am33xx.yamli  tps65217.yamli
```

Note the recursive option automatically generates the dependent include files.

```
$ cc -I ./ -I ../../port -I ../../include -I ../../include/dt-bindings/input \
	-nostdinc -undef -x assembler-with-cpp -D__DTS__ am335x-boneblack.yaml | \
	../../yamldt -C -@ - -o am335x-boneblack.dtb 
```

```
$ ls -l *.dtb
-rw-rw-r-- 1 panto panto 50045 Jul 27 19:10 am335x-boneblack.dtb
-rw-rw-r-- 1 panto panto 50045 Jul 27 19:07 am335x-boneblack.dtc.dtb
$ md5sum *.dtb
3bcf838dc9c32c196f66870b7e6dfe81  am335x-boneblack.dtb
3bcf838dc9c32c196f66870b7e6dfe81  am335x-boneblack.dtc.dtb
```

Compiling without the -C option resulting in the same functional file
but is slightly smaller due to better string table optimization.

```
$ yamldt am335x-boneblack.dtc.yaml -o am335x-boneblack.dtb
$ ls -l *.dtb
-rw-rw-r-- 1 panto panto 50003 Jul 27 19:12 am335x-boneblack.dtb
-rw-rw-r-- 1 panto panto 50045 Jul 27 19:07 am335x-boneblack.dtc.dtb
```

Plese note that the CPP command line is the same, so no changes to header files
is required. dts2yaml is smart enough to detect macro usage and convert from
the space delimited form that DTC uses to the comma one that YAML does.

# yamldt as a DTC compiler

yamldt supports almost all DTC options so using it as a DTC replacement
is straightforward.

Using it for compiling in Linux Kernel DTS files is as simple as:

```
$ make DTC=yamldt dtbs
```

Note that by default the compatible option (-C) so if you need to be
bit-compatible with DTC pass the -C flag as follows:

```
$ make DTC=yamldt DTC_FLAGS="-C"
```

Generally `yamldt` is a little bit faster than `dtc` and generates somewhat
smaller DTB files (if not using the -C option). However due to internally
tracking all parsed tokens and their locations in files it is capable
of generating accurate error messages that are parseable by all editors
for automatic movement to the error by a programmer's editor like vim.

For instance a file containing an error:

```
/* duplicate label */
/dts-v1/;
/ {
	a: foo { foo; };
	a: bar { bar; };
};
```

yamldt will generate the following error:

```
$ yamldt -I dts -o dts -C duplabel.dts
duplabel.dts:8:2: error: duplicate label a at "/bar"
  a: bar {
  ^
duplabel.dts:4:2: error: duplicate label a is defined also at "/foo"
  a: foo {
  ^
```

while dtc will generate:

```
$ yamldt -I dts -o dts -C duplabel.dts
dts: ERROR (duplicate_label): Duplicate label 'a' on /bar and /foo
ERROR: Input tree has errors, aborting (use -f to force output)
```

Known features of DTC that are not available are:

* Only version 17 DT blobs are supported. Passing a -V argument requesting a
  different one will result in error.
* Assembly output is not supported.
* Assembly and filesystem inputs are not supported.
* The sort option is not yet supported.
* The warning and error options are accepted but they don't do anything.
  yamldt uses a validation schema for application specific error and warnings
  so those options are superfluous.

## Notes on DTS to DTS conversion

The conversion from DTS is straight forward:

For example:

```
/* foo.dts */
/ {
	foo = "bar";
	#cells = <2>;
	phandle-ref = <&ref 1>;
	ref: refnode { baz; };
};
```

```yaml
# foo.yaml
foo: "bar"
"#cells": 2
phandle-ref: [ *ref 1 ]
refnode: &ref
  baz: true
```

Major differences between DTS & YAML:

* YAML is using # as a comment marker, therefore properties with
  a # prefix get converted to explicit string literals:

```
#cells = <0>;
```
to YAML

```yaml
"#cells": 0
```

* YAML is indentation sensitive, but it is a JSON superset.
  Therefore the following are equivalent:

```yaml
foo: [ 1, 2 ]
```
```yaml
foo:
 - 1
 - 2
```

* The labels in DTS are defined and used as

```
foo: node { baz; };
bar = <&foo>;
```

In YAML the equivalent methods are called anchors and are defined
as follows:

```yaml
node: &foo
  baz: true
bar: *foo
```

* Explicit tags in YAML are using !, so the following

```
mac = [ 0 1 2 3 4 5 ];
```

Is used like this in YAML

```yaml
mac: !int8 [ 0, 1, 2, 3, 4, 5 ]
```

* DTS uses spaces to seperate array elements, YAML uses either
  indentation or commas in JSON form. Note that yamldt is smart
  enough to detect the DTS form and automatically convert in
  most cases.

```
pinmux = <0x00 0x01>;
```

In YAML:

```yaml
pinmux:
  - 0x00
  - 0x01
```
or

```yaml
pinmux: [ 0x00, 0x01 ]
```

* Path references (<&/foo>) automatically are converted to pseudo
  YAML anchors (of the form yaml\_pseudo\_\_n\_\_)

```
/ {
	foo { bar; };
};
ref = <&/foo>;
```

In YAML:

```yaml
foo: &yaml_pseudo__0__
ref: *foo
```

* Integer expression evaluation, similar in manner to that which the CPP preprocessor
  performs, is available. This is required in order for macros to
  work. For example:

  Given the following two files

```c
/* add.h */
#define ADD(x, y) ((x) + (y))
```

```yaml
# macro-use.yaml

#include "add.h"

result: ADD(10, 12)
```

  The output after the cpp preprocessor pass:

```yaml
result: ((10) + (12))
```

  Parsing with `yamldt` to DTB will generate a property

```
result = <22>;
```

## Example conversion

The Beaglebone Black DTS `am335x-bone-common.dtsi` source file

```
/*
 * Copyright (C) 2012 Texas Instruments Incorporated - http://www.ti.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/ {
	cpus {
		cpu@0 {
			cpu0-supply = <&dcdc2_reg>;
		};
	};

	memory@80000000 {
		device_type = "memory";
		reg = <0x80000000 0x10000000>; /* 256 MB */
	};

	chosen {
		stdout-path = &uart0;
	};

	leds {
		pinctrl-names = "default";
		pinctrl-0 = <&user_leds_s0>;

		compatible = "gpio-leds";

		led2 {
			label = "beaglebone:green:heartbeat";
			gpios = <&gpio1 21 GPIO_ACTIVE_HIGH>;
			linux,default-trigger = "heartbeat";
			default-state = "off";
		};

		led3 {
			label = "beaglebone:green:mmc0";
			gpios = <&gpio1 22 GPIO_ACTIVE_HIGH>;
			linux,default-trigger = "mmc0";
			default-state = "off";
		};

		led4 {
			label = "beaglebone:green:usr2";
			gpios = <&gpio1 23 GPIO_ACTIVE_HIGH>;
			linux,default-trigger = "cpu0";
			default-state = "off";
		};

		led5 {
			label = "beaglebone:green:usr3";
			gpios = <&gpio1 24 GPIO_ACTIVE_HIGH>;
			linux,default-trigger = "mmc1";
			default-state = "off";
		};
	};

	vmmcsd_fixed: fixedregulator0 {
		compatible = "regulator-fixed";
		regulator-name = "vmmcsd_fixed";
		regulator-min-microvolt = <3300000>;
		regulator-max-microvolt = <3300000>;
	};
};

&am33xx_pinmux {
	pinctrl-names = "default";
	pinctrl-0 = <&clkout2_pin>;

	user_leds_s0: user_leds_s0 {
		pinctrl-single,pins = <
			AM33XX_IOPAD(0x854, PIN_OUTPUT_PULLDOWN | MUX_MODE7)	/* gpmc_a5.gpio1_21 */
			AM33XX_IOPAD(0x858, PIN_OUTPUT_PULLUP | MUX_MODE7)	/* gpmc_a6.gpio1_22 */
			AM33XX_IOPAD(0x85c, PIN_OUTPUT_PULLDOWN | MUX_MODE7)	/* gpmc_a7.gpio1_23 */
			AM33XX_IOPAD(0x860, PIN_OUTPUT_PULLUP | MUX_MODE7)	/* gpmc_a8.gpio1_24 */
		>;
	};

	i2c0_pins: pinmux_i2c0_pins {
		pinctrl-single,pins = <
			AM33XX_IOPAD(0x988, PIN_INPUT_PULLUP | MUX_MODE0)	/* i2c0_sda.i2c0_sda */
			AM33XX_IOPAD(0x98c, PIN_INPUT_PULLUP | MUX_MODE0)	/* i2c0_scl.i2c0_scl */
		>;
	};

	i2c2_pins: pinmux_i2c2_pins {
		pinctrl-single,pins = <
			AM33XX_IOPAD(0x978, PIN_INPUT_PULLUP | MUX_MODE3)	/* uart1_ctsn.i2c2_sda */
			AM33XX_IOPAD(0x97c, PIN_INPUT_PULLUP | MUX_MODE3)	/* uart1_rtsn.i2c2_scl */
		>;
	};

	uart0_pins: pinmux_uart0_pins {
		pinctrl-single,pins = <
			AM33XX_IOPAD(0x970, PIN_INPUT_PULLUP | MUX_MODE0)	/* uart0_rxd.uart0_rxd */
			AM33XX_IOPAD(0x974, PIN_OUTPUT_PULLDOWN | MUX_MODE0)	/* uart0_txd.uart0_txd */
		>;
	};

	clkout2_pin: pinmux_clkout2_pin {
		pinctrl-single,pins = <
			AM33XX_IOPAD(0x9b4, PIN_OUTPUT_PULLDOWN | MUX_MODE3)	/* xdma_event_intr1.clkout2 */
		>;
	};

	cpsw_default: cpsw_default {
		pinctrl-single,pins = <
			/* Slave 1 */
			AM33XX_IOPAD(0x910, PIN_INPUT_PULLUP | MUX_MODE0)	/* mii1_rxerr.mii1_rxerr */
			AM33XX_IOPAD(0x914, PIN_OUTPUT_PULLDOWN | MUX_MODE0)	/* mii1_txen.mii1_txen */
			AM33XX_IOPAD(0x918, PIN_INPUT_PULLUP | MUX_MODE0)	/* mii1_rxdv.mii1_rxdv */
			AM33XX_IOPAD(0x91c, PIN_OUTPUT_PULLDOWN | MUX_MODE0)	/* mii1_txd3.mii1_txd3 */
			AM33XX_IOPAD(0x920, PIN_OUTPUT_PULLDOWN | MUX_MODE0)	/* mii1_txd2.mii1_txd2 */
			AM33XX_IOPAD(0x924, PIN_OUTPUT_PULLDOWN | MUX_MODE0)	/* mii1_txd1.mii1_txd1 */
			AM33XX_IOPAD(0x928, PIN_OUTPUT_PULLDOWN | MUX_MODE0)	/* mii1_txd0.mii1_txd0 */
			AM33XX_IOPAD(0x92c, PIN_INPUT_PULLUP | MUX_MODE0)	/* mii1_txclk.mii1_txclk */
			AM33XX_IOPAD(0x930, PIN_INPUT_PULLUP | MUX_MODE0)	/* mii1_rxclk.mii1_rxclk */
			AM33XX_IOPAD(0x934, PIN_INPUT_PULLUP | MUX_MODE0)	/* mii1_rxd3.mii1_rxd3 */
			AM33XX_IOPAD(0x938, PIN_INPUT_PULLUP | MUX_MODE0)	/* mii1_rxd2.mii1_rxd2 */
			AM33XX_IOPAD(0x93c, PIN_INPUT_PULLUP | MUX_MODE0)	/* mii1_rxd1.mii1_rxd1 */
			AM33XX_IOPAD(0x940, PIN_INPUT_PULLUP | MUX_MODE0)	/* mii1_rxd0.mii1_rxd0 */
		>;
	};

	cpsw_sleep: cpsw_sleep {
		pinctrl-single,pins = <
			/* Slave 1 reset value */
			AM33XX_IOPAD(0x910, PIN_INPUT_PULLDOWN | MUX_MODE7)
			AM33XX_IOPAD(0x914, PIN_INPUT_PULLDOWN | MUX_MODE7)
			AM33XX_IOPAD(0x918, PIN_INPUT_PULLDOWN | MUX_MODE7)
			AM33XX_IOPAD(0x91c, PIN_INPUT_PULLDOWN | MUX_MODE7)
			AM33XX_IOPAD(0x920, PIN_INPUT_PULLDOWN | MUX_MODE7)
			AM33XX_IOPAD(0x924, PIN_INPUT_PULLDOWN | MUX_MODE7)
			AM33XX_IOPAD(0x928, PIN_INPUT_PULLDOWN | MUX_MODE7)
			AM33XX_IOPAD(0x92c, PIN_INPUT_PULLDOWN | MUX_MODE7)
			AM33XX_IOPAD(0x930, PIN_INPUT_PULLDOWN | MUX_MODE7)
			AM33XX_IOPAD(0x934, PIN_INPUT_PULLDOWN | MUX_MODE7)
			AM33XX_IOPAD(0x938, PIN_INPUT_PULLDOWN | MUX_MODE7)
			AM33XX_IOPAD(0x93c, PIN_INPUT_PULLDOWN | MUX_MODE7)
			AM33XX_IOPAD(0x940, PIN_INPUT_PULLDOWN | MUX_MODE7)
		>;
	};

	davinci_mdio_default: davinci_mdio_default {
		pinctrl-single,pins = <
			/* MDIO */
			AM33XX_IOPAD(0x948, PIN_INPUT_PULLUP | SLEWCTRL_FAST | MUX_MODE0)	/* mdio_data.mdio_data */
			AM33XX_IOPAD(0x94c, PIN_OUTPUT_PULLUP | MUX_MODE0)			/* mdio_clk.mdio_clk */
		>;
	};

	davinci_mdio_sleep: davinci_mdio_sleep {
		pinctrl-single,pins = <
			/* MDIO reset value */
			AM33XX_IOPAD(0x948, PIN_INPUT_PULLDOWN | MUX_MODE7)
			AM33XX_IOPAD(0x94c, PIN_INPUT_PULLDOWN | MUX_MODE7)
		>;
	};

	mmc1_pins: pinmux_mmc1_pins {
		pinctrl-single,pins = <
			AM33XX_IOPAD(0x960, PIN_INPUT | MUX_MODE7) /* GPIO0_6 */
		>;
	};

	emmc_pins: pinmux_emmc_pins {
		pinctrl-single,pins = <
			AM33XX_IOPAD(0x880, PIN_INPUT_PULLUP | MUX_MODE2) /* gpmc_csn1.mmc1_clk */
			AM33XX_IOPAD(0x884, PIN_INPUT_PULLUP | MUX_MODE2) /* gpmc_csn2.mmc1_cmd */
			AM33XX_IOPAD(0x800, PIN_INPUT_PULLUP | MUX_MODE1) /* gpmc_ad0.mmc1_dat0 */
			AM33XX_IOPAD(0x804, PIN_INPUT_PULLUP | MUX_MODE1) /* gpmc_ad1.mmc1_dat1 */
			AM33XX_IOPAD(0x808, PIN_INPUT_PULLUP | MUX_MODE1) /* gpmc_ad2.mmc1_dat2 */
			AM33XX_IOPAD(0x80c, PIN_INPUT_PULLUP | MUX_MODE1) /* gpmc_ad3.mmc1_dat3 */
			AM33XX_IOPAD(0x810, PIN_INPUT_PULLUP | MUX_MODE1) /* gpmc_ad4.mmc1_dat4 */
			AM33XX_IOPAD(0x814, PIN_INPUT_PULLUP | MUX_MODE1) /* gpmc_ad5.mmc1_dat5 */
			AM33XX_IOPAD(0x818, PIN_INPUT_PULLUP | MUX_MODE1) /* gpmc_ad6.mmc1_dat6 */
			AM33XX_IOPAD(0x81c, PIN_INPUT_PULLUP | MUX_MODE1) /* gpmc_ad7.mmc1_dat7 */
		>;
	};
};

&uart0 {
	pinctrl-names = "default";
	pinctrl-0 = <&uart0_pins>;

	status = "okay";
};

&usb {
	status = "okay";
};

&usb_ctrl_mod {
	status = "okay";
};

&usb0_phy {
	status = "okay";
};

&usb1_phy {
	status = "okay";
};

&usb0 {
	status = "okay";
	dr_mode = "peripheral";
	interrupts-extended = <&intc 18 &tps 0>;
	interrupt-names = "mc", "vbus";
};

&usb1 {
	status = "okay";
	dr_mode = "host";
};

&cppi41dma  {
	status = "okay";
};

&i2c0 {
	pinctrl-names = "default";
	pinctrl-0 = <&i2c0_pins>;

	status = "okay";
	clock-frequency = <400000>;

	tps: tps@24 {
		reg = <0x24>;
	};

	baseboard_eeprom: baseboard_eeprom@50 {
		compatible = "atmel,24c256";
		reg = <0x50>;

		#address-cells = <1>;
		#size-cells = <1>;
		baseboard_data: baseboard_data@0 {
			reg = <0 0x100>;
		};
	};
};

&i2c2 {
	pinctrl-names = "default";
	pinctrl-0 = <&i2c2_pins>;

	status = "okay";
	clock-frequency = <100000>;

	cape_eeprom0: cape_eeprom0@54 {
		compatible = "atmel,24c256";
		reg = <0x54>;
		#address-cells = <1>;
		#size-cells = <1>;
		cape0_data: cape_data@0 {
			reg = <0 0x100>;
		};
	};

	cape_eeprom1: cape_eeprom1@55 {
		compatible = "atmel,24c256";
		reg = <0x55>;
		#address-cells = <1>;
		#size-cells = <1>;
		cape1_data: cape_data@0 {
			reg = <0 0x100>;
		};
	};

	cape_eeprom2: cape_eeprom2@56 {
		compatible = "atmel,24c256";
		reg = <0x56>;
		#address-cells = <1>;
		#size-cells = <1>;
		cape2_data: cape_data@0 {
			reg = <0 0x100>;
		};
	};

	cape_eeprom3: cape_eeprom3@57 {
		compatible = "atmel,24c256";
		reg = <0x57>;
		#address-cells = <1>;
		#size-cells = <1>;
		cape3_data: cape_data@0 {
			reg = <0 0x100>;
		};
	};
};


/include/ "tps65217.dtsi"

&tps {
	/*
	 * Configure pmic to enter OFF-state instead of SLEEP-state ("RTC-only
	 * mode") at poweroff.  Most BeagleBone versions do not support RTC-only
	 * mode and risk hardware damage if this mode is entered.
	 *
	 * For details, see linux-omap mailing list May 2015 thread
	 *	[PATCH] ARM: dts: am335x-bone* enable pmic-shutdown-controller
	 * In particular, messages:
	 *	http://www.spinics.net/lists/linux-omap/msg118585.html
	 *	http://www.spinics.net/lists/linux-omap/msg118615.html
	 *
	 * You can override this later with
	 *	&tps {  /delete-property/ ti,pmic-shutdown-controller;  }
	 * if you want to use RTC-only mode and made sure you are not affected
	 * by the hardware problems. (Tip: double-check by performing a current
	 * measurement after shutdown: it should be less than 1 mA.)
	 */

	interrupts = <7>; /* NMI */
	interrupt-parent = <&intc>;

	ti,pmic-shutdown-controller;

	charger {
		interrupts = <0>, <1>;
		interrupt-names = "USB", "AC";
		status = "okay";
	};

	pwrbutton {
		interrupts = <2>;
		status = "okay";
	};

	regulators {
		dcdc1_reg: regulator@0 {
			regulator-name = "vdds_dpr";
			regulator-always-on;
		};

		dcdc2_reg: regulator@1 {
			/* VDD_MPU voltage limits 0.95V - 1.26V with +/-4% tolerance */
			regulator-name = "vdd_mpu";
			regulator-min-microvolt = <925000>;
			regulator-max-microvolt = <1351500>;
			regulator-boot-on;
			regulator-always-on;
		};

		dcdc3_reg: regulator@2 {
			/* VDD_CORE voltage limits 0.95V - 1.1V with +/-4% tolerance */
			regulator-name = "vdd_core";
			regulator-min-microvolt = <925000>;
			regulator-max-microvolt = <1150000>;
			regulator-boot-on;
			regulator-always-on;
		};

		ldo1_reg: regulator@3 {
			regulator-name = "vio,vrtc,vdds";
			regulator-always-on;
		};

		ldo2_reg: regulator@4 {
			regulator-name = "vdd_3v3aux";
			regulator-always-on;
		};

		ldo3_reg: regulator@5 {
			regulator-name = "vdd_1v8";
			regulator-always-on;
		};

		ldo4_reg: regulator@6 {
			regulator-name = "vdd_3v3a";
			regulator-always-on;
		};
	};
};

&cpsw_emac0 {
	phy_id = <&davinci_mdio>, <0>;
	phy-mode = "mii";
};

&mac {
	slaves = <1>;
	pinctrl-names = "default", "sleep";
	pinctrl-0 = <&cpsw_default>;
	pinctrl-1 = <&cpsw_sleep>;
	status = "okay";
};

&davinci_mdio {
	pinctrl-names = "default", "sleep";
	pinctrl-0 = <&davinci_mdio_default>;
	pinctrl-1 = <&davinci_mdio_sleep>;
	status = "okay";
};

&mmc1 {
	status = "okay";
	bus-width = <0x4>;
	pinctrl-names = "default";
	pinctrl-0 = <&mmc1_pins>;
	cd-gpios = <&gpio0 6 GPIO_ACTIVE_LOW>;
};

&aes {
	status = "okay";
};

&sham {
	status = "okay";
};

&rtc {
	clocks = <&clk_32768_ck>, <&clkdiv32k_ick>;
	clock-names = "ext-clk", "int-clk";
};
```

Is converted to the `am335x-bone-common.yaml` file

```yaml
# Copyright (C) 2012 Texas Instruments Incorporated - http://www.ti.com/
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.

cpus:
  cpu@0:
    cpu0-supply: *dcdc2_reg

memory@80000000:
  device_type: "memory"
  reg: [ 0x80000000, 0x10000000 ] # 256 MB

chosen:
  stdout-path: !pathref uart0

leds:
  pinctrl-names: "default"
  pinctrl-0: *user_leds_s0
  compatible: "gpio-leds"
  led2:
    label: "beaglebone:green:heartbeat"
    gpios: [ *gpio1, 21, GPIO_ACTIVE_HIGH ]
    linux,default-trigger: "heartbeat"
    default-state: "off"
  led3:
    label: "beaglebone:green:mmc0"
    gpios: [ *gpio1, 22, GPIO_ACTIVE_HIGH ]
    linux,default-trigger: "mmc0"
    default-state: "off"
  led4:
    label: "beaglebone:green:usr2"
    gpios: [ *gpio1, 23, GPIO_ACTIVE_HIGH ]
    linux,default-trigger: "cpu0"
    default-state: "off"
  led5:
    label: "beaglebone:green:usr3"
    gpios: [ *gpio1, 24, GPIO_ACTIVE_HIGH ]
    linux,default-trigger: "mmc1"
    default-state: "off"

fixedregulator0: &vmmcsd_fixed
  compatible: "regulator-fixed"
  regulator-name: "vmmcsd_fixed"
  regulator-min-microvolt: 3300000
  regulator-max-microvolt: 3300000

*am33xx_pinmux:
  pinctrl-names: "default"
  pinctrl-0: *clkout2_pin

  user_leds_s0: &user_leds_s0
    pinctrl-single,pins:
      - AM33XX_IOPAD(0x854, PIN_OUTPUT_PULLDOWN | MUX_MODE7)	# gpmc_a5.gpio1_21
      - AM33XX_IOPAD(0x858,   PIN_OUTPUT_PULLUP | MUX_MODE7)	# gpmc_a6.gpio1_22
      - AM33XX_IOPAD(0x85c, PIN_OUTPUT_PULLDOWN | MUX_MODE7)	# gpmc_a7.gpio1_23
      - AM33XX_IOPAD(0x860,   PIN_OUTPUT_PULLUP | MUX_MODE7)	# gpmc_a8.gpio1_24
  pinmux_i2c0_pins: &i2c0_pins
    pinctrl-single,pins:
      - AM33XX_IOPAD(0x988, PIN_INPUT_PULLUP | MUX_MODE0)	# i2c0_sda.i2c0_sda
      - AM33XX_IOPAD(0x98c, PIN_INPUT_PULLUP | MUX_MODE0)	# i2c0_scl.i2c0_scl
  pinmux_i2c2_pins: &i2c2_pins
    pinctrl-single,pins:
      - AM33XX_IOPAD(0x978, PIN_INPUT_PULLUP | MUX_MODE3)	# uart1_ctsn.i2c2_sda
      - AM33XX_IOPAD(0x97c, PIN_INPUT_PULLUP | MUX_MODE3)	# uart1_rtsn.i2c2_scl
  pinmux_uart0_pins: &uart0_pins
    pinctrl-single,pins:
      - AM33XX_IOPAD(0x970,    PIN_INPUT_PULLUP | MUX_MODE0)	# uart0_rxd.uart0_rxd
      - AM33XX_IOPAD(0x974, PIN_OUTPUT_PULLDOWN | MUX_MODE0)	# uart0_txd.uart0_txd
  pinmux_clkout2_pin: &clkout2_pin
    pinctrl-single,pins:
      - AM33XX_IOPAD(0x9b4, PIN_OUTPUT_PULLDOWN | MUX_MODE3)	# xdma_event_intr1.clkout2
  cpsw_default: &cpsw_default
    pinctrl-single,pins:
      # Slave 1
      - AM33XX_IOPAD(0x910, PIN_INPUT_PULLUP | MUX_MODE0)	# mii1_rxerr.mii1_rxerr
      - AM33XX_IOPAD(0x914, PIN_OUTPUT_PULLDOWN | MUX_MODE0)	# mii1_txen.mii1_txen
      - AM33XX_IOPAD(0x918, PIN_INPUT_PULLUP | MUX_MODE0)	# mii1_rxdv.mii1_rxdv
      - AM33XX_IOPAD(0x91c, PIN_OUTPUT_PULLDOWN | MUX_MODE0)	# mii1_txd3.mii1_txd3
      - AM33XX_IOPAD(0x920, PIN_OUTPUT_PULLDOWN | MUX_MODE0)	# mii1_txd2.mii1_txd2
      - AM33XX_IOPAD(0x924, PIN_OUTPUT_PULLDOWN | MUX_MODE0)	# mii1_txd1.mii1_txd1
      - AM33XX_IOPAD(0x928, PIN_OUTPUT_PULLDOWN | MUX_MODE0)	# mii1_txd0.mii1_txd0
      - AM33XX_IOPAD(0x92c, PIN_INPUT_PULLUP | MUX_MODE0)	# mii1_txclk.mii1_txclk
      - AM33XX_IOPAD(0x930, PIN_INPUT_PULLUP | MUX_MODE0)	# mii1_rxclk.mii1_rxclk
      - AM33XX_IOPAD(0x934, PIN_INPUT_PULLUP | MUX_MODE0)	# mii1_rxd3.mii1_rxd3
      - AM33XX_IOPAD(0x938, PIN_INPUT_PULLUP | MUX_MODE0)	# mii1_rxd2.mii1_rxd2
      - AM33XX_IOPAD(0x93c, PIN_INPUT_PULLUP | MUX_MODE0)	# mii1_rxd1.mii1_rxd1
      - AM33XX_IOPAD(0x940, PIN_INPUT_PULLUP | MUX_MODE0)	# mii1_rxd0.mii1_rxd0
  cpsw_sleep: &cpsw_sleep
    pinctrl-single,pins:
      # Slave 1 reset value
      - AM33XX_IOPAD(0x910, PIN_INPUT_PULLDOWN | MUX_MODE7)
      - AM33XX_IOPAD(0x914, PIN_INPUT_PULLDOWN | MUX_MODE7)
      - AM33XX_IOPAD(0x918, PIN_INPUT_PULLDOWN | MUX_MODE7)
      - AM33XX_IOPAD(0x91c, PIN_INPUT_PULLDOWN | MUX_MODE7)
      - AM33XX_IOPAD(0x920, PIN_INPUT_PULLDOWN | MUX_MODE7)
      - AM33XX_IOPAD(0x924, PIN_INPUT_PULLDOWN | MUX_MODE7)
      - AM33XX_IOPAD(0x928, PIN_INPUT_PULLDOWN | MUX_MODE7)
      - AM33XX_IOPAD(0x92c, PIN_INPUT_PULLDOWN | MUX_MODE7)
      - AM33XX_IOPAD(0x930, PIN_INPUT_PULLDOWN | MUX_MODE7)
      - AM33XX_IOPAD(0x934, PIN_INPUT_PULLDOWN | MUX_MODE7)
      - AM33XX_IOPAD(0x938, PIN_INPUT_PULLDOWN | MUX_MODE7)
      - AM33XX_IOPAD(0x93c, PIN_INPUT_PULLDOWN | MUX_MODE7)
      - AM33XX_IOPAD(0x940, PIN_INPUT_PULLDOWN | MUX_MODE7)
  davinci_mdio_default: &davinci_mdio_default
    pinctrl-single,pins:
      # MDIO
      - AM33XX_IOPAD(0x948, PIN_INPUT_PULLUP | SLEWCTRL_FAST | MUX_MODE0)	# mdio_data.mdio_data
      - AM33XX_IOPAD(0x94c, PIN_OUTPUT_PULLUP | MUX_MODE0)     		# mdio_clk.mdio_clk
  davinci_mdio_sleep: &davinci_mdio_sleep
    pinctrl-single,pins:
      # MDIO reset value
      - AM33XX_IOPAD(0x948, PIN_INPUT_PULLDOWN | MUX_MODE7)
      - AM33XX_IOPAD(0x94c, PIN_INPUT_PULLDOWN | MUX_MODE7)
  pinmux_mmc1_pins: &mmc1_pins
    pinctrl-single,pins:
      - AM33XX_IOPAD(0x960, PIN_INPUT | MUX_MODE7) # GPIO0_6
  pinmux_emmc_pins: &emmc_pins
    pinctrl-single,pins:
      - AM33XX_IOPAD(0x880, PIN_INPUT_PULLUP | MUX_MODE2) # gpmc_csn1.mmc1_clk
      - AM33XX_IOPAD(0x884, PIN_INPUT_PULLUP | MUX_MODE2) # gpmc_csn2.mmc1_cmd
      - AM33XX_IOPAD(0x800, PIN_INPUT_PULLUP | MUX_MODE1) # gpmc_ad0.mmc1_dat0
      - AM33XX_IOPAD(0x804, PIN_INPUT_PULLUP | MUX_MODE1) # gpmc_ad1.mmc1_dat1
      - AM33XX_IOPAD(0x808, PIN_INPUT_PULLUP | MUX_MODE1) # gpmc_ad2.mmc1_dat2
      - AM33XX_IOPAD(0x80c, PIN_INPUT_PULLUP | MUX_MODE1) # gpmc_ad3.mmc1_dat3
      - AM33XX_IOPAD(0x810, PIN_INPUT_PULLUP | MUX_MODE1) # gpmc_ad4.mmc1_dat4
      - AM33XX_IOPAD(0x814, PIN_INPUT_PULLUP | MUX_MODE1) # gpmc_ad5.mmc1_dat5
      - AM33XX_IOPAD(0x818, PIN_INPUT_PULLUP | MUX_MODE1) # gpmc_ad6.mmc1_dat6
      - AM33XX_IOPAD(0x81c, PIN_INPUT_PULLUP | MUX_MODE1) # gpmc_ad7.mmc1_dat7

*uart0:
  pinctrl-names: "default"
  pinctrl-0: *uart0_pins
  status: "okay"

*usb:
  status: "okay"

*usb_ctrl_mod:
  status: "okay"

*usb0_phy:
  status: "okay"

*usb1_phy:
  status: "okay"

*usb0:
  status: "okay"
  dr_mode: "peripheral"
  interrupts-extended: [ *intc , 18, *tps, 0 ]
  interrupt-names: [ "mc", "vbus" ]

*usb1:
  status: "okay"
  dr_mode: "host"

*cppi41dma:
  status: "okay"

*i2c0:
  pinctrl-names: "default"
  pinctrl-0: *i2c0_pins
  status: "okay"
  clock-frequency: 400000

  tps@24: &tps
    reg: 0x24

  baseboard_eeprom@50: &baseboard_eeprom
    compatible: "atmel,24c256"
    reg: 0x50
    "#address-cells": 1
    "#size-cells": 1
    baseboard_data@0: &baseboard_data
      reg: [ 0, 0x100 ]

*i2c2:
  pinctrl-names: "default"
  pinctrl-0: *i2c2_pins
  status: "okay"
  clock-frequency: 100000

  cape_eeprom0@54: &cape_eeprom0
    compatible: "atmel,24c256"
    reg: 0x54
    "#address-cells": 1
    "#size-cells": 1
    cape_data@0: &cape0_data
      reg: [ 0, 0x100 ]
  cape_eeprom1@55: &cape_eeprom1
    compatible: "atmel,24c256"
    reg: 0x55
    "#address-cells": 1
    "#size-cells": 1
    cape_data@0: &cape1_data
      reg: [ 0, 0x100 ]
  cape_eeprom2@56: &cape_eeprom2
    compatible: "atmel,24c256"
    reg: 0x56
    "#address-cells": 1
    "#size-cells": 1
    cape_data@0: &cape2_data
      reg: [ 0, 0x100 ]
  cape_eeprom3@57: &cape_eeprom3
    compatible: "atmel,24c256"
    reg: 0x57
    "#address-cells": 1
    "#size-cells": 1
    cape_data@0: &cape3_data
      reg: [ 0, 0x100 ]

#include "tps65217.yaml"

*tps:
  # Configure pmic to enter OFF-state instead of SLEEP-state ("RTC-only
  # mode") at poweroff.  Most BeagleBone versions do not support RTC-only
  # mode and risk hardware damage if this mode is entered.
  #
  # For details, see linux-omap mailing list May 2015 thread
  #	[PATCH] ARM: dts: am335x-bone* enable pmic-shutdown-controller
  # In particular, messages:
  #	http://www.spinics.net/lists/linux-omap/msg118585.html
  #	http://www.spinics.net/lists/linux-omap/msg118615.html
  #
  # You can override this later with
  #	*tps:
  #	  ti,pmic-shutdown-controller: null
  #
  # If you want to use RTC-only mode and made sure you are not affected
  # by the hardware problems. (Tip: double-check by performing a current
  # measurement after shutdown: it should be less than 1 mA.)
  interrupts: 7
  interrupt-parent: *intc
  ti,pmic-shutdown-controller: true

  charger:
    compatible: "ti,tps65217-charger"
    status: "okay"
    interrupts: [ 0, 1 ]
    interrupt-names: [ "USB", "AC" ]

  pwrbutton:
    compatible: "ti,tps65217-pwrbutton"
    status: "okay"
    interrupts: 2

  regulators:
    "#address-cells": 1
    "#size-cells": 0
    regulator@0: &dcdc1_reg
      regulator-name: "vdds_dpr"
      regulator-always-on: true

    regulator@1: &dcdc2_reg
      # VDD_MPU voltage limits 0.95V - 1.26V with +/-4% tolerance
      regulator-name: "vdd_mpu"
      regulator-min-microvolt: 925000
      regulator-max-microvolt: 1351500
      regulator-boot-on: true
      regulator-always-on: true

    regulator@2: &dcdc3_reg
      # VDD_CORE voltage limits 0.95V - 1.1V with +/-4% tolerance
      regulator-name: "vdd_core"
      regulator-min-microvolt: 925000
      regulator-max-microvolt: 1150000
      regulator-boot-on: true
      regulator-always-on: true

    regulator@3: &ldo1_reg
      regulator-name: "vio,vrtc,vdds"
      regulator-always-on: true

    regulator@4: &ldo2_reg
      regulator-name: "vdd_3v3aux"
      regulator-always-on: true

    regulator@5: &ldo3_reg
      regulator-name: "vdd_1v8"
      regulator-always-on: true

    regulator@6: &ldo4_reg
      regulator-name: "vdd_3v3a"
      regulator-always-on: true

*cpsw_emac0:
  phy_id: [ *davinci_mdio, 0x00000000 ]
  phy-mode: "mii"

*mac:
  slaves: 1
  pinctrl-names: [ "default", "sleep" ]
  pinctrl-0: *cpsw_default
  pinctrl-1: *cpsw_sleep
  status: "okay"

*davinci_mdio:
  pinctrl-names: [ "default", "sleep" ]
  pinctrl-0: *davinci_mdio_default
  pinctrl-1: *davinci_mdio_sleep
  status: "okay"

*mmc1:
  status: "okay"
  bus-width: 4
  pinctrl-names: "default"
  pinctrl-0: *mmc1_pins
  cd-gpios: [ *gpio0, 6, GPIO_ACTIVE_LOW ]

*aes:
  status: "okay"

*sham:
  status: "okay"

*rtc:
  clocks: [ *clk_32768_ck, *clkdiv32k_ick ]
  clock-names: [ "ext-clk", "int-clk" ]
```

# Validation example

For this example we're going to use port/am335x-boneblack-dev/
An extra rule-check.yaml file has been added where validation
tests can be performed.

That file contains a single jedec,spi-nor device and when we validate:

```yaml
*spi0:
  m25p80@0:
    compatible: "s25fl256s1"
    spi-max-frequency: 76800000
    reg: 0
    spi-tx-bus-width: 1
    spi-rx-bus-width: 4
    "#address-cells": 1
    "#size-cells": 1
```

This is a valid device node, so running validate produces the following:

```
$ make validate
cc -E -MT am33xx.cpp.yaml -MMD -MP -MF am33xx.o.Yd -I ./ -I ../../port -I ../../include -I ../../include/dt-bindings/input -nostdinc -undef -x assembler-with-cpp -D__DTS__ -D__YAML__ am33xx.yaml >am33xx.cpp.yaml
cc -E -MT am33xx-clocks.cpp.yaml -MMD -MP -MF am33xx-clocks.o.Yd -I ./ -I ../../port -I ../../include -I ../../include/dt-bindings/input -nostdinc -undef -x assembler-with-cpp -D__DTS__ -D__YAML__ am33xx-clocks.yaml >am33xx-clocks.cpp.yaml
cc -E -MT am335x-bone-common.cpp.yaml -MMD -MP -MF am335x-bone-common.o.Yd -I ./ -I ../../port -I ../../include -I ../../include/dt-bindings/input -nostdinc -undef -x assembler-with-cpp -D__DTS__ -D__YAML__ am335x-bone-common.yaml >am335x-bone-common.cpp.yaml
cc -E -MT am335x-boneblack-common.cpp.yaml -MMD -MP -MF am335x-boneblack-common.o.Yd -I ./ -I ../../port -I ../../include -I ../../include/dt-bindings/input -nostdinc -undef -x assembler-with-cpp -D__DTS__ -D__YAML__ am335x-boneblack-common.yaml >am335x-boneblack-common.cpp.yaml
cc -E -MT am335x-boneblack.cpp.yaml -MMD -MP -MF am335x-boneblack.o.Yd -I ./ -I ../../port -I ../../include -I ../../include/dt-bindings/input -nostdinc -undef -x assembler-with-cpp -D__DTS__ -D__YAML__ am335x-boneblack.yaml >am335x-boneblack.cpp.yaml
cc -E -MT rule-check.cpp.yaml -MMD -MP -MF rule-check.o.Yd -I ./ -I ../../port -I ../../include -I ../../include/dt-bindings/input -nostdinc -undef -x assembler-with-cpp -D__DTS__ -D__YAML__ rule-check.yaml >rule-check.cpp.yaml
../../yamldt  -g ../../validate/schema/codegen.yaml -S ../../validate/bindings/ -y am33xx.cpp.yaml am33xx-clocks.cpp.yaml am335x-bone-common.cpp.yaml am335x-boneblack-common.cpp.yaml am335x-boneblack.cpp.yaml rule-check.cpp.yaml -o am335x-boneblack-rules.pure.yaml
jedec,spi-nor: /ocp/spi@48030000/m25p80@0 OK
```
Note the last line. It means the node was checked and was found OK.

Editing the rule-check.yaml file, let's introduce a couple of errors.
The following output is generated by commenting out the reg property `# reg: 0`

```
$ make validate
cc -E -MT rule-check.cpp.yaml -MMD -MP -MF rule-check.o.Yd -I ./ -I ../../port -I ../../include -I ../../include/dt-bindings/input -nostdinc -undef -x assembler-with-cpp -D__DTS__ -D__YAML__ rule-check.yaml >rule-check.cpp.yaml
../../yamldt  -g ../../validate/schema/codegen.yaml -S ../../validate/bindings/ -y am33xx.cpp.yaml am33xx-clocks.cpp.yaml am335x-bone-common.cpp.yaml am335x-boneblack-common.cpp.yaml am335x-boneblack.cpp.yaml rule-check.cpp.yaml -o am335x-boneblack-rules.pure.yaml
jedec,spi-nor: /ocp/spi@48030000/m25p80@0 FAIL (-2004)
../../validate/bindings/jedec,spi-nor.yaml:15:5: error: missing property: property was defined at /jedec,spi-nor/properties/reg
     reg:
     ^~~~
```

Note the descriptive error and the pointer to the missing property in the schema.

Making another error, assign a string to the reg property `reg: "string"`

```
$ make validate
$ make validate
cc -E -MT rule-check.cpp.yaml -MMD -MP -MF rule-check.o.Yd -I ./ -I ../../port -I ../../include -I ../../include/dt-bindings/input -nostdinc -undef -x assembler-with-cpp -D__DTS__ -D__YAML__ rule-check.yaml >rule-check.cpp.yaml
../../yamldt  -g ../../validate/schema/codegen.yaml -S ../../validate/bindings/ -y am33xx.cpp.yaml am33xx-clocks.cpp.yaml am335x-bone-common.cpp.yaml am335x-boneblack-common.cpp.yaml am335x-boneblack.cpp.yaml rule-check.cpp.yaml -o am335x-boneblack-rules.pure.yaml
jedec,spi-nor: /ocp/spi@48030000/m25p80@0 FAIL (-3004)
rule-check.yaml:8:10: error: bad property type
     reg: "string"
          ^~~~~~~~
../../validate/bindings/jedec,spi-nor.yaml:15:5: error: property was defined at /jedec,spi-nor/properties/reg
     reg:
     ^~~~
```

Note the message about the type error and the pointer to the place where the reg property was defined.

Finally, let's make an error that violates a constraint.

Change the `spi-tx-bus-width` value to 3.

```
$ make validate
cc -E -MT rule-check.cpp.yaml -MMD -MP -MF rule-check.o.Yd -I ./ -I ../../port -I ../../include -I ../../include/dt-bindings/input -nostdinc -undef -x assembler-with-cpp -D__DTS__ -D__YAML__ rule-check.yaml >rule-check.cpp.yaml
../../yamldt  -g ../../validate/schema/codegen.yaml -S ../../validate/bindings/ -y am33xx.cpp.yaml am33xx-clocks.cpp.yaml am335x-bone-common.cpp.yaml am335x-boneblack-common.cpp.yaml am335x-boneblack.cpp.yaml rule-check.cpp.yaml -o am335x-boneblack-rules.pure.yaml
jedec,spi-nor: /ocp/spi@48030000/m25p80@0 FAIL (-1018)
rule-check.yaml:9:23: error: constraint rule failed
     spi-tx-bus-width: 3
                       ^
../../validate/bindings/spi/spi-slave.yaml:77:19: error: constraint that fails was defined here
       constraint: v == 1 || v == 2 || v == 4
                   ^~~~~~~~~~~~~~~~~~~~~~~~~~
../../validate/bindings/spi/spi-slave.yaml:74:5: error: property was defined at /spi-slave/properties/spi-tx-bus-width
     spi-tx-bus-width:
```

Note how the offending value is highlighted. The offending constraint and property definition are listed too.
