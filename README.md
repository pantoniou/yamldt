# yamldt

A YAML to DT blob generator/compiler and validator, utilizing a YAML schema
that is functionaly equivalent to DTS and supports all DTS features.

Validation is performed against another YAML schema that defines properties
and constraints which a checker uses generating small code fragments that
are compiled to ebpf and executed for the specific validation of each
node that the rule selects in the output tree.

`yamldl` parses a device tree description (source) file in YAML format
and outputs a (bit-exact if the -C option is used) device tree blob.

## Rationale

A DT aware YAML schema is a good fit as a DTS syntax alternative.

YAML is a human-readable data serialization language, and is expressive
enough to cover all DTS source features.

Simple YAML file are just key value pairs that are very easy to parse, even
without using a formal YAML parser. For instance YAML in restricted
environments may simple be appending a few lines of text in a given YAML file.

The parsers of YAML are very mature, as it has been released in 2001.
It is in wide-spread use and schema validation tools are available.
YAML support is available for every major programming language.

Projects currently use YAML as their configuration format:

1. [github](https://github.com/github/linguist/blob/master/lib/linguist/languages.yml)
2. [openstack](https://github.com/openstack/governance/blob/master/reference/projects.yaml)
3. [jenkins](https://wiki.jenkins.io/display/JENKINS/YAML+Project+Plugin)
4. [yedit](https://github.com/oyse/yedit/wiki)

Data in YAML can easily be converted to/form other format that a
particular tool that we may use in the future understands.

More importantly YAML offers (an optional) type information for each
data, which is IMHO crucial for thorough validation and checking
against device tree bindings (when they will be converted to a
machine readable format, preferably YAML).

yamldt implements a schema checker partly based on an RFC posted
on the mainline list some years ago by Rob Herring.

## Validation

`yamldt` is capable to perform validation of DT constructs using
a C code based eBPF checker. eBPF code fragments are assembled that
can perform type checking of properties, enforce arbitrary value
constraints while fully supporting inheritance.

As an example, let's see how the validation of a given fragment
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

Note the constraint rule that matches on any compatible on the
given list. This binding inherits from spi-slave `inherits: *spi-slave`

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
inherited bindings include.

This in turn inherits from `device-compatible` which is this:

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

It simply defines a `selected` rule. The checker uses it
as part of the `select` method which will generate in order
to find out whether a node should be checked against a rule.

The `selected` rule defines two constraints. The first one
is the name of a variable in a derived binding that all
it's constraints has to satisfy; in this case it's the
jedec,spi-nor compatible constraint in the binding above.
The select constraint is a reference to the
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

Taking those two constraints together we generate the enable
method filter which triggers on an enable device node that
matches any of the compatible strings defined in the jedec,spi-nor
binding.

The check method will be generated by collecting all the
property constraints (category, type and explicit value constraints).

Note how a variable v is used a the current property value. The
generated methods will provide it to the constraint all primed
up and ready to use.

Note that custom, manually written select and check methods
are possible but their usage is not recommended for simple type.

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
   -o, --output        Output file
   -d, --debug         Debug messages
   -c                  Don't resolve references (object mode)
   -C, --compatible    Compatible mode
   -s, --dts           DTS mode
   -y, --yaml          YAML mode
   -S, --schema        Use schema (all yaml files in dir/)
   -g, --codegen       Code generator configuration file
       --save-temps    Save temporary files
       --silent        Be really silent
       --color         [auto|off|on]
   -h, --help          Help
   -v, --version       Display version
```

The `-C/--compatible` option generates a bit exact DTB file.

The `-l/--late-resolve` option enables manipulation of the tree in ways
that is not possible with DTS (for example unit names are automatically
generated).

The `-c/--object` option generates an YAML object file that can be
used in linking similar to the way C sources and object files work.

The `-s/--dts` option selects a DTS output format instead of DTB.

The `-y/--yaml` option output a _pure_ YAML format file. A _pure_
YAML file is one that is containing no comments and integer values
have been calculated if possible. It is guaranteed to be a valid
YAML file suitable for use by other external tools.

The `-S/--schema` option is going to use the given file(s) as
input for the checker. As an extension if given a directory name
with a terminating slash (i.e. dir/) it will recursively collect
and use all YAML files within.

The `-g/--codegen` option is going to use the given YAML file(s)
(or dir/ as in the schema option) as input for the code generator.

The `--save-temps` option will save all intermediate files/blobs.

The `--silent` option will supress all informational messages.

`--color` controls color output in the terminal.

Automatic suffix detection does what you expect (i.e. an output file
ending in .dtb is selecting the DTB generation option, .yaml the yaml
one and so on).

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

## Test suite

To run the test-suite you will need a patched DTC that can generate
yaml as an output option. If it a capable DTC is found in your path
it will be used.

The DTC patches are available under patches/dtc and at
https://github.com/pantoniou/dtc/tree/yaml

The test-suite compiles all the DTS files in the Linux kernel for
all arches to both YAML and dtb format. The generated YAML file
is compiled again with `yamldt` using the compatible option to a
different dtb file.

The resulting dtb files are bit-exact because the `-C` option is used.

Run `make check` to run the test suite.
Run `make validate` to run the test suite and perform schema
validation checks. It is recommended to use the `--keep-going`
flag to continue checking even in the presence of validation
errors.

# Workflow

It is expected that the first thing a user of `yamldt` would want
to do is to convert an existing DTS configuration to YAML.

Using a patched DTC as mentioned earlier you can generate a raw
YAML file that functionally generates the same (bitexact with the
-C option) DTB file.

We're going to use as an example the beaglebone black and the
am335x-boneblack.dts source as located in the port/ directory.

The DTS source files in the kernel are using the C preprocessor
so it's imperative to use it as a first pass (note you can pipe
the output to cut down on the steps).

```
$ cpp -I ./ -I ../../port -I ../../include \
-I ../../include/dt-bindings/input -nostdinc \
-undef -x assembler-with-cpp -D__DTS__ \
am335x-boneblack.dts > am335x-boneblack.cpp.dts
```

Compile this file with DTC to generate a DTB file, we'll use this
as a reference.

```
$ dtc -@ -q -I dts -O dtb am335x-boneblack.cpp.dts \
-o am335x-boneblack.dtc.dtb
```

Compile the same file with the patched DTC but now select a YAML
output option.

```
$ dtc -@ -q -I dts -O yaml am335x-boneblack.cpp.dts \
-o am335x-boneblack.dtc.yaml
```

This (raw) yaml file is functionally identical to the original DTS
and parses down to the same exact file using the -C option.

```
$ yamldt -C am335x-boneblack.dtc.yaml -o am335x-boneblack.dtb
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

You can now start the conversion to YAML using the same file
structure as the DTS files but with yaml instead of DTS.
Large parts of the new YAML source can be copied verbatim from
m335x-boneblack.dtc.yaml file.

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

In YAML the equivalent method is called anchors and are defined
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

* DTS is using spaces to seperate array elements, YAML is either using
  indentation or commas in JSON form.

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

* Integer expression evaluation similar in manner that the CPP preprocessor
  performs is available. This is required in order for macros defined to
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

This is a valid device node so running validate..

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
Note the last line, it means that the node was checked and it was found OK.

Editing the rule-check.yaml file, let's introduce a couple of errors;
Commenting out the reg property `# reg: 0`

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

Finally, let's make an error that violates a constraint

Change the `spi-tx-bus-width` value to 3

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

Note how the offending value was highlighted, the offending constraint and property definition were listed too.
