# yamldt

A YAML to DT blob generator/compiler.

`yamldl` parses a device tree description file in YAML and outputs
a (bit-exact if the -C option is used) device tree blob.

## Rationale

YAML is a good fit as a DTS alternative. YAML is a human-readable
data serialization language, and is expressive enough to cover all
DTS source features.

The parsers are very mature, it is wide-spread and schema validation
tools are available. Data in YAML can easily be converted to/form other
forms that particular tools that we may use in the future.

More importantly YAML offers (an optional) type information for each
data, which is IMHO crucial for thorough validation and checking
against device tree bindings (when they will be converted to a
machine readable format, preferably YAML).

## Installation

Install libyaml-dev and the standard autoconf/automake generation tools.

Compile by the standard `./autogen.sh`, `./configure` and make cycle.

For a complete example of a port of a board DTS file to YAML take a
look in the `port/` directory

You can pass a CPP processed file to `yamldt` and everything works
as expected.

# Usage

```
yamldt [options] <input-file>
 options are:
   -o, --output	Output DTB file
   -d, --debug		Debug messages
   -C, --compatible	Bit exact compatibility mode
   -h, --help		Help
   -v, --version	Display version
```

## Test suite

To run the test-suite you will need a patched DTC that can generate
yaml as an output option. If it a capable DTC is found in your path
it will be used.

The DTC patches are available under patches/dtc and at
https://github.com/pantoniou/dtc/tree/yaml

The test-suite compiles all the DTS files in the Linux kernel for
all arches to both YAML and dtb format. The generated YAML file
is compiled again with yamldt using the compatible option to a
different dtb file.

The resulting dtb files are bit-exact.

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
