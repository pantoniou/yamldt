#
# Leaf makefile for 
#

CPP ?= cpp
CPPFLAGS ?= -I ./ -I $(TOPDIR)/test-suite \
	 -I $(TOPDIR)/include \
	 -I $(TOPDIR)/include/dt-bindings/input \
	 -nostdinc -undef -D__DTS__ -x assembler-with-cpp
DTC ?= dtc
DTCFLAGS ?= -@ -q
FDTDUMP ?= fdtdump
YAMLDT ?= $(TOPDIR)/yamldt

# pass extra validate flags
YAMLDTFLAGS ?= -C \
	$(if $(findstring validate, $(MAKECMDGOALS)), \
		-g $(TOPDIR)/validate/schema/codegen.yaml -S $(TOPDIR)/validate/bindings/)

FDTDUMPFLAGS ?=

DIFFS    := $(addsuffix .diff, $(basename $(BOARDS)))
DTBS     := $(addsuffix .dtb, $(basename $(BOARDS)))
YAMLS    := $(addsuffix .yaml, $(basename $(BOARDS)))
YAMLDTBS := $(addsuffix .yaml.dtb, $(basename $(BOARDS)))
FDTDUMPS := $(addsuffix .fdtdump, $(basename $(DTBS))) $(addsuffix .fdtdump, $(basename $(YAMLDTBS)))
CPPS     := $(addsuffix .cpp, $(basename $(DTBS))) $(addsuffix .yaml.cpp, $(basename $(YAMLDTBS)))

%.diff: %.yaml.fdtdump %.fdtdump
	-cmp -s $^ || (diff -u $^ | tee $@)

%.cpp: %.dts
	$(CPP) $(CPPFLAGS) $< > $@

%.yaml.cpp: %.dts
	$(CPP) $(CPPFLAGS) $< > $@

%.dtb: %.dts
	$(CPP) $(CPPFLAGS) $< | $(DTC) $(DTCFLAGS) -I dts -O dtb - -o $@

%.yaml.dtb: %.yaml
	$(CPP) $(CPPFLAGS) $< | $(YAMLDT) $(YAMLDTFLAGS) - -o $@

%.yaml: %.dts
	$(CPP) $(CPPFLAGS) $< | $(DTC) $(DTCFLAGS) -I dts -O yaml - -o $@

%.fdtdump: %.dtb
	$(FDTDUMP) $(FDTDUMPFLAGS) 2>/dev/null $< >$@

.PHONY: clean check

check: $(DIFFS)

clean:
	rm -f $(DIFFS) $(DTBS) $(YAMLDTBS) $(FDTDUMPS) $(CPPS) $(YAMLS)

validate: check
