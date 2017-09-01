#
# Leaf makefile for 
#

.SUFFIXES:

CPP ?= cpp
CPPFLAGS ?= -I ./ -I $(TOPDIR)/test-suite \
	 -I $(TOPDIR)/include \
	 -I $(TOPDIR)/include/dt-bindings/input \
	 -nostdinc -undef -D__DTS__ -x assembler-with-cpp
DTC ?= dtc
# DTCFLAGS ?= -@ -q
DTCFLAGS ?= -q
FDTDUMP ?= fdtdump
YAMLDT ?= $(TOPDIR)/yamldt
DTS2YAML ?= $(TOPDIR)/dts2yaml

# pass extra validate flags
YAMLDTFLAGS ?= -C \
	$(if $(findstring validate, $(MAKECMDGOALS)), \
		-g $(TOPDIR)/validate/schema/codegen.yaml -S $(TOPDIR)/validate/bindings/)

DTS2YAMLFLAGS ?=
FDTDUMPFLAGS ?=

YAMLS    := $(addsuffix .yaml, $(filter-out $(basename $(BLACKLIST)),$(basename $(BOARDS))))
DTSS     := $(addsuffix .dts, $(filter-out $(basename $(BLACKLIST)),$(basename $(BOARDS))))
DTCYAMLS := $(addsuffix .dtc.yaml, $(basename $(BOARDS)))
DIFFS    := $(addsuffix .diff, $(basename $(YAMLS)))
DTBS     := $(addsuffix .dtb, $(basename $(YAMLS)))
YAMLDTBS := $(addsuffix .yaml.dtb, $(basename $(YAMLS)))
FDTDUMPS := $(addsuffix .fdtdump, $(basename $(DTBS))) $(addsuffix .fdtdump, $(basename $(YAMLDTBS)))
CPPS     := $(addsuffix .cpp, $(basename $(DTBS))) $(addsuffix .yaml.cpp, $(basename $(YAMLDTBS)))

%.diff: %.yaml.fdtdump %.fdtdump
	cmp -s $^ || (diff -u $^ | tee $@; false)

%.cpp.dts: %.dts
	$(CPP) $(CPPFLAGS) $< > $@

%.dtb: %.dts
	$(CPP) $(CPPFLAGS) $< | $(DTC) $(DTCFLAGS) -I dts -O dtb - -o $@

%.yaml.dtb: %.yaml | genyamls
	$(CPP) $(CPPFLAGS) $^ | $(YAMLDT) $(YAMLDTFLAGS) - -o $@

%.dtc.yaml: %.dts
	$(CPP) $(CPPFLAGS) $< | $(DTC) $(DTCFLAGS) -I dts -O yaml - -o $@

# will also generate all yamli included files
# %.yaml: %.dts
#	$(DTS2YAML) $(DTS2YAMLFLAGS) -r $^

%.fdtdump: %.dtb
	$(FDTDUMP) $(FDTDUMPFLAGS) 2>/dev/null $< >$@

.PHONY: clean check genyamls

# .NOTPARALLEL:

check: $(DIFFS)

clean:
	rm -f $(DIFFS) $(DTBS) $(YAMLDTBS) $(FDTDUMPS) $(CPPS) $(YAMLS)
	rm -f *.yaml
	rm -f *.yamli

$(YAMLS): $(DTSS)
$(YAMLS): genyamls

genyamls:
	$(DTS2YAML) $(DTS2YAMLFLAGS) -r $(DTSS) || true
	@echo "dts2yaml DONE"

validate: check
