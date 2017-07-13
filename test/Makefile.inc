#
# Leaf makefile for 
#

CPP ?= cpp
CPPFLAGS ?= -I ./ -I $(TOPDIR) \
	 -I $(TOPDIR)/../include \
	 -I $(TOPDIR)/../include/dt-bindings/input \
	 -nostdinc -undef -D__DTS__ -D__YAML__ \
	 -x assembler-with-cpp
DTC ?= dtc
DTCFLAGS ?= -@ -q
FDTDUMP ?= fdtdump
YAMLDT ?= $(TOPDIR)/../yamldt
YAMLDTFLAGS ?= -C -d
FDTDUMPFLAGS ?=

DTBS     := $(addsuffix .dtb, $(basename $(YAMLS)))
FDTDUMPS := $(addsuffix .fdtdump, $(basename $(YAMLS)))
CPPS     := $(addsuffix .cpp.yaml, $(basename $(YAMLS)))

%.cpp.yaml: %.yaml
	$(CPP) $(CPPFLAGS) $< > $@

%.dtb: %.yaml
	$(CPP) $(CPPFLAGS) $< | $(YAMLDT) $(YAMLDTFLAGS) - -o $@

%.fdtdump: %.dtb
	$(FDTDUMP) $(FDTDUMPFLAGS) 2>/dev/null $< >$@

.PHONY: clean check

all: $(DTBS) $(FDTDUMPS) $(CPPS)

clean:
	rm -f $(DTBS) $(FDTDUMPS) $(CPPS)
