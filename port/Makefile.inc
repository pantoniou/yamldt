#
# Leaf makefile for 
#

CPP ?= cpp
CPPFLAGS ?= -I ./ -I $(TOPDIR)/port \
	 -I $(TOPDIR)/include \
	 -I $(TOPDIR)/include/dt-bindings/input \
	 -nostdinc -undef \
	 -x assembler-with-cpp
DTC ?= dtc
DTCFLAGS ?= -@ -q
FDTDUMP ?= fdtdump
YAMLDT ?= $(TOPDIR)/yamldt
YAMLDTFLAGS ?= -C
FDTDUMPFLAGS ?=
YDEPFLAGS = -MT $@ -MMD -MP -MF $*.Yd
DDEPFLAGS = -MT $@ -MMD -MP -MF $*.Dd

DTBS     := $(addsuffix .dtb, $(basename $(YAMLS)))
DTCDTBS  := $(addsuffix .dtc.dtb, $(basename $(YAMLS)))
FDTDUMPS := $(addsuffix .fdtdump, $(basename $(DTBS))) \
	    $(addsuffix .fdtdump, $(basename $(DTCDTBS)))
CPPS     := $(addsuffix .cpp.yaml, $(basename $(YAMLS)))
DIFFS    := $(addsuffix .diff, $(basename $(YAMLS)))
YDEPS    := $(addsuffix .Yd, $(basename $(YAMLS)))
DDEPS    := $(addsuffix .Dd, $(basename $(YAMLS)))

%.diff: %.dtc.fdtdump %.fdtdump
	-cmp -s $^ || (diff -u $^ | tee $@)

%.cpp.yaml: %.yaml
	$(CPP) $(CPPFLAGS) $< > $@

%.dtb: %.yaml
	$(CPP) $(YDEPFLAGS) $(CPPFLAGS) -D__DTS__ -D__YAML__ $< | \
		$(YAMLDT) $(YAMLDTFLAGS) - -o $@

%.dtc.dtb: %.dts
	$(CPP) $(DDEPFLAGS) $(CPPFLAGS) -D__DTS__ $< | \
		$(DTC) $(DTCFLAGS) -I dts -O dtb - -o $@

%.fdtdump: %.dtb
	$(FDTDUMP) $(FDTDUMPFLAGS) 2>/dev/null $< >$@

.PHONY: clean distclean check

all: $(DTBS)

clean:
	rm -f $(DTBS) $(FDTDUMPS) $(CPPS) $(YDEPS) \
	      $(DTCDTBS) $(DDEPS)

check: $(DIFFS) $(DTCFDTDUMPS) $(CPPS)

-include $(YDEPS) $(DDEPS)
