TOPDIR ?= ../..

YAMLSO := am33xx.o.yaml am33xx-clocks.o.yaml am335x-bone-common.o.yaml \
	  am335x-boneblack-common.o.yaml am335x-boneblack.o.yaml

YAMLS  := am335x-boneblack.pure.yaml
DTBS   := $(addsuffix .dtb, $(basename $(YAMLS)))
DTSS   := $(addsuffix .dts, $(basename $(YAMLS)))
YDEPS  := $(addsuffix  .Yd, $(basename $(YAMLSO)))

# include $(TOPDIR)/port/Makefile.inc

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
YDEPFLAGS = -MT $@ -MMD -MP -MF $*.o.Yd

%.o.yaml: %.yaml
	$(CPP) $(YDEPFLAGS) $(CPPFLAGS) -D__DTS__ -D__YAML__ $< | \
		$(YAMLDT) $(YAMLDTFLAGS) -y -c - -o $@

%.dtb: %.yaml
	$(YAMLDT) $(YAMLDTFLAGS) $< -o $@

%.dts: %.yaml
	$(YAMLDT) $(YAMLDTFLAGS) -s $< -o $@

.PHONY: all clean distclean check

all: $(DTBS) $(DTSS)

clean:
	rm -f $(YDEPS) $(YAMLSO) $(TARGETS) $(DTBS) $(DTSS)

check:
	@echo YDEPS=$(YDEPS)
	@echo nothing to do for check

am335x-boneblack.pure.yaml: $(YAMLSO)
	$(YAMLDT) $(YAMLDTFLAGS) -y $^ -o $@

-include $(YDEPS)
