TOPDIR ?= ../..

YAMLSO := am33xx.o.yaml am33xx-clocks.o.yaml am335x-bone-common.o.yaml \
	  am335x-boneblack-common.o.yaml am335x-boneblack.o.yaml

YAMLS  := am335x-boneblack.pure.yaml
DTBS   := $(addsuffix .dtb, $(basename $(YAMLS)))
DTSS   := $(addsuffix .dts, $(basename $(YAMLS)))
YDEPS  := $(addsuffix  .Yd, $(basename $(YAMLSO)))
DDEPS  := $(addsuffix  .Dd, $(basename $(YAMLS)))
CPPS   := $(addsuffix .cpp.yaml, $(basename $(YAMLS)))

DTCDTBS    := $(addsuffix .dtc.dtb, $(basename $(YAMLS)))
DTSDTCDTBS := $(addsuffix .dts.dtb, $(basename $(YAMLS)))

ALLDTBS	   := $(DTBS) $(DTCDTBS) $(DTSDTCDTBS)

FDTDUMPS   := $(addsuffix .fdtdump, $(basename $(ALLDTBS)))

DIFFS      := $(addsuffix .diff, $(basename $(YAMLS)))

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
YDEPFLAGS ?= -MT $@ -MMD -MP -MF $*.o.Yd
DDEPFLAGS ?= -MT $@ -MMD -MP -MF $*.Dd

%.o.yaml: %.yaml
	$(CPP) $(YDEPFLAGS) $(CPPFLAGS) -D__DTS__ -D__YAML__ $< | \
		$(YAMLDT) $(YAMLDTFLAGS) -y -c - -o $@

%.dtb: %.yaml
	$(YAMLDT) $(YAMLDTFLAGS) $< -o $@

%.dts: %.yaml
	$(YAMLDT) $(YAMLDTFLAGS) -s $< -o $@

%.yaml.dts: %.pure.yaml
	$(YAMLDT) $(YAMLDTFLAGS) -s $< -o $@

%.dtc.dtb: %.dts
	$(CPP) $(DDEPFLAGS) $(CPPFLAGS) -D__DTS__ $< | \
		$(DTC) $(DTCFLAGS) -I dts -O dtb - -o $@

%.fdtdump: %.dtb
	$(FDTDUMP) $(FDTDUMPFLAGS) 2>/dev/null $< >$@

%.diff: %.dtc.fdtdump %.fdtdump
	-cmp -s $^ || (diff -u $^ | tee $@)

.PHONY: all clean distclean check

all: $(DTBS) $(DTSS)

clean:
	rm -f $(YDEPS) $(DDEPS) $(YAMLSO) $(ALLDTBS) $(FDTDUMPS) $(DIFFS)

check: $(DTCDTBS) $(DTBS) $(DTSS) $(DIFFS)

am335x-boneblack.pure.yaml: $(YAMLSO)
	$(YAMLDT) $(YAMLDTFLAGS) -y $^ -o $@

-include $(YDEPS) $(DDEPS)
