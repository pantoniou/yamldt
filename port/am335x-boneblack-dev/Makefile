TOPDIR ?= ../..

YAMLSO := am33xx.o.yaml am33xx-clocks.o.yaml am335x-bone-common.o.yaml \
	  am335x-boneblack-common.o.yaml am335x-boneblack.o.yaml \
	  rule-check.o.yaml

YAMLSS := am33xx.yaml am33xx-clocks.yaml am335x-bone-common.yaml \
	  am335x-boneblack-common.yaml am335x-boneblack.yaml rule-check.yaml

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

CPPYAMLS  := $(addsuffix .cpp.yaml, $(basename $(YAMLSS)))

CPP ?= cpp
YAML_CPP ?= $(CPP)
CPPFLAGS ?= -I ./ -I $(TOPDIR)/port \
	 -I $(TOPDIR)/include \
	 -I $(TOPDIR)/include/dt-bindings/input \
	 -nostdinc -undef \
	 -x assembler-with-cpp
DTC ?= dtc
DTCFLAGS ?= -@ -q
FDTDUMP ?= fdtdump
YAMLDT ?= $(TOPDIR)/yamldt
YAMLDTFLAGS_VALIDATE ?= \
		       --codegen=$(TOPDIR)/validate/schema/codegen.yaml \
		       --schema=$(TOPDIR)/validate/bindings/ \
		       --schema-save=schema.yaml
YAMLDTFLAGS ?= -@ -C
FDTDUMPFLAGS ?=
YDEPFLAGS ?= -MT $@ -MMD -MP -MF $*.o.Yd
DDEPFLAGS ?= -MT $@ -MMD -MP -MF $*.Dd

%.o.yaml: %.yaml
	$(YAML_CPP) $(YDEPFLAGS) $(CPPFLAGS) -D__DTS__ -D__YAML__ $< | \
		$(YAMLDT) $(YAMLDTFLAGS) -I yaml -O yaml -c - -o $@

%.cpp.yaml: %.yaml
	$(YAML_CPP) $(YDEPFLAGS) $(CPPFLAGS) -D__DTS__ -D__YAML__ $< >$@

%.dtb: %.yaml
	$(YAMLDT) $(YAMLDTFLAGS) -C $< -o $@

%.dts: %.yaml
	$(YAMLDT) $(YAMLDTFLAGS) -I yaml -O dts $< -o $@

%.yaml.dts: %.pure.yaml
	$(YAMLDT) $(YAMLDTFLAGS) -s $< -o $@

%.dtc.dtb: %.dts
	$(YAML_CPP) $(DDEPFLAGS) $(CPPFLAGS) -D__DTS__ $< | \
		$(DTC) $(DTCFLAGS) -I dts -O dtb - -o $@

%.fdtdump: %.dtb
	$(FDTDUMP) $(FDTDUMPFLAGS) 2>/dev/null $< >$@

%.diff: %.dtc.fdtdump %.fdtdump
	-cmp -s $^ || (diff -u $^ | tee $@)

.PHONY: all clean distclean check validate

all: $(DTBS) $(DTSS)

clean:
	rm -f $(YDEPS) $(DDEPS) $(YAMLSO) $(ALLDTBS) $(FDTDUMPS) $(DIFFS)
	rm -f am335x-boneblack-rules.yaml *.pure.yaml *.pure.dts *.[ch] *.ebpf *.cpp.yaml
	rm -f schema.yaml

check: $(DTCDTBS) $(DTBS) $(DTSS) $(DIFFS)

validate: am335x-boneblack-rules.pure.yaml

am335x-boneblack.pure.yaml: $(YAMLSO)
	$(YAMLDT) $(YAMLDTFLAGS) -I yaml -O yaml $^ -o $@

am335x-boneblack-rules.pure.yaml: $(CPPYAMLS) rule-check.cpp.yaml
	$(YAMLDT) $(YAMLDTFLAGS) $(YAMLDTFLAGS_VALIDATE) -I yaml -O yaml $^ -o $@

-include $(YDEPS) $(DDEPS)
