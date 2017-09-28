TOPDIR ?= ../..
DTSS := $(shell ls *.dts)
DTSIS := $(shell ls *.dtsi)
YAMLS := $(addsuffix .yaml, $(basename $(DTSS)))
YAMLIS := $(addsuffix .yamli, $(basename $(DTSIS)))

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
DTS2YAML ?= $(TOPDIR)/dts2yaml

# pass extra validate flags
YAMLDTFLAGS ?= -C -@ \
	$(if $(findstring validate, $(MAKECMDGOALS)), \
		--codegen=$(TOPDIR)/validate/schema/codegen.yaml \
		--schema=$(TOPDIR)/validate/bindings/)

DTS2YAMLFLAGS ?=
FDTDUMPFLAGS ?=
YDEPFLAGS = -MT $@ -MMD -MP -MF $*.Yd
DDEPFLAGS = -MT $@ -MMD -MP -MF $*.Dd

DTBS     := $(addsuffix .dtb, $(basename $(YAMLS)))
DTCDTBS  := $(addsuffix .dtc.dtb, $(basename $(YAMLS)))
YDTCDTBS := $(addsuffix .ydtc.dtb, $(basename $(YAMLS)))
FDTDUMPS := $(addsuffix .fdtdump, $(basename $(DTBS))) \
	    $(addsuffix .fdtdump, $(basename $(DTCDTBS)))
CPPS     := $(addsuffix .cpp.yaml, $(basename $(YAMLS)))
DIFFS    := $(addsuffix .diff, $(basename $(YAMLS)))
YDIFFS   := $(addsuffix .y.diff, $(basename $(YAMLS)))
YDEPS    := $(addsuffix .Yd, $(basename $(YAMLS)))
DDEPS    := $(addsuffix .Dd, $(basename $(YAMLS)))

%.diff: %.dtc.fdtdump %.fdtdump
	-cmp -s $^ || (diff -u $^ | tee $@)

%.y.diff: %.ydtc.fdtdump %.fdtdump
	-cmp -s $^ || (diff -u $^ | tee $@)

%.cpp.yaml: %.yaml
	$(CPP) $(CPPFLAGS) -D__DTS__ $< > $@

%.cpp.dts: %.dts
	$(CPP) $(CPPFLAGS) -D__DTS__ $< > $@

%.dtb: %.yaml
	$(CPP) $(YDEPFLAGS) $(CPPFLAGS) -D__DTS__ -D__YAML__ $< | \
		$(YAMLDT) $(YAMLDTFLAGS) - -o $@

%.dtc.dtb: %.dts
	$(CPP) $(DDEPFLAGS) $(CPPFLAGS) -D__DTS__ $< | \
		$(DTC) $(DTCFLAGS) -I dts -O dtb - -o $@

%.ydtc.dtb: %.dts
	$(CPP) $(DDEPFLAGS) $(CPPFLAGS) -D__DTS__ $< | \
		$(YAMLDT) $(YAMLDTFLAGS) - -o $@

%.fdtdump: %.dtb
	$(FDTDUMP) $(FDTDUMPFLAGS) 2>/dev/null $< >$@

# will also generate all yamli included files
%.yaml: %.dts
	$(DTS2YAML) $(DTS2YAMLFLAGS) -r $^

.PHONY: clean distclean check validate .FORCE

all: $(DTBS)

check: $(DTCDTBS) $(DTBS) $(DIFFS) $(YDIFFS)

clean:
	rm -f $(DTBS) $(FDTDUMPS) $(CPPS) $(YDEPS) \
	      $(DTCDTBS) $(DDEPS) $(YAMLS) $(YAMLIS) \
	      *.dtb *.diff *.fdtdump

validate: check

# always rebuild the final DTBS to check
$(DTBS): .FORCE

.FORCE:

-include $(YDEPS) $(DDEPS)
