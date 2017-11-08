TOPDIR ?= ../..
SCHEMA ?= schema.yaml

BOARDS := $(filter-out %.yaml.yaml, $(filter-out $(SCHEMA), $(shell ls *.yaml)))
JSONS := $(addsuffix .yaml.json, $(basename $(BOARDS)))
YAMLYAMLS := $(addsuffix .yaml.yaml, $(basename $(BOARDS)))

include $(TOPDIR)/test-suite/Makefile.rules

.PHONY: all clean check genyamls genblackyamls checkblack

all: $(YAMLDTBS) $(JSONS) $(YAMLYAMLS)

check: all

clean:
	rm -f *.cpp.yaml *.cpp.dts
	rm -f *.yaml.yaml *.yaml.json
	rm -f *.dtb
	rm -f *.json
	rm -f *.diff
	rm -f *.fdtdump
	rm -f $(SCHEMA)

$(DTBS) $(YAMLDTBS) $(YDTCDTBS): $(if $(findstring 1, $(VALIDATE)), $(SCHEMA))

$(SCHEMA): $(CODEGEN) $(BINDING_FILES)
	$(YAMLDT) -g $(CODEGEN) --schema $(BINDINGS)/ --schema-save=$(SCHEMA) $(YAMLDTSCHEMAFLAGS)

validate: $(SCHEMA) check

genyamls:
genblackyamls:
checkblack:
