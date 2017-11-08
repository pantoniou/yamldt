#
# Leaf makefile for 
#

include $(TOPDIR)/test-suite/Makefile.rules

.PHONY: clean check genyamls genblackyamls checkblack

# .NOTPARALLEL:

check: $(DIFFS) $(YDIFFS)

clean:
	rm -f $(YAMLS)
	find ./ -name '*.yaml' -print | xargs rm -f
	find ./ -name '*.yamli' -print | xargs rm -f
	rm -f *.cpp.yaml *.cpp.dts
	rm -f *.dtb
	rm -f *.diff
	rm -f *.fdtdump
	rm -f $(SCHEMA)

$(YAMLS): $(DTSS)
$(YAMLS): genyamls

$(DTBS) $(YAMLDTBS) $(YDTCDTBS): $(if $(findstring 1, $(VALIDATE)), $(SCHEMA))

genyamls:
	$(DTS2YAML) $(DTS2YAMLFLAGS) -r $(DTSS) || true
	@echo "dts2yaml DONE"

checkblack: $(BLACKDIFFS) $(BLACKYDIFFS)

genblackyamls:
	$(DTS2YAML) $(DTS2YAMLFLAGS) -r $(BLACKDTSS) || true
	@echo "dts2yaml DONE"

$(SCHEMA): $(CODEGEN) $(BINDING_FILES)
	$(YAMLDT) -g $(CODEGEN) --schema $(BINDINGS)/ --schema-save=$(SCHEMA) $(YAMLDTSCHEMAFLAGS)

validate: $(SCHEMA) check
