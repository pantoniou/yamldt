#!/bin/sh

#valgrind --leak-check=full \
# ../../yamldt -T -y -g codegen.yaml -S "`find ../bindings/ -name "*.yaml"`" -i schema.i.yaml $*

set -x
# ../../yamldt -T -y -g codegen.yaml -S "`find ../bindings/ -name "*.yaml"`" $*
../../yamldt -T -y -g codegen.yaml -S ../bindings/ $*
