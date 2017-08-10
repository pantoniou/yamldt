#!/bin/sh
set -x
# ./yamldt -y valid-compatible.yaml device-compatible.yaml device-enabled.yaml reg.yaml spi-slave.yaml jedec,spi-nor.yaml -o schema.yaml
#. /yamldt -T -y -g codegen.yaml -S schema.yaml -i schema.i.yaml -o dra7-evm.pure.yaml dra7-evm.yaml 
# ./yamldt -y valid-compatible.yaml device-compatible.yaml device-enabled.yaml reg.yaml spi-slave.yaml jedec,spi-nor.yaml -o schema.yaml

#valgrind --leak-check=full \
#./yamldt -T -y -g codegen.yaml \
#	-S "valid-compatible.yaml device-compatible.yaml device-enabled.yaml reg.yaml spi-slave.yaml jedec,spi-nor.yaml" \
#	-i schema.i.yaml \
#	-o dra7-evm.pure.yaml \
#	dra7-evm.yaml 

#valgrind --leak-check=full \
./yamldt -T -y -g codegen.yaml \
	-S "valid-compatible.yaml device-compatible.yaml device-enabled.yaml reg.yaml spi-slave.yaml jedec,spi-nor.yaml" \
	-i schema.i.yaml \
	-o x.pure.yaml \
	x.yaml 
