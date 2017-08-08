#!/bin/sh
set -x
./yamldt -y valid-compatible.yaml device-enabled.yaml reg.yaml spi-slave.yaml jedec,spi-nor.yaml -o schema.yaml
./yamldt -y -g codegen.yaml -S schema.yaml -i schema.i.yaml -o dra7-evm.pure.yaml dra7-evm.yaml 
