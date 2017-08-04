#!/bin/sh
set -x
./yamldt -y valid-compatible.yaml spi-slave.yaml jedec,spi-nor.yaml -o schema.yaml
./yamldt -y -S schema.yaml -i schema.i.yaml -o dra7-evm.pure.yaml dra7-evm.yaml 
