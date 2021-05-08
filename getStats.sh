#!/bin/bash
#Copyright GammaByte.xyz 2021
all() {
  kvmtop -p json -r 1 --mem --host --disk --io --net --cpu --pressure --verbose
}

ram(){
  kvmtop -p json -r 1 --mem --host --disk --io --net --cpu --pressure --verbose | jq '.host.ram_Free' | sed 's/"//g'
}

domains(){
  kvmtop -p json -r 1 --mem --host --disk --io --net --cpu --pressure --verbose | jq '.domains[] .name' | sed 's/"//g'
}

while getopts "a:r:d" arg; do
  case $arg in
    a) all;;
    r) ram;;
    d) domains;;
  esac
done