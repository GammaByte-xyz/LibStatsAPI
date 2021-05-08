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

while [ "$1" != "" ]; do
    case $1 in
        -a | --all )
            all
        ;;
        -r | --ram )
            ram
        ;;
        -d | --domains )
            domains
        ;;
        * )
            exit 1
    esac
    shift
done
