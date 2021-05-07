#!/bin/bash
#Copyright GammaByte.xyz 2021
kvmtop -p json -r 1 --mem --host --disk --io --net --cpu --pressure --verbose | jq '.domains[] .name' | sed 's/"//g'