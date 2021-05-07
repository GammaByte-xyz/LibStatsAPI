#!/bin/bash

echo $(virsh domstats --cpu-total|awk 'BEGIN { ORS = " " } { print }')|sed 's/Domain:/\nDomain:/g' | sed 1d | ruby stdout2json  | sed "s/'//g"
