#!/bin/bash
#Copyright GammaByte.xyz 2021
curl -fsSL http://localhost:8081/api/kvm/stats | jq '.host.ram_Total' | sed 's"///g'