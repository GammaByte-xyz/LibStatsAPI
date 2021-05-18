#!/bin/bash

addLeases() {

iplinenum=2
maclinenum=1

while :
do
        virsh net-dhcp-leases default | sed 1,2d | sed $'s/ \{1,\}/\\\n/' | sed $'s/ \{1,\}/\\\n/' | sed $'s/ \{1,\}/\\\n/' | sed $'s/ \{1,\}/\\\n/' | sed $'s/ \{1,\}/\\\n/' | sed $'s/ \{1,\}/\\\n/' | sed $'s/ \{1,\}/\\\n/' | sed '/./,$!d' | sed 1,2d | sed 's/^$/NEWHOST/' | sed '/NEWHOST/,+2 g' | sed '/ipv4/d' | sed ':a; /^\n*$/{ s/\n//; N;  ba};' | sed '/^$/d' | sed '4~4d' | sed '3~3d' | sed '0~2 a\\' | sed 's/\/.*//' > /tmp/kvm.leases
        virsh net-update default add ip-dhcp-host "<host mac='$(cat /tmp/kvm.leases | sed -n "$maclinenum"p)' ip='$(cat /tmp/kvm.leases | sed -n "$iplinenum"p)'/>" --live --config
        ((maclinenum=maclinenum+3))
        ((iplinenum=iplinenum+3))
        cat /tmp/kvm.leases | sed -n "$maclinenum"p
        cat /tmp/kvm.leases | sed -n "$iplinenum"p
        if [[ "$iplinenum" -gt "$(cat /tmp/kvm.leases | wc -l)" ]]; then
                iplinenum=2
                maclinenum=1
        fi
done

}

addLeases