package main

import (
	"fmt"
	"github.com/Terry-Mao/goconf"
)

type TestConfig struct {
	Hostname string `goconf:":hostname"`
	Address  string `goconf:":address"`
}

func parseHostFile() ([]string, []string) {
	conf := goconf.New()
	if err := conf.Parse("hosts.conf"); err != nil {
		panic(err)
	}

	tf := &TestConfig{}
	if err := conf.Unmarshal(tf); err != nil {
		panic(err)
	}

	var hostnames []string
	var hostIPs []string
	var i int = 0
	sections := conf.Sections()
	for i = range conf.Sections() {
		sect := conf.Get(sections[i])

		hostname, err := sect.String("hostname")
		if err != nil {
			fmt.Println(err)
			return nil, nil
		}
		fmt.Printf("Host %d: %s\n", i, hostname)

		addr, err := sect.String("addr")
		if err != nil {
			fmt.Println(err)
			return nil, nil
		}
		fmt.Printf("  Address: %s\n", addr)
		hostnames = append(hostnames, hostname)
		hostIPs = append(hostIPs, addr)
	}
	fmt.Printf("Hosts with hostnames: %d\n", len(hostnames))
	fmt.Printf("Hosts with IPs: %d\n", len(hostIPs))
	return hostnames, hostIPs
}
