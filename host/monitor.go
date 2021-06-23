package main

import (
	"encoding/json"
	"os/exec"
	"time"
)

func gatherMetrics(ConfigFile *configFile) {
	if !fileExists("/usr/bin/kvmtop") {
		l.Printf("Installing kvmtop to /usr/bin...")
		_, err := exec.Command("dnf", "-y", "install", "https://github.com/cha87de/kvmtop/releases/download/2.1.3/kvmtop_2.1.3_linux_amd64.rpm").Output()
		if err != nil {
			l.Printf("Error installing Kvmtop: %s\n", err.Error())
			panic(err.Error())
		}
		l.Printf("Success!")
	}

	switch cf := ConfigFile.MetricsPollRate; {
	case cf == 0:
		l.Printf("Error: Polling rate is either invalid or doesn't exist.")
		panic("Error: Polling rate is either invalid or doesn't exist.")
	case cf == -1:
		l.Printf("Error: Polling rate must be a positive integer.")
		panic("Error: Polling rate is either invalid or doesn't exist.")
	case cf >= 12:
		l.Printf("Error: Polling rate is too high.")
		panic("Error: Polling rate is too high.")
	}
	l.Printf("%t\n", ConfigFile.StoreMetrics)
	l.Printf("%d\n", ConfigFile.MetricsPollRate)
	if ConfigFile.StoreMetrics == true {
		l.Printf("Storing all metrics to MySQL...")
	}
	for range time.Tick(time.Duration(ConfigFile.MetricsPollRate) * time.Second) {
		go func() {
			cmd := exec.Command("/usr/bin/kvmtop", "-r1", "--verbose", "--printer=json", "--cpu", "--mem", "--disk", "--net", "--io", "--pressure", "--host", "--output=file", "--target=/var/log/domain-metrics.log")
			err = cmd.Run()
			if err != nil {
				l.Printf("Error executing Kvmtop (file log): %s\n", err.Error())
			}
		}()
		if ConfigFile.SyslogAddress != "" {
			go func() {
				cmd := exec.Command("/usr/bin/kvmtop", "-r1", "--verbose", "--printer=json", "--cpu", "--mem", "--disk", "--net", "--io", "--pressure", "--host", "--output=udp", "--target="+ConfigFile.SyslogAddress)
				err = cmd.Run()
				if err != nil {
					l.Printf("Error executing Kvmtop (remote syslog): %s\n", err.Error())
				}
			}()
		}
		if ConfigFile.StoreMetrics == true {
			go func() {
				cmd := exec.Command("/usr/bin/kvmtop", "-r1", "--verbose", "--printer=json", "--cpu", "--mem", "--disk", "--net", "--io", "--pressure", "--host")
				out, err := cmd.Output()
				if err != nil {
					//l.Printf("Error getting kvmtop output: %s\n", err.Error())
					return
				}
				timer := time.AfterFunc(time.Duration(ConfigFile.MetricsPollRate-1)*time.Second, func() {
					err := cmd.Process.Kill()
					if err != nil {
						l.Printf("Error: %s\n", err.Error())
						return
					}
				})
				/*err = cmd.Wait()
				if err != nil {
					l.Printf("Error waiting for command: %s\n", err.Error())
					return
				}*/
				timer.Stop()

				var newJson systemMetrics
				if err = json.Unmarshal(out, &newJson); err != nil {
					//l.Printf("Error unmarshalling metrics: %s\n", err.Error())
					return
				}
				for _, b := range newJson.Domains {
					_, err = db.Exec("INSERT INTO metrics (cpu, ram, disk, io_readbytes, io_writebytes, net, net_txbytes, net_rxbytes, timestamp, domain_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", b.CPUOtherTotal, b.RAMUsed, b.DiskSizePhysical, b.IoReadBytes, b.IoWriteBytes, b.NetInterfaces, b.NetTransmittedBytes, b.NetReceivedBytes, time.Now().Format(time.RFC3339), b.Name)
					if err != nil {
						//l.Printf("Error inserting domain metrics into MySQL: %s\n", err.Error())
						continue
					}
				}
				_, err = db.Exec("INSERT INTO host_metrics (cpu , ram, io_readbytes, io_writebytes, net_txbytes, net_rxbytes, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)", newJson.Host.CPUCurfreq, newJson.Host.RAMAvailable, newJson.Host.DiskDeviceReadsmerged, newJson.Host.DiskDeviceWritesmerged, newJson.Host.NetHostTransmittedBytes, newJson.Host.NetHostReceivedBytes, time.Now().Format(time.RFC3339))
				if err != nil {
					//l.Printf("Error inserting host metrics into MySQL: %s\n", err.Error())
					return
				}
			}()
		}
	}
}
