package main

import "C"
import (
	"database/sql"
	"encoding/json"
	"encoding/xml"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/libvirt/libvirt-go"
	"golang.org/x/net/context"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"libvirt.org/libvirt-go-xml"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Set logging facility
var l = log.New(os.Stdout, "[LibStatsAPI] ", 2)

// Verify functionality of API with the "/" URI path
func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "API Endpoint Hit\n")
}

// Handle all HTTP requests on different paths
func handleRequests() {
	http.HandleFunc("/", homePage)
	http.HandleFunc("/api/kvm/stats", getStats)
	http.HandleFunc("/api/kvm/domains", getDomains)
	http.HandleFunc("/api/kvm/ram-usage", getRamUsage)
	http.HandleFunc("/api/kvm/create/domain", createDomain)
	http.HandleFunc("/api/kvm/delete/domain", deleteDomain)

	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config.yml")
	yamlConfig, err := ioutil.ReadFile(filename)

	if err != nil {
		panic(err)
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	listenAddr := fmt.Sprintf("%s:%s", ConfigFile.ListenAddress, ConfigFile.ListenPort)

	// Listen on specified port
	l.Fatal(http.ListenAndServe(listenAddr, nil))
}

// This is 1 GiB (gibibyte) in bytes
const (
	GiB = 1073741824 // 1 GiB = 2^30 bytes
)

// Main function that always runs first
func main() {

	// Check to see if config file exists
	if fileExists("/etc/gammabyte/lsapi/config.yml") {
		l.Println("Config file found.")
	} else {
		l.Println("Config file '/etc/gammabyte/lsapi/config.yml' not found!")
	}

	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config.yml")
	yamlConfig, err := ioutil.ReadFile(filename)

	if err != nil {
		panic(err)
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	// Connect to MariaDB
	dbConnectString := fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/lsapi", ConfigFile.SqlUser, ConfigFile.SqlPassword)
	db, err := sql.Open("mysql", dbConnectString)

	if err != nil {
		l.Printf("Error - could not connect to MySQL DB:\n %s\n", err)
		panic(err)
	}

	err = db.Ping()
	if err != nil {
		l.Printf("Error - could not connect to MySQL DB:\n %s\n", err)
		panic(err)
	} else {
		l.Printf("Successfully connected to MySQL DB.\n")
	}

	handleRequests()
}

// Generate a MAC address to use for the VPS
func genMac() string {
	buf := make([]byte, 6)
	_, err := rand.Read(buf)
	if err != nil {
		l.Println("error:", err)
		return ""
	}
	buf[0] = (buf[0] | 2) & 0xfe // Set local bit, ensure unicast address
	macAddr := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])
	return macAddr
}

// Retrieve statistics of the host
func getStats(w http.ResponseWriter, r *http.Request) {
	args := []string{"getStats.sh", "-a"}

	cmd := exec.Command("bash", args...)
	stdout, err := cmd.Output()

	if err != nil {
		l.Println(err.Error())
		return
	}

	l.Println(cmd)
	l.Println(string(stdout))
	fmt.Fprintf(w, string(stdout))
}

// Retrieve the ram usage of the host
func getRamUsage(w http.ResponseWriter, r *http.Request) {
	args := []string{"getStats.sh", "-r"}

	cmd := exec.Command("bash", args...)
	stdout, err := cmd.Output()

	if err != nil {
		l.Println(err.Error())
		return
	}

	l.Println(cmd)
	l.Println(string(stdout))
	fmt.Fprintf(w, string(stdout))
}

// Set values for alphabetic random string generation
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
)

type configFile struct {
	VolumePath      string `yaml:"volume_path"`
	ListenPort      string `yaml:"listen_port"`
	ListenAddress   string `yaml:"listen_address"`
	SqlPassword     string `yaml:"sql_password"`
	Manufacturer    string `yaml:"vm_manufacturer"`
	SqlUser         string `yaml:"sql_user"`
	DomainBandwidth int    `yaml:"domain_bandwidth"`
}

// Values parsed from JSON API input that can be used later
type createDomainStruct struct {
	// VM Specs
	RamSize            int    `json:"RamSize,string,omitempty"`
	CpuSize            int    `json:"CpuSize,string,omitempty"`
	DiskSize           int    `json:"DiskSize,string,omitempty"`
	OperatingSystem    string `json:"OperatingSystem"`
	Network            string `json:"Network"`
	VncPasswordEnabled bool   `json:"VncPasswordEnabled"`
	VncPassword        string `json:"VncPassword"`
	NetworkFilter      string `json:"NetworkFilter"`

	// User Information
	UserEmail string `json:"UserEmail"`
	UserID    int    `json:"UserID,string,omitempty"`
	FullName  string `json:"FullName"`
	UserRole  string `json:"UserRole"`
	Username  string `json:"Username"`

	// Misc. Data
	CreationDate string `json:"CreationDate"`
}

// Generate a random integer for the VPS ID
func random(min int, max int) int {
	return rand.Intn(max-min) + min
}

// Create the VPS
func createDomain(w http.ResponseWriter, r *http.Request) {

	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config.yml")
	yamlConfig, err := ioutil.ReadFile(filename)

	if err != nil {
		panic(err)
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	// Decode JSON & assign the json value struct to a variable we can use here
	decoder := json.NewDecoder(r.Body)
	var t *createDomainStruct = &createDomainStruct{}

	// Set the maximum bytes able to be consumed by the API to prevent denial of service
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	// Decode the struct internally
	err = decoder.Decode(&t)
	if err != nil {
		l.Println(err.Error())
		return
	}

	if err == nil {
		fmt.Fprintf(w, "\n  [1/6] Request received! Provisioning VM...\n")
		fmt.Fprintf(w, "  ------------------------------------------\n")
	}

	// Print values to both console and API output
	l.Printf("Got API request.\n\n")
	l.Printf("RAM => %dGB\n", t.RamSize)
	l.Printf("vCPUs => %d\n", t.CpuSize)
	l.Printf("Disk Size => %dGB\n", t.DiskSize)
	l.Printf("Operating System => %s\n", t.OperatingSystem)
	l.Printf("User Email => %s\n", t.UserEmail)
	l.Printf("User ID => %d\n", t.UserID)
	l.Printf("Full Name => %s\n", t.FullName)
	l.Printf("Username => %s\n", t.Username)
	l.Printf("User Role => %s\n", t.UserRole)
	l.Printf("\n")
	l.Printf("VM Creation Date: %s\n", t.CreationDate)

	fmt.Fprintf(w, "  RAM => %dGB\n", t.RamSize)
	fmt.Fprintf(w, "  vCPUs => %d\n", t.CpuSize)
	fmt.Fprintf(w, "  Disk Size => %dGB\n", t.DiskSize)
	fmt.Fprintf(w, "  Operating System => %s\n", t.OperatingSystem)
	fmt.Fprintf(w, "  User Email => %s\n", t.UserEmail)
	fmt.Fprintf(w, "  User ID => %d\n", t.UserID)
	fmt.Fprintf(w, "  Full Name => %s\n", t.FullName)
	fmt.Fprintf(w, "  Username => %s\n", t.FullName)
	fmt.Fprintf(w, "  User Role => %s\n", t.UserRole)
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "  VM Creation Date: %s\n", t.CreationDate)
	fmt.Fprintf(w, "  ------------------------------------------\n")

	// Set random ID
	rand.Seed(time.Now().UnixNano())
	randID := random(1, 99999999999)
	l.Printf("Random Domain ID: %d\n\n\n", randID)
	domainID := randID

	domainName := fmt.Sprintf("%s-VPS-%d", t.Username, domainID)

	// ConfigFile.VolumePath REQUIRES A TRAILING SLASH
	qcow2Name := fmt.Sprintf("%s%s", ConfigFile.VolumePath, domainName)
	qcow2Size := fmt.Sprintf("%d%s", t.DiskSize, "G")

	// Provision VPS at specified location
	qcow2Args := []string{"create", "-f", "qcow2", "-o", "preallocation=metadata", qcow2Name, qcow2Size}
	cmd := exec.Command("qemu-img", qcow2Args...)
	stdout, err := cmd.Output()
	if err != nil {
		l.Println(err.Error())
		l.Println(qcow2Args)
		l.Println(cmd)
		l.Println(string(stdout))
		fmt.Fprintf(w, string(stdout))
		fmt.Fprintf(w, "  [2/6] Error, VPS disk failed to provision. The error is printed below.\n")
		errcode := fmt.Sprintf("  %s\n", err)
		fmt.Fprintf(w, errcode)
		revertArgs := []string{"-rf", qcow2Name}
		exec.Command("rm", revertArgs...)
		l.Fatal("Failed.")
		return
	}
	if err == nil {
		fmt.Fprintf(w, "  [2/6] VPS disk successfully created!\n")
	}

	// Change permissions of VPS disk so that qemu can interface with it over NFS
	chmodArgs := []string{"777", qcow2Name}
	cmd = exec.Command("chmod", chmodArgs...)
	stdout, err = cmd.Output()
	if err != nil {
		l.Println(err.Error())
		l.Println(cmd)
		fmt.Fprintf(w, "  [2.5/6] Error, changing permissions of VPS disk failed. The error is printed below.\n")
		fmt.Fprintf(w, "%s", cmd)
		revertArgs := []string{"-rf", qcow2Name}
		exec.Command("rm", revertArgs...)
		l.Fatal("Failed.")
		return
	}

	// ALl the variables below set the pointers that libvirt-go can understand
	var macAddr = genMac()

	var ramConfMemory *libvirtxml.DomainMemory = &libvirtxml.DomainMemory{
		Unit:  "GiB",
		Value: uint(t.RamSize),
	}

	var ramConfCurrentMemory *libvirtxml.DomainCurrentMemory = &libvirtxml.DomainCurrentMemory{
		Value: uint(t.RamSize),
		Unit:  "GiB",
	}

	var cpuConfVCPU *libvirtxml.DomainVCPU = &libvirtxml.DomainVCPU{
		Current: uint(t.CpuSize),
		Value:   uint(t.CpuSize),
	}

	var confDomainOS *libvirtxml.DomainOS = &libvirtxml.DomainOS{
		Type: &libvirtxml.DomainOSType{
			Type:    "hvm",
			Machine: "pc-q35-rhel8.2.0",
			Arch:    "x86_64",
		},
		FirmwareInfo: &libvirtxml.DomainOSFirmwareInfo{
			Features: nil,
		},
		InitUser:  "root",
		InitGroup: "root",
		BootMenu: &libvirtxml.DomainBootMenu{
			Enable:  "yes",
			Timeout: "4000",
		},
		SMBios: &libvirtxml.DomainSMBios{
			Mode: "sysinfo",
		},
	}

	var confSysInfo = []libvirtxml.DomainSysInfo{
		libvirtxml.DomainSysInfo{
			SMBIOS: &libvirtxml.DomainSysInfoSMBIOS{
				BIOS: &libvirtxml.DomainSysInfoBIOS{
					Entry: []libvirtxml.DomainSysInfoEntry{
						libvirtxml.DomainSysInfoEntry{
							Name:  "vendor",
							Value: ConfigFile.Manufacturer,
						},
					},
				},
				System: &libvirtxml.DomainSysInfoSystem{
					Entry: []libvirtxml.DomainSysInfoEntry{
						libvirtxml.DomainSysInfoEntry{
							Name:  "manufacturer",
							Value: ConfigFile.Manufacturer,
						},
						libvirtxml.DomainSysInfoEntry{
							Name:  "product",
							Value: "HPC VPS",
						},
						libvirtxml.DomainSysInfoEntry{
							Name:  "version",
							Value: "v4.8.1",
						},
					},
				},
				BaseBoard: []libvirtxml.DomainSysInfoBaseBoard{
					libvirtxml.DomainSysInfoBaseBoard{
						Entry: []libvirtxml.DomainSysInfoEntry{
							libvirtxml.DomainSysInfoEntry{
								Name:  "manufacturer",
								Value: ConfigFile.Manufacturer,
							},
							libvirtxml.DomainSysInfoEntry{
								Name:  "product",
								Value: "HPC VPS",
							},
							libvirtxml.DomainSysInfoEntry{
								Name:  "version",
								Value: "v4.8.1",
							},
						},
					},
				},
				Chassis: &libvirtxml.DomainSysInfoChassis{
					Entry: []libvirtxml.DomainSysInfoEntry{
						libvirtxml.DomainSysInfoEntry{
							Name:  "manufacturer",
							Value: ConfigFile.Manufacturer,
						},
						libvirtxml.DomainSysInfoEntry{
							Name:  "version",
							Value: "v4.8.1",
						},
						libvirtxml.DomainSysInfoEntry{
							Name:  "sku",
							Value: ConfigFile.Manufacturer,
						},
					},
				},
				Processor: []libvirtxml.DomainSysInfoProcessor{
					libvirtxml.DomainSysInfoProcessor{
						Entry: []libvirtxml.DomainSysInfoEntry{
							libvirtxml.DomainSysInfoEntry{
								Name:  "manufacturer",
								Value: ConfigFile.Manufacturer,
							},
						},
					},
				},
			},
		},
	}

	var confCPUType *libvirtxml.DomainCPU = &libvirtxml.DomainCPU{
		Mode:       "host-passthrough",
		Migratable: "on",
		Check:      "none",
		Topology: &libvirtxml.DomainCPUTopology{
			Sockets: 1,
			Cores:   t.CpuSize,
			Threads: 1,
		},
		Cache: &libvirtxml.DomainCPUCache{
			Level: 3,
			Mode:  "emulate",
		},
		Features: nil,
	}

	var confClock *libvirtxml.DomainClock = &libvirtxml.DomainClock{
		TimeZone: "utc",
	}

	// Generate outbound/inbound peak in kilobytes from megabits per second
	var outboundPeak int = ConfigFile.DomainBandwidth * 1000

	// Check input values for sanity (GammaByte.xyz Specific)

	if !(t.Network == "default" || t.Network == "infranet") {
		fmt.Fprintf(w, "Network %s not found!\n", t.Network)
		l.Fatalf("Network %s not found!\n", t.Network)
	}

	installCD := fmt.Sprintf("%sisos/netboot.xyz.iso", ConfigFile.VolumePath)

	var confDevices *libvirtxml.DomainDeviceList = &libvirtxml.DomainDeviceList{
		Disks: []libvirtxml.DomainDisk{
			libvirtxml.DomainDisk{
				Device: "cdrom",
				Driver: &libvirtxml.DomainDiskDriver{
					Name: "qemu",
					Type: "raw",
				},
				Source: &libvirtxml.DomainDiskSource{
					File: &libvirtxml.DomainDiskSourceFile{
						File: installCD,
					},
				},
				Target: &libvirtxml.DomainDiskTarget{
					Dev: "vdb",
					Bus: "sata",
				},
				Boot: &libvirtxml.DomainDeviceBoot{
					Order: 2,
				},
			},
			libvirtxml.DomainDisk{
				Driver: &libvirtxml.DomainDiskDriver{
					Cache:       "directsync",
					IO:          "native",
					ErrorPolicy: "stop",
				},
				Source: &libvirtxml.DomainDiskSource{
					File: &libvirtxml.DomainDiskSourceFile{
						File:     fmt.Sprintf("%s%s", ConfigFile.VolumePath, domainName),
						SecLabel: nil,
					},
				},
				BlockIO: &libvirtxml.DomainDiskBlockIO{
					LogicalBlockSize:  512,
					PhysicalBlockSize: 8192,
				},
				Target: &libvirtxml.DomainDiskTarget{
					Dev: "vda",
					Bus: "virtio",
				},
				IOTune: &libvirtxml.DomainDiskIOTune{
					ReadBytesSec:  146800640,
					WriteBytesSec: 89128960,
				},
				Boot: &libvirtxml.DomainDeviceBoot{
					Order: 1,
				},
				Alias: &libvirtxml.DomainAlias{
					Name: domainName,
				},
			},
		},
		Interfaces: []libvirtxml.DomainInterface{
			libvirtxml.DomainInterface{
				MAC: &libvirtxml.DomainInterfaceMAC{
					Address: macAddr,
				},
				Source: &libvirtxml.DomainInterfaceSource{
					Network: &libvirtxml.DomainInterfaceSourceNetwork{
						Network: t.Network,
					},
				},
				Model: &libvirtxml.DomainInterfaceModel{
					Type: "virtio",
				},
				FilterRef: &libvirtxml.DomainInterfaceFilterRef{
					Filter: t.NetworkFilter,
				},
				Bandwidth: &libvirtxml.DomainInterfaceBandwidth{
					Outbound: &libvirtxml.DomainInterfaceBandwidthParams{
						Peak:    &outboundPeak,
						Average: &outboundPeak,
						Burst:   &outboundPeak,
					},
					Inbound: &libvirtxml.DomainInterfaceBandwidthParams{
						Peak:    &outboundPeak,
						Average: &outboundPeak,
						Burst:   &outboundPeak,
					},
				},
			},
		},
		Graphics: []libvirtxml.DomainGraphic{
			libvirtxml.DomainGraphic{
				VNC: &libvirtxml.DomainGraphicVNC{
					AutoPort:    "yes",
					SharePolicy: "ignore",
					Listen:      "0.0.0.0",
				},
			},
		},
		Videos: []libvirtxml.DomainVideo{
			libvirtxml.DomainVideo{
				Model: libvirtxml.DomainVideoModel{
					Type: "qxl",
				},
			},
		},
	}

	// Assign the variables shown above to the domcfg var, which is of the type "&libvirtxml.domain"
	domcfg := &libvirtxml.Domain{
		XMLName:       xml.Name{},
		Type:          "kvm",
		ID:            &domainID,
		Name:          domainName,
		Title:         domainName,
		Description:   domainName,
		Metadata:      nil,
		MaximumMemory: nil,
		Memory:        ramConfMemory,
		CurrentMemory: ramConfCurrentMemory,
		BlockIOTune:   nil,
		MemoryTune:    nil,
		MemoryBacking: nil,
		VCPU:          cpuConfVCPU,
		VCPUs:         nil,
		IOThreads:     2,
		IOThreadIDs:   nil,
		CPUTune:       nil,
		Resource:      nil,
		SysInfo:       confSysInfo,
		OS:            confDomainOS,
		CPU:           confCPUType,
		Clock:         confClock,
		OnPoweroff:    "destroy",
		OnReboot:      "restart",
		OnCrash:       "restart",
		Devices:       confDevices,
	}

	// Parse the values into human readable XML
	xmldoc, err := domcfg.Marshal()
	if err != nil {
		fmt.Fprintf(w, "Failed to parse generated XML buffer into readable output. Exiting.\n")
		fmt.Fprintf(w, "Err --> %s\n", err)
		revertArgs := []string{"-rf", qcow2Name}
		exec.Command("rm", revertArgs...)
		l.Fatal("Failed.")
		return
	}

	// Connect to qemu-kvm
	conn, err := libvirt.NewConnect("qemu:///system?socket=/var/run/libvirt/libvirt-sock")
	if err != nil {
		l.Fatalf("Failed! \nReason: %s\n", err)
		l.Fatalf("Failed to connect to qemu.n\n")
		revertArgs := []string{"-rf", qcow2Name}
		exec.Command("rm", revertArgs...)
		l.Fatal("Failed.")
		return
	}
	defer conn.Close()

	if err == nil {
		fmt.Fprintf(w, "  [2/6] Successfully connected to QEMU-KVM!\n")
	}

	// Finally, define the VPS
	dom, err := conn.DomainDefineXML(xmldoc)

	if err != nil {
		fmt.Fprintf(w, "Failed to define new domain from XML. Exiting.\n")
		fmt.Fprintf(w, "Err --> %s\n", err)
		fmt.Fprintf(w, "VPS MAC Address: %s\n", macAddr)
		revertArgs := []string{"-rf", qcow2Name}
		exec.Command("rm", revertArgs...)
		l.Fatal("Failed.")
		l.Println(dom)
		return
	}

	if err == nil {
		fmt.Fprintf(w, "  [5/6] Successfully defined new VPS!\n")
	}

	// Configure the VPS to automatically start when the host boots
	autostartDomainArgs := []string{"autostart", domainName}
	cmd = exec.Command("virsh", autostartDomainArgs...)
	stdout, err = cmd.Output()
	if err != nil {
		l.Println(err.Error())
		l.Println(cmd)
		fmt.Fprintf(w, "  [6/6] Error, autostart configuration setup of VPS failed. The error is printed below.\n")
		fmt.Fprintf(w, "  VPS MAC Address: %s\n", macAddr)
		fmt.Fprintf(w, "%s", cmd)
		revertArgs := []string{"-rf", qcow2Name}
		exec.Command("rm", revertArgs...)
		l.Fatal("Failed.")
		return
	}
	if err == nil {
		fmt.Fprintf(w, "  [6/6] Successfully enabled autostart on VPS.\n")
	}

	// Start the VPS now
	startDomainArgs := []string{"start", domainName}
	cmd = exec.Command("virsh", startDomainArgs...)
	stdout, err = cmd.Output()
	if err != nil {
		l.Println(err.Error())
		l.Println(cmd)
		fmt.Fprintf(w, "  [6/6] Error, starting VPS failed. The error is printed below.\n")
		fmt.Fprintf(w, "%s\n", cmd)
		fmt.Fprintf(w, "  VPS MAC Address: %s\n", macAddr)
		revertDiskArgs := []string{"-rf", qcow2Name}
		exec.Command("rm", revertDiskArgs...)
		l.Fatal("Failed.")
		RevertDomainArgs := []string{"undefine", domainName}
		exec.Command("virsh", RevertDomainArgs...)
		return
	}

	if err == nil {
		fmt.Fprintf(w, "  [6/6] Successfully started VPS!\n")
		fmt.Fprintf(w, "\n\n  VPS Name: %s\n", domainName)
		fmt.Fprintf(w, "  VPS MAC Address: %s\n", macAddr)
	}

	domIP := setIP(t.Network, macAddr, domainName, qcow2Name, t.UserEmail, t.FullName, t.Username)
	fmt.Fprintf(w, "  VPS IP: %s\n", domIP)

}

type domainNetworkDomainName struct {
	DomainName string `json:"DomainName"`
	Details    domainNetworks
}

// Write values to JSON file with this data struct
type domainNetworks struct {
	NetworkName string `json:"NetworkName"`
	MacAddress  string `json:"MacAddress"`
	IpAddress   string `json:"IpAddress"`
}

type dbValues struct {
	DomainName   string
	NetworkName  string
	MacAddress   string
	IpAddress    string
	DiskPath     string
	TimeCreated  string
	UserEmail    string
	UserFullName string
	UserName     string
}

// Set the IP address of the VM based on the MAC
func setIP(network string, macAddr string, domainName string, qcow2Name string, userEmail string, userFullName string, userName string) string {

	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config.yml")
	yamlConfig, err := ioutil.ReadFile(filename)

	if err != nil {
		panic(err)
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	// Connect to MariaDB
	dbConnectString := fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/lsapi", ConfigFile.SqlUser, ConfigFile.SqlPassword)
	db, err := sql.Open("mysql", dbConnectString)

	// if there is an error opening the connection, handle it
	if err != nil {
		panic(err.Error())
	}

	// defer the close till after the main function has finished
	// executing
	defer db.Close()

	query := `CREATE TABLE IF NOT EXISTS domaininfo(domain_name text, network text, mac_address text, ip_address text, disk_path text, time_created text, user_email text, user_full_name text, username text)`

	ctx, cancelfunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelfunc()

	res, err := db.ExecContext(ctx, query)
	if err != nil {
		l.Fatalf("Error %s when creating domaininfo table", err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		l.Fatalf("Error %s when getting rows affected", err)
	}
	l.Printf("Rows affected when creating table: %d", rows)

	// Connect to Qemu
	conn, err := libvirt.NewConnect("qemu:///system?socket=/var/run/libvirt/libvirt-sock")
	if err != nil {
		l.Fatalf("Failed to connect to qemu")
		revertDiskArgs := []string{"-rf", qcow2Name}
		exec.Command("rm", revertDiskArgs...)
		l.Fatal("Failed.")
		RevertDomainArgs := []string{"undefine", domainName}
		exec.Command("virsh", RevertDomainArgs...)
		return ""
	}
	defer conn.Close()

	net, err := conn.LookupNetworkByName(network)
	l.Printf("Network: %s\n", network)
	if err != nil {
		l.Printf("Error: Could not find network: %s\n%s\n", net, err)
		revertDiskArgs := []string{"-rf", qcow2Name}
		exec.Command("rm", revertDiskArgs...)
		l.Fatal("Failed.")
		RevertDomainArgs := []string{"undefine", domainName}
		exec.Command("virsh", RevertDomainArgs...)
		return ""
	}
	leases, err := net.GetDHCPLeases()
	if err != nil {
		l.Printf("Error: Could not get leases: %s\n%s\n", leases, err)
		revertDiskArgs := []string{"-rf", qcow2Name}
		exec.Command("rm", revertDiskArgs...)
		l.Fatal("Failed.")
		RevertDomainArgs := []string{"undefine", domainName}
		exec.Command("virsh", RevertDomainArgs...)
		return ""
	}

	ipMap := map[string]struct{}{}

	for _, lease := range leases {
		l.Printf("  %s\n", lease.IPaddr)
		ipMap[lease.IPaddr] = struct{}{}
	}

	rand.Seed(time.Now().Unix())
	randIP := fmt.Sprintf("%d.%d.%d.%d", 192, 168, 2, rand.Intn(254))

	_, exists := ipMap[randIP]
	l.Printf("  IP Exists: %t\n", exists)
	l.Printf("  Random IP: %s\n\n", randIP)

	if exists == false {
		dhLease := &libvirtxml.NetworkDHCPHost{
			MAC:  macAddr,
			Name: domainName,
			IP:   randIP,
		}
		dhSection := libvirt.NetworkUpdateSection(4)

		var dhLeaseString, _ = xml.Marshal(dhLease)
		l.Printf("Inserted network info: %s\n\n", dhLeaseString)

		netUpdateFlags0 := libvirt.NetworkUpdateFlags(0)

		// This one only updates the live state of the network, which is not what we want. We want persistent AND live updates
		//netUpdateFlags1 := libvirt.NetworkUpdateFlags(1)

		netUpdateFlags2 := libvirt.NetworkUpdateFlags(2)

		net.Update(libvirt.NETWORK_UPDATE_COMMAND_ADD_LAST, dhSection, -1, string(dhLeaseString), netUpdateFlags0)

		// This one only updates the live state of the network, which is not what we want. We want persistent AND live updates
		//net.Update(libvirt.NETWORK_UPDATE_COMMAND_ADD_LAST, dhSection, -1, string(dhLeaseString), netUpdateFlags1)

		net.Update(libvirt.NETWORK_UPDATE_COMMAND_ADD_LAST, dhSection, -1, string(dhLeaseString), netUpdateFlags2)
		if err != nil {
			l.Fatalf("Failed to update network. Error: \n%s\n", err)
			revertDiskArgs := []string{"-rf", qcow2Name}
			exec.Command("rm", revertDiskArgs...)
			l.Fatal("Failed.")
			RevertDomainArgs := []string{"undefine", domainName}
			exec.Command("virsh", RevertDomainArgs...)
			return ""
		}

	} else if exists == true {
		setIP(network, macAddr, domainName, qcow2Name, userEmail, userFullName, userName)
	}

	// Get the current date/time
	dt := time.Now()
	// Generate the insert string
	insertData := fmt.Sprintf("INSERT INTO domaininfo (domain_name, network, mac_address, ip_address, disk_path, time_created, user_email, user_full_name, username) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')", domainName, network, macAddr, randIP, qcow2Name, dt.String(), userEmail, userFullName, userName)
	l.Printf("MySQL ==> %s\n\n", insertData)

	res, err = db.Exec(insertData)

	if err != nil {
		panic(err.Error())
		revertDiskArgs := []string{"-rf", qcow2Name}
		exec.Command("rm", revertDiskArgs...)
		l.Fatal("Failed.")
		RevertDomainArgs := []string{"undefine", domainName}
		exec.Command("virsh", RevertDomainArgs...)
		return ""
	}

	lastId, err := res.LastInsertId()

	if err != nil {
		l.Fatal(err)
		revertDiskArgs := []string{"-rf", qcow2Name}
		exec.Command("rm", revertDiskArgs...)
		l.Fatal("Failed.")
		RevertDomainArgs := []string{"undefine", domainName}
		exec.Command("virsh", RevertDomainArgs...)
		return ""
	}

	l.Printf("MySQL ==> The last inserted row id: %d\n", lastId)

	return randIP
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func checkFile(filename string) error {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		_, err := os.Create(filename)
		if err != nil {
			return err
		}
	}
	return nil
}

// Get the existing domains and print them
func getDomains(w http.ResponseWriter, r *http.Request) {
	// Read the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config.yml")
	yamlConfig, err := ioutil.ReadFile(filename)

	// Parse the config file
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	// Connect to MariaDB
	dbConnectString := fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/lsapi", ConfigFile.SqlUser, ConfigFile.SqlPassword)
	db, err := sql.Open("mysql", dbConnectString)

	// if there is an error opening the connection, handle it
	if err != nil {
		panic(err.Error())
	}

	// defer the close till after the main function has finished
	// executing
	defer db.Close()

	conn, err := libvirt.NewConnect("qemu:///system?socket=/var/run/libvirt/libvirt-sock")
	if err != nil {
		l.Fatalf("failed to connect to qemu\n")
	}
	defer conn.Close()

	doms, err := conn.ListAllDomains(libvirt.CONNECT_LIST_DOMAINS_ACTIVE)

	l.Printf("All VMs:\n")
	fmt.Fprintf(w, "All VMs:\n")
	for _, dom := range doms {
		name, err := dom.GetName()
		if err == nil {
			l.Printf("  %s\n", name)
			fmt.Fprintf(w, "  %s\n", name)
		}
		dom.Free()
	}

	// Execute MySQL Query to get all managed VMs
	query := `SELECT domain_name FROM domaininfo`
	dbVars, err := db.Query(query)
	if err != nil {
		fmt.Fprint(w, "Could not get domains from MySQL.")
		l.Fatalf("Could not get domains from MySQL.")
	}

	l.Printf("All LibStatsAPI Managed VMs:\n")
	fmt.Fprintf(w, "All LibStatsAPI Managed VMs:\n")
	var d dbValues
	var totalLsapiVMs int
	for dbVars.Next() {
		err := dbVars.Scan(&d.DomainName, &totalLsapiVMs)
		if err != nil {
			l.Fatal(err)
		}
		fmt.Fprintf(w, "  %s\n", d.DomainName)
		l.Printf("  %s\n", d.DomainName)
	}

	l.Printf("\nTotal VMs: %d\n", len(doms))
	fmt.Fprintf(w, "\nTotal VMs: %d\n", len(doms))
	l.Printf("Total LibStatsAPI Managed VMs: %d\n", totalLsapiVMs)
	fmt.Fprintf(w, "total LibStatsAPI Managed VMs: %d\n", totalLsapiVMs)
}

// Delete domain based on values
type deleteDomainStruct struct {
	VpsName string `json:"VpsName"`
}

func deleteDomain(w http.ResponseWriter, r *http.Request) {
	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config.yml")
	yamlConfig, err := ioutil.ReadFile(filename)

	if err != nil {
		panic(err)
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	// Connect to MariaDB
	dbConnectString := fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/lsapi", ConfigFile.SqlUser, ConfigFile.SqlPassword)
	db, err := sql.Open("mysql", dbConnectString)

	// if there is an error opening the connection, handle it
	if err != nil {
		panic(err.Error())
	}

	// defer the close till after the main function has finished
	// executing
	defer db.Close()

	// Create a new decoder
	decoder := json.NewDecoder(r.Body)
	var t *deleteDomainStruct = &deleteDomainStruct{}

	// Set the maximum bytes able to be consumed by the API to prevent denial of service
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	// Decode the struct internally
	err = decoder.Decode(&t)
	if err != nil {
		l.Println(err.Error())
		return
	}
	// Connect to Qemu-KVM/Libvirt
	conn, err := libvirt.NewConnect("qemu:///system?socket=/var/run/libvirt/libvirt-sock")
	if err != nil {
		l.Fatalf("Failed to connect to qemu")
	}
	defer conn.Close()

	// Check to see if the VPS name has been defined. If not, notify endpoint & exit.
	if t.VpsName != "" {
		l.Printf("\nGot request to remove domain: %s\n", t.VpsName)
		domain, _ := conn.LookupDomainByName(t.VpsName)
		fmt.Fprintf(w, "Domain to delete: %s\n", t.VpsName)

		var d dbValues
		queryData := fmt.Sprintf("SELECT domain_name, ip_address, mac_address, network, disk_path, time_created, user_email, user_full_name, username FROM domaininfo WHERE domain_name ='%s'", t.VpsName)
		l.Println(queryData)
		err := db.QueryRow(queryData).Scan(&d.DomainName, &d.IpAddress, &d.MacAddress, &d.NetworkName, &d.DiskPath, &d.TimeCreated, &d.UserEmail, &d.UserFullName, &d.UserName)
		l.Printf("Domain name: %s\n Ip Address: %s\n Mac Address: %s\n Network Name: %s\n Disk Path: %s\n Date Created: %s\n User Email: %s\n User's Full Name: %s\n Username: %s\n", d.DomainName, d.IpAddress, d.MacAddress, d.NetworkName, d.DiskPath, d.TimeCreated, d.UserEmail, d.UserFullName, d.UserName)
		if err != nil {
			l.Fatalf(err.Error())
		}

		dhSection := libvirt.NetworkUpdateSection(4)

		dhLeaseString := fmt.Sprintf("<host mac='%s'/>", d.MacAddress)
		l.Printf("XML to query and delete from network %s: %s\n", d.NetworkName, dhLeaseString)

		netUpdateFlags0 := libvirt.NetworkUpdateFlags(0)

		// This one only updates the live state of the network, which is not what we want. We want persistent AND live updates
		// netUpdateFlags1 := libvirt.NetworkUpdateFlags(1)

		netUpdateFlags2 := libvirt.NetworkUpdateFlags(2)

		net, err := conn.LookupNetworkByName(d.NetworkName)
		if err != nil {
			fmt.Fprintf(w, "Could not find network %s\n", d.NetworkName)
			l.Fatalf("Could could find network %s\n", d.NetworkName)
		} else {
			fmt.Fprintf(w, "Successfully queried network %s\n", d.NetworkName)
			l.Printf("Successfully queried network %s\n", d.NetworkName)
		}

		err = net.Update(libvirt.NETWORK_UPDATE_COMMAND_DELETE, dhSection, -1, string(dhLeaseString), netUpdateFlags0)
		if err != nil {
			l.Printf("Failed to update network. Error: \n%s\n", err)
			fmt.Fprintf(w, "Failed to update network. Error: \n  %s\n", err)
		} else {
			l.Printf("Successfully updated the live state of network %s\n", d.NetworkName)
			fmt.Fprintf(w, "Successfully updated the live state of network %s\n", d.NetworkName)
		}

		// This one only updates the live state of the network, which is not what we want. We want persistent AND live updates
		/* err = net.Update(libvirt.NETWORK_UPDATE_COMMAND_ADD_LAST, dhSection, -1, string(dhLeaseString), netUpdateFlags1)
		if err != nil {
			l.Printf("Failed to check live network. Error: \n%s\n", err)
			fmt.Fprintf(w, "Failed to check live network. Error: \n  %s\n", err)
		} else {
			l.Printf("Successfully checked the update status on the live network.\n")
			fmt.Fprintf(w, "Succesfully checked the update status on the live network.\n")
		} */

		err = net.Update(libvirt.NETWORK_UPDATE_COMMAND_DELETE, dhSection, -1, string(dhLeaseString), netUpdateFlags2)
		if err != nil {
			l.Printf("Failed to update network. Error: \n%s\n", err)
			fmt.Fprintf(w, "Failed to update network. Error: \n  %s\n", err)
		} else {
			l.Printf("Successfully updated the persistent network.")
			fmt.Fprintf(w, "Successfully updated the persistent network.")
		}

		e := domain.Destroy()
		if e != nil {
			fmt.Fprintf(w, "Error destroying domain: %s (Force Shutdown)\n", t.VpsName)
			l.Printf("Error destroying domain: %s (Force Shutdown)\n", t.VpsName)
		} else {
			fmt.Fprintf(w, "Domain %s was forcefully shut down.\n", t.VpsName)
			l.Printf("Domain %s was forcefully shut down.\n", t.VpsName)
		}
		e = domain.Undefine()
		if e != nil {
			fmt.Fprintf(w, "Error undefining the domain %s\n.", t.VpsName)
			l.Printf("Error undefining the domain %s\n.", t.VpsName)
		} else {
			fmt.Fprintf(w, "Domain %s was undefined successfully.\n", t.VpsName)
			l.Printf("Domain %s was undefined successfully.\n", t.VpsName)
		}
		fileName := fmt.Sprintf(d.DiskPath)
		e = os.Remove(d.DiskPath)
		if e != nil {
			fmt.Fprintf(w, "Domain disk (%s) has failed to purge.\n", fileName)
			l.Printf("Domain disk (%s) has failed to purge.\n", fileName)
			l.Fatal(e)
		} else {
			fmt.Fprintf(w, "Domain disk (%s) was successfully wiped & purged.\n", fileName)
			l.Printf("Domain disk (%s) was successfully wiped & purged.\n", fileName)
		}
		dbQuery := fmt.Sprintf("DELETE FROM domaininfo WHERE domain_name = '%s'", t.VpsName)
		res, err := db.Exec(dbQuery)
		if err != nil {
			fmt.Fprintf(w, "Failed to remove row from DB.\n", err, res)
			l.Fatalf("Failed to remove row from DB.", err, res)
		} else {
			fmt.Fprintf(w, "Successfully removed domain %s from MySQL database.\n", t.VpsName)
			l.Printf("Successfully removed domain %s from MySQL database.\n", t.VpsName)
		}

	} else if t.VpsName == "" {
		fmt.Fprintf(w, "Please specify a domain with the JSON parameter: 'VpsName'\n")
	}

}
