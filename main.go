package main

import "C"
import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/libvirt/libvirt-go"
	uuid "github.com/satori/go.uuid"
	"libvirt.org/libvirt-go-xml"
	"log"
	"math/rand"
	"net/http"
	"os/exec"
	"time"
)

type Article struct {
	Title   string `json:"Title"`
	Desc    string `json:"desc"`
	Content string `json:"content"`
}

type Articles []Article

func allArticles(w http.ResponseWriter, r *http.Request) {
	articles := Articles{
		Article{Title: "Test Title", Desc: "Test Desc.", Content: "Hello World"},
	}

	fmt.Println("Endpoint Hit: All articles endpoint")
	json.NewEncoder(w).Encode(articles)
}

func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Homepage Endpoint Hit\n")
}

func handleRequests() {
	http.HandleFunc("/", homePage)
	http.HandleFunc("/articles", allArticles)
	http.HandleFunc("/api/kvm/stats", getStats)
	// http.HandleFunc("/api/kvm/domains", getDomains)
	http.HandleFunc("/api/kvm/ram-usage", getRamUsage)

	http.HandleFunc("/api/kvm/create/domain", createDomain)
	log.Fatal(http.ListenAndServe(":8082", nil))
}

func main() {
	handleRequests()
}

func getStats(w http.ResponseWriter, r *http.Request) {
	args := []string{"getStats.sh", "-a"}

	cmd := exec.Command("bash", args...)
	stdout, err := cmd.Output()

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println(cmd)
	fmt.Println(string(stdout))
	fmt.Fprintf(w, string(stdout))
}

/*func getDomains(w http.ResponseWriter, r *http.Request) {
	args := []string{"getStats.sh", "-d"}

	cmd := exec.Command("bash", args...)
	stdout, err := cmd.Output()

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println(cmd)
	fmt.Println(string(stdout))
	fmt.Fprintf(w, string(stdout))
}*/

func getRamUsage(w http.ResponseWriter, r *http.Request) {
	args := []string{"getStats.sh", "-r"}

	cmd := exec.Command("bash", args...)
	stdout, err := cmd.Output()

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println(cmd)
	fmt.Println(string(stdout))
	fmt.Fprintf(w, string(stdout))
}

type createDomainStruct struct {
	// VM Specs
	RamSize         int    `json:"RamSize,string,omitempty"`
	CpuSize         int    `json:"CpuSize,string,omitempty"`
	DiskSize        int    `json:"DiskSize,string,omitempty"`
	OperatingSystem string `json:"OperatingSystem"`

	// User Information
	UserEmail string `json:"UserEmail"`
	UserID    int    `json:"UserID,string,omitempty"`
	FullName  string `json:"FullName"`
	UserRole  string `json:"UserRole"`

	// Misc. Data
	CreationDate string
}

func random(min int, max int) int {
	return rand.Intn(max-min) + min
}

func createDomain(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var t *createDomainStruct = &createDomainStruct{}

	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	err := decoder.Decode(&t)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	if err == nil {
		fmt.Fprintf(w, "\n  [1/6] Request recieved! Provisioning VM...\n")
	}

	fmt.Printf("  RAM => %dGB\n", t.RamSize)
	fmt.Printf("  vCPUs => %d\n", t.CpuSize)
	fmt.Printf("  Disk Size => %dGB\n", t.DiskSize)
	fmt.Printf("  Operating System => %s\n", t.OperatingSystem)
	fmt.Printf("  User Email => %s\n", t.UserEmail)
	fmt.Printf("  User ID => %d\n", t.UserID)
	fmt.Printf("  Full Name => %s\n", t.FullName)
	fmt.Printf("  User Role => %s\n", t.UserRole)
	fmt.Printf("\n")
	fmt.Printf("  VM Creation Date: %s\n\n", t.CreationDate)

	fmt.Fprintf(w, "RAM => %dGB\n", t.RamSize)
	fmt.Fprintf(w, "vCPUs => %d\n", t.CpuSize)
	fmt.Fprintf(w, "Disk Size => %dGB\n", t.DiskSize)
	fmt.Fprintf(w, "Operating System => %s\n", t.OperatingSystem)
	fmt.Fprintf(w, "User Email => %s\n", t.UserEmail)
	fmt.Fprintf(w, "User ID => %d\n", t.UserID)
	fmt.Fprintf(w, "Full Name => %s\n", t.FullName)
	fmt.Fprintf(w, "User Role => %s\n", t.UserRole)
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "VM Creation Date: %s\n", t.CreationDate)

	rand.Seed(time.Now().UnixNano())
	randID := random(1, 2000000)
	fmt.Printf("Random Domain ID: %d\n", randID)
	domainID := randID

	domainName := fmt.Sprintf("VPS-%d", domainID)

	//fmt.Fprintf(w, domainName)

	DomUuidRaw := uuid.Must(uuid.NewV4())
	DomUUID := DomUuidRaw.String()

	/*ramPtr := uintptr(t.RamSize)
	cpuPtr := uintptr(t.CpuSize)*/

	//var ramPtr int = *(*int)(unsafe.Pointer(&t.RamSize))

	qcow2Name := fmt.Sprintf("%s%s%s", "/mnt/vmblocknew/", domainName, ".qcow2")
	qcow2Size := fmt.Sprintf("%d%s", t.DiskSize, "G")

	qcow2Args := []string{"create", "-f", "qcow2", qcow2Name, qcow2Size}
	cmd := exec.Command("qemu-img", qcow2Args...)
	stdout, err := cmd.Output()
	if err != nil {
		fmt.Println(err.Error())
		fmt.Println(qcow2Args)
		fmt.Println(cmd)
		fmt.Println(string(stdout))
		fmt.Fprintf(w, string(stdout))
		fmt.Fprintf(w, "  [2/6] Error, VPS disk failed to provision. The error is printed below.\n")
		errcode := fmt.Sprintf("  %s\n", err)
		fmt.Fprintf(w, errcode)
		return
	}
	if err == nil {
		fmt.Fprintf(w, "  [2/6] VPS disk successfully created!\n")
	}

	chmodArgs := []string{"777", "/mnt/vmblocknew/", qcow2Name}
	cmd = exec.Command("chmod", chmodArgs...)
	stdout, err = cmd.Output()
	if err != nil {
		fmt.Println(err.Error())
		fmt.Println(cmd)
		fmt.Fprintf(w, "  [2.5/6] Error, changing permissions of VPS disk failed. The error is printed below.\n")
		fmt.Fprintf(w, "%s", cmd)
	}

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
							Value: "GammaByte.xyz",
						},
					},
				},
				System: &libvirtxml.DomainSysInfoSystem{
					Entry: []libvirtxml.DomainSysInfoEntry{
						libvirtxml.DomainSysInfoEntry{
							Name:  "manufacturer",
							Value: "GammaByte.xyz",
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
								Value: "GammaByte.xyz",
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
			},
		},
		libvirtxml.DomainSysInfo{
			FWCfg: &libvirtxml.DomainSysInfoFWCfg{
				Entry: []libvirtxml.DomainSysInfoEntry{
					libvirtxml.DomainSysInfoEntry{
						Name:  "vendor",
						Value: "GammaByte.xyz",
					},
				},
			},
		},
	}

	var confCPUType *libvirtxml.DomainCPU = &libvirtxml.DomainCPU{
		Mode:       "custom",
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

	var confDevices = &libvirtxml.DomainDeviceList{
		Disks: []libvirtxml.DomainDisk{
			libvirtxml.DomainDisk{
				Device: "cdrom",
				Driver: &libvirtxml.DomainDiskDriver{
					Name: "qemu",
					Type: "raw",
				},
				Source: &libvirtxml.DomainDiskSource{
					File: &libvirtxml.DomainDiskSourceFile{
						File: "/mnt/vmblocknew/isos/netboot.xyz.iso",
					},
				},
				Target: &libvirtxml.DomainDiskTarget{
					Dev: "vdb",
					Bus: "sata",
				},
				Boot: &libvirtxml.DomainDeviceBoot{
					Order: 2,
				},
				ReadOnly: &libvirtxml.DomainDiskReadOnly{},
			},
			libvirtxml.DomainDisk{
				Driver: &libvirtxml.DomainDiskDriver{
					Cache:       "none",
					IO:          "native",
					ErrorPolicy: "stop",
				},
				Source: &libvirtxml.DomainDiskSource{
					File: &libvirtxml.DomainDiskSourceFile{
						File:     fmt.Sprint("/mnt/vmblocknew/", domainName, ".qcow2"),
						SecLabel: nil,
					},
				},
				Target: &libvirtxml.DomainDiskTarget{
					Dev: "vda",
					Bus: "virtio",
				},
				Boot: &libvirtxml.DomainDeviceBoot{
					Order: 1,
				},
			},
		},
		Interfaces: []libvirtxml.DomainInterface{
			libvirtxml.DomainInterface{
				Model: &libvirtxml.DomainInterfaceModel{
					Type: "virtio",
				},
				Source: &libvirtxml.DomainInterfaceSource{
					Network: &libvirtxml.DomainInterfaceSourceNetwork{
						Network: "default",
					},
				},
			},
		},
	}

	domcfg := &libvirtxml.Domain{
		XMLName:              xml.Name{},
		Type:                 "kvm",
		ID:                   &domainID,
		Name:                 domainName,
		UUID:                 DomUUID,
		Title:                domainName,
		Description:          domainName,
		Metadata:             nil,
		MaximumMemory:        nil,
		Memory:               ramConfMemory,
		CurrentMemory:        ramConfCurrentMemory,
		BlockIOTune:          nil,
		MemoryTune:           nil,
		MemoryBacking:        nil,
		VCPU:                 cpuConfVCPU,
		VCPUs:                nil,
		IOThreads:            2,
		IOThreadIDs:          nil,
		CPUTune:              nil,
		Resource:             nil,
		SysInfo:              confSysInfo,
		Bootloader:           "",
		BootloaderArgs:       "",
		OS:                   confDomainOS,
		IDMap:                nil,
		Features:             nil,
		CPU:                  confCPUType,
		Clock:                confClock,
		OnPoweroff:           "destroy",
		OnReboot:             "restart",
		OnCrash:              "restart",
		PM:                   nil,
		Perf:                 nil,
		Devices:              confDevices,
		SecLabel:             nil,
		KeyWrap:              nil,
		LaunchSecurity:       nil,
		QEMUCommandline:      nil,
		QEMUCapabilities:     nil,
		QEMUDeprecation:      nil,
		LXCNamespace:         nil,
		BHyveCommandline:     nil,
		VMWareDataCenterPath: nil,
		XenCommandline:       nil,
	}

	xmldoc, err := domcfg.Marshal()

	if err != nil {
		fmt.Fprintf(w, "Failed to parse generated XML buffer into readable output. Exiting.\n")
		fmt.Fprintf(w, "Err --> %s\n", err)
		return
	}

	//fmt.Fprintf(w, "%s\n", xmldoc)
	conn, err := libvirt.NewConnect("qemu:///system?socket=/var/run/libvirt/libvirt-sock")
	if err != nil {
		log.Fatalf("Failed! \nReason: %s\n", err)
		log.Fatalf("Failed to connect to qemu.n\n")
	}

	if err == nil {
		fmt.Fprintf(w, "  [3/6] Successfully connected to QEMU-KVM!\n")
	}

	dom, err := conn.DomainDefineXML(xmldoc)

	if err != nil {
		fmt.Fprintf(w, "Failed to define new domain from XML. Exiting.\n")
		fmt.Fprintf(w, "Err --> %s\n", err)
		return
	}

	if err == nil {
		fmt.Fprintf(w, "  [4/6] Successfully defined new VPS!\n")
	}

	fmt.Println(dom)

	autostartDomainArgs := []string{"autostart", domainName}
	cmd = exec.Command("virsh", autostartDomainArgs...)
	stdout, err = cmd.Output()
	if err != nil {
		fmt.Println(err.Error())
		fmt.Println(cmd)
		fmt.Fprintf(w, "  [5/6] Error, autostart configuration setup of VPS failed. The error is printed below.\n")
		fmt.Fprintf(w, "%s", cmd)
		return
	}
	if err == nil {
		fmt.Fprintf(w, "  [5/6] Successfully enabled autostart on VPS.\n")
	}

	startDomainArgs := []string{"start", domainName}
	cmd = exec.Command("virsh", startDomainArgs...)
	stdout, err = cmd.Output()
	if err != nil {
		fmt.Println(err.Error())
		fmt.Println(cmd)
		fmt.Fprintf(w, "  [6/6] Error, starting VPS failed. The error is printed below.\n")
		fmt.Fprintf(w, "%s", cmd)
		return
	}

	if err == nil {
		fmt.Fprintf(w, "  [6/6] Sucessfully started VPS!\n")
		fmt.Fprintf(w, "\n\n  VPS Name: %s\n", domainName)
	}

}

/*func getDomains(w http.ResponseWriter, r *http.Request){

	conn, err := libvirt.NewConnect("qemu+ssh://root@alpha1-host2/system?socket=/var/run/libvirt/libvirt-sock")
	if err != nil {
		log.Fatalf("failed to connect to qemu")
	}
	defer conn.Close()

	doms, err := conn.ListAllDomains(libvirt.CONNECT_LIST_DOMAINS_ACTIVE)

	for _, dom := range doms {
		name, err := dom.GetName()
		if err == nil {
			fmt.Printf("  %s\n", name)
			fmt.Fprintf(w,"%s\n", name)
		}
		dom.Free()
	}

	fmt.Printf("%d\n", len(doms))
}*/
