package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
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

	fmt.Printf("RAM => %dGB\n", t.RamSize)
	fmt.Printf("vCPUs => %d\n", t.CpuSize)
	fmt.Printf("Disk Size => %dGB\n", t.DiskSize)
	fmt.Printf("Operating System => %s\n", t.OperatingSystem)
	fmt.Printf("User Email => %s\n", t.UserEmail)
	fmt.Printf("User ID => %d\n", t.UserID)
	fmt.Printf("Full Name => %s\n", t.FullName)
	fmt.Printf("User Role => %s\n", t.UserRole)
	fmt.Printf("\n")
	fmt.Printf("VM Creation Date: %s\n", t.CreationDate)

	rand.Seed(time.Now().UnixNano())
	randID := random(1, 2000000)
	fmt.Printf("Random Domain ID: %d\n", randID)
	domainID := randID
	domainName := fmt.Sprintf("VPS-%d\n", int(domainID))

	fmt.Fprintf(w, domainName)

	domcfg := &libvirtxml.Domain{
		Type: "kvm",
		Name: domainName,
		UUID: "8f99e332-06c4-463a-9099-330fb244e1b3",
	}

	xmldoc, err := xml.Marshal(domcfg)
	fmt.Fprintf(w, xmldoc)

	// Will end up figuring this out later lol

	/*domain := &libvirtxml.Domain{
		XMLName: xml.Name{
			Space: "GammaByte.xyz",
			Local: "VM",
		},
		Type:        "kvm",
		ID:          &domainID,
		Name:        domainName,
		Title:       domainName,
		Description: domainName,
		Metadata: &libvirtxml.DomainMetadata{
			XML: "",
		},
		Memory: (*libvirtxml.DomainMemory)(unsafe.Pointer(&t.RamSize)),
		VCPU:   (*libvirtxml.DomainVCPU)(unsafe.Pointer(&t.CpuSize)),
		OS: &libvirtxml.DomainOS{
			BootDevices: []libvirtxml.DomainBootDevice{
				libvirtxml.DomainBootDevice{
					Dev: "vda",
				},
			},
			Type: &libvirtxml.DomainOSType{
				Arch: "x86_64",
				Type: "hvm",
			},
		},
		OnCrash:    "restart",
		OnPoweroff: "destroy",
		OnReboot:   "restart",
		Devices: &libvirtxml.DomainDeviceList{
			Emulator: "/usr/bin/kvm-spice",
			Graphics: []libvirtxml.DomainGraphic{
				libvirtxml.DomainGraphic{
					VNC: &libvirtxml.DomainGraphicVNC{
						AutoPort: "yes",
						Listen:   "0.0.0.0",
						Listeners: []libvirtxml.DomainGraphicListener{
							libvirtxml.DomainGraphicListener{
								Address: &libvirtxml.DomainGraphicListenerAddress{
									Address: "0.0.0.0",
								},
							},
						},
					},
				},
			},
		},
	}
	fmt.Printf("%s\n", domain)
	fmt.Fprintf(w,"%s\n", domain)*/
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
