package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
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
	http.HandleFunc("/api/kvm/domains", getDomains)
	http.HandleFunc("/api/kvm/ram-usage", getRamUsage)
	http.HandleFunc("/api/kvm/create/domain", createDomain)
	log.Fatal(http.ListenAndServe(":8081", nil))
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

func getDomains(w http.ResponseWriter, r *http.Request) {
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
}

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
	RamSize         string
	CpuSize         string
	DiskSize        string
	OperatingSystem string

	// User Information
	UserEmail string
	UserID    string
	FullName  string
	UserRole  string

	// Misc. Data
	CreationDate string
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

	//for key, value := range r.Form {
	//	fmt.Printf("%s = %s\n", key, value)
	//	fmt.Fprintf(w, "%+v", t)
	//}
	//fmt.Fprintf(w, "%+v", t)
	//fmt.Fprintf(w,"Create Domain:\n %+v", t)

	fmt.Fprintf(w, "RAM => %sGB\n", t.RamSize)
	fmt.Fprintf(w, "vCPUs => %s\n", t.CpuSize)
	fmt.Fprintf(w, "Disk Size => %sGB\n", t.DiskSize)
	fmt.Fprintf(w, "Operating System => %s\n", t.OperatingSystem)
	fmt.Fprintf(w, "User Email => %s\n", t.UserEmail)
	fmt.Fprintf(w, "User ID => %s\n", t.UserID)
	fmt.Fprintf(w, "Full Name => %s\n", t.FullName)
	fmt.Fprintf(w, "User Role => %s\n", t.UserRole)
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "VM Creation Date: %s\n", t.CreationDate)

}
