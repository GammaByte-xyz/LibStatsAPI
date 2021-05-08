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
