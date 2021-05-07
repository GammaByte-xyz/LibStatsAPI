package main

import (
    "fmt"
    "log"
    "net/http"
    "encoding/json"
    "os/exec"
)

type Article struct {
    Title string `json:"Title"`
    Desc string `json:"desc"`
    Content string `json:"content"`
}

type Articles []Article

func allArticles(w http.ResponseWriter, r *http.Request) {
    articles := Articles{
        Article{Title:"Test Title", Desc: "Test Desc.", Content: "Hello World"},
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
    log.Fatal(http.ListenAndServe(":8081", nil))
}

func main() {
    handleRequests()
}

func getStats(w http.ResponseWriter, r *http.Request){
    app := "./cpustats.sh"

    cmd := exec.Command(app)
    stdout, err := cmd.Output()

    if err != nil {
        fmt.Println(err.Error())
        return
    }

    fmt.Println(string(stdout))
    fmt.Fprintf(w, string(stdout))
}
