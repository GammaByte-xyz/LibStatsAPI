package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/", logic)
	/*var listen_interface string = "0.0.0.0:8080"*/
	fmt.Printf("server started on \n")
	if err := http.ListenAndServe("0.0.0.0:8080", nil); err != nil {
		log.Fatal(err)
	}
}

func logic(w http.ResponseWriter, r *http.Request) {
	var content []byte
	var err error
	if r.URL.Path == "/" {
		content, err = ioutil.ReadFile("./www/index.html")
		if err != nil {
			log.Fatal(err.Error())
		}
		_, err = fmt.Fprint(w, string(content))
		if err != nil {
			log.Fatal(err.Error())
		}
	} else if !fileExists("./www/index.html") {
		http.FileServer(http.Dir("./www" + r.URL.Path))
	}
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
