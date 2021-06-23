package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/Showmax/go-fqdn"
	"github.com/klauspost/compress/gzhttp"
	"github.com/machinebox/progress"
	"github.com/tus/tusd/pkg/filestore"
	tusd "github.com/tus/tusd/pkg/handler"
	"golang.org/x/net/context"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	GiB = 1073741823
	MiB = 1048576
)

type prepareVolumeJson struct {
	MasterKey      string `json:"MasterKey"`
	VolumeName     string `json:"VolumeName"`
	SparsifyVolume bool   `json:"SparsifyVolume"`
}

func prepareVolume(w http.ResponseWriter, r *http.Request) {
	// Set the transport options and apply them to the client
	transport := &http.Transport{
		WriteBufferSize: 125000000,
		ReadBufferSize:  125000000,
	}
	client := http.Client{
		Transport: gzhttp.Transport(transport),
		Timeout:   0,
	}

	l.Printf("Got request from host %s to prepare volume", r.RemoteAddr)
	pvj := prepareVolumeJson{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&pvj)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		l.Printf("Error parsing request JSON: %s\n", err.Error())
		_, err = w.Write([]byte("500 Internal Server Error: " + err.Error()))
		if err != nil {
			l.Printf("Error writing error response to client: %s\n", err.Error())
			return
		}
		return
	}
	if pvj.MasterKey != ConfigFile.MasterKey {
		l.Printf("Host %s requested unauthorized access to volume preparation endpoint!", r.Host)
		w.WriteHeader(http.StatusUnauthorized)
		_, err := w.Write([]byte("401 Unauthorized"))
		if err != nil {
			l.Printf("Error returning unauthorized message: %s\n", err.Error())
			return
		}
		return
	}
	if ConfigFile.LegacyStorage != true {
		l.Printf("Nothing to do, image is already prepared.")
		w.WriteHeader(http.StatusOK)
		return
	}
	body := strings.NewReader(fmt.Sprintf(`{"MasterKey": "%s", "VolumeName": "%s"}`, ConfigFile.MasterKey, pvj.VolumeName))
	req, err := http.NewRequest("POST", "https://"+ConfigFile.StorageServer+":8941/api/san/volume/sparsify", body)
	if err != nil {
		l.Printf("Error generating new HTTP request: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte("500 Internal Server Error: " + err.Error()))
		if err != nil {
			l.Printf("Error writing error response to client: %s\n", err.Error())
			return
		}
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		l.Printf("Error sending HTTP request: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte("500 Internal Server Error: " + err.Error()))
		if err != nil {
			l.Printf("Error writing error response to client: %s\n", err.Error())
			return
		}
		return
	}
	if resp.StatusCode != http.StatusOK {
		l.Printf("Invalid response code from storage server: %s\n", resp.Status)
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte("500 Internal Server Error: " + resp.Status))
		if err != nil {
			l.Printf("Error writing error response to client: %s\n", err.Error())
			return
		}
		return
	}
	w.Header().Set("sparseSize", resp.Header.Get("sparseSize"))
	defer resp.Body.Close()
	defer req.Body.Close()
}

func recieveVolumeUpload(w http.ResponseWriter, r *http.Request) {
	l.Printf("Got request from host %s!", r.Header.Get("hostname"))
	if r.Header.Get("masterkey") == "" {
		l.Printf("HTTP Header 'masterkey' missing from request")
		w.WriteHeader(http.StatusUnauthorized)
		_, err = w.Write([]byte("401 Unauthorized"))
		if err != nil {
			l.Printf("Error returning unauthorized message: %s\n", err.Error())
			return
		}
		return
	}

	if r.Host == "" {
		l.Printf("HTTP Header 'host' missing from request!")
		w.WriteHeader(http.StatusUnauthorized)
		_, err := w.Write([]byte("401 Unauthorized"))
		if err != nil {
			l.Printf("Error returning unauthorized message: %s\n", err.Error())
			return
		}
		return
	}

	if r.Header.Get("masterkey") != ConfigFile.MasterKey {
		l.Printf("Unauthorized access to upload volume data requested from host %s! (unauthorized master key)", r.Header.Get("hostname"))
		w.WriteHeader(http.StatusUnauthorized)
		_, err := w.Write([]byte("401 Unauthorized"))
		if err != nil {
			l.Printf("Error returning unauthorized message: %s\n", err.Error())
			return
		}
		return
	}

	hostnames, _, err := parseHostFile()
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if contains(hostnames, r.Header.Get("hostname")) != true {
		l.Printf("Unauthorized access to upload volume data requested from host %s! (hostname not in config file)", r.Header.Get("hostname"))
		w.WriteHeader(http.StatusUnauthorized)
		_, err := w.Write([]byte("401 Unauthorized"))
		if err != nil {
			l.Printf("Error returning unauthorized message: %s\n", err.Error())
			return
		}
		return
	}

	fileSize, err := strconv.Atoi(r.Header.Get("filesize"))
	if err != nil {
		l.Printf("Error getting volume size from request header: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	fileSizeInt, err := strconv.Atoi(r.Header.Get("filesize"))
	if err != nil {
		l.Printf("Error converting file size string to integer: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if fileSizeInt > 3*GiB {
		fi, err := os.OpenFile(ConfigFile.BackupLocation+r.Header.Get("filename")+"_"+r.Header.Get("hash")+".qcow2.gz", os.O_CREATE|os.O_WRONLY, 0644)
		defer fi.Close()
		if err != nil {
			l.Printf("Error creating file %s%s_%s.qcow2.gz: %s\n", ConfigFile.BackupLocation, r.Header.Get("filename"), r.Header.Get("hash"), err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		rb := progress.NewReader(r.Body)
		ctx := context.Background()
		var finishedWriting = make(chan bool)
		var p = progress.Progress{}
		go func(finished chan bool) {
			progressChan := progress.NewTicker(ctx, rb, int64(fileSize), 5*time.Second)
			var timeCompleted int64
			var lastRound int64
			for p = range progressChan {
				timeCompleted = timeCompleted + 5
				lastRound = p.N() - lastRound
				//l.Printf("%v remaining...", p.Remaining().Round(time.Second))
				l.Printf("%.2f%% complete - %.3f GiB written - (%dMiB/s)", p.Percent(), float64(p.N())/GiB, lastRound/timeCompleted/MiB)
			}
			l.Printf("Wrote %.3f GiB to %s at an average speed of %d MiB/s", float64(p.N())/GiB, ConfigFile.BackupLocation+r.Header.Get("filename")+r.Header.Get("hash")+".qcow2.gz", p.N()/timeCompleted/MiB)
			finished <- true
			return
		}(finishedWriting)

		l.Printf("Copying data...")

		_, err = io.Copy(fi, rb)
		if err != nil {
			l.Printf("Error copying to file from write buffer: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		err = fi.Sync()
		if err != nil {
			l.Printf("Error syncing buffer to file: %s\n", err.Error())
			return
		}

		<-finishedWriting
	} else if fileSizeInt < 3*GiB {
		fi, err := os.OpenFile(ConfigFile.BackupLocation+r.Header.Get("filename")+"_"+r.Header.Get("hash")+".qcow2.gz", os.O_CREATE|os.O_WRONLY, 0644)
		defer fi.Close()
		if err != nil {
			l.Printf("Error creating file %s%s_%s.qcow2.gz: %s\n", ConfigFile.BackupLocation, r.Header.Get("filename"), r.Header.Get("hash"), err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		l.Println("Omitting transfer rate: Volume is less than 3GiB (probably 0), so transfer tracking may hang the application and return inaccurate results.")
		l.Println("Copying data...")
		_, err = io.Copy(fi, r.Body)
		if err != nil {
			l.Printf("Error copying to file from write buffer: %s\n", err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		r.Body.Close()
		l.Printf("Done copying data to %s\n", ConfigFile.BackupLocation+r.Header.Get("filename")+r.Header.Get("hash")+".qcow2.gz")
		l.Println("Syncing buffer to retain data integrity...")
		err = fi.Sync()
		if err != nil {
			l.Printf("Error syncing buffer to file: %s\n", err.Error())
			return
		}
		l.Println("Done syncing buffer.")
		err = fi.Close()
		if err != nil {
			l.Printf("Error closing output file: %s\n", err.Error())
			return
		}
	}

	l.Printf("Successfully gzipped & wrote %s to %s", r.Header.Get("filename"), ConfigFile.BackupLocation+r.Header.Get("filename")+"_"+r.Header.Get("hash")+".qcow2.gz")

	token := GenerateSecureToken(24)
	_, err = db.Exec("INSERT INTO images (path, name, token, tus_hash) VALUES (?, ?, ?, ?)", ConfigFile.BackupLocation+r.Header.Get("filename")+"_"+r.Header.Get("hash")+".qcow2.gz", r.Header.Get("filename"), token, r.Header.Get("hash"))
	if err != nil {
		l.Printf("Error inserting image info into MySQL: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("generated_url", "https://api.gammabyte.xyz/volume?hash="+r.Header.Get("hash")+"&token="+token)
	w.WriteHeader(http.StatusOK)
}

func downloadVolumeBackup(w http.ResponseWriter, r *http.Request) {
	http.DefaultTransport = gzhttp.Transport(http.DefaultTransport)
	u, err := url.Parse(r.URL.String())
	if err != nil {
		l.Printf("Error parsing request URL: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if u.Query().Get("token") == "" {
		l.Printf("Missing token in volume download request.")
		w.WriteHeader(http.StatusUnauthorized)
		_, err := w.Write([]byte("401 Unauthorized"))
		if err != nil {
			l.Printf("Error returning unauthorized message: %s\n", err.Error())
			return
		}
		return
	}
	if u.Query().Get("hash") == "" {
		l.Printf("Missing hash in volume download request.")
		w.WriteHeader(http.StatusUnauthorized)
		_, err := w.Write([]byte("401 Unauthorized"))
		if err != nil {
			l.Printf("Error returning unauthorized message: %s\n", err.Error())
			return
		}
		return
	}

	var token string
	var volPath string
	var volName string

	err = db.QueryRow("SELECT path, name, token FROM images WHERE tus_hash = ?", u.Query().Get("hash")).Scan(&volPath, &volName, &token)
	l.Printf("Got request to download image %s!\n", volName)
	if err != nil {
		l.Printf("Error querying DB: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if u.Query().Get("token") != token {
		l.Printf("Unauthorized access to volume %s requested!", volPath)
		w.WriteHeader(http.StatusUnauthorized)
		_, err := w.Write([]byte("401 Unauthorized"))
		if err != nil {
			l.Printf("Error returning unauthorized message: %s\n", err.Error())
			return
		}
		return
	}

	f, err := os.Open(volPath)
	if err != nil {
		l.Printf("Error opening volume: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, err := w.Write([]byte("500 Internal Server Error"))
		if err != nil {
			l.Printf("Error returning error message to client: %s\n", err.Error())
			return
		}
		return
	}

	buf := bytes.NewBuffer(make([]byte, 1024000))
	buf2 := bytes.NewBuffer(make([]byte, 1024000))
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		_, err = io.CopyBuffer(pw, f, buf.Bytes())
		if err != nil {
			l.Printf("Error writing volume to copy buffer: %s\n", err.Error())
			return
		}
	}()

	w.Header().Set("Content-Disposition", "attachment; filename="+volName+".qcow2.gz")
	w.Header().Set("filename", volName+".qcow2.gz")

	_, err = io.CopyBuffer(w, pr, buf2.Bytes())
	if err != nil {
		if err.Error() == "http2: stream closed" {
			l.Printf("Warning: Client closed remote HTTP session.")
			defer pr.Close()
			defer buf.Reset()
			defer buf2.Reset()
			return
		}
		l.Printf("Error writing response: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, err := w.Write([]byte("500 Internal Server Error"))
		if err != nil {
			l.Printf("Error returning error message to client: %s\n", err.Error())
			defer pr.Close()
			defer buf.Reset()
			defer buf2.Reset()
			return
		}
		defer pr.Close()
		defer buf.Reset()
		defer buf2.Reset()
		return
	}
	pr.Close()
	buf.Reset()
	buf2.Reset()
}

func downloadVolumes(w http.ResponseWriter, r *http.Request) {
	http.DefaultTransport = gzhttp.Transport(http.DefaultTransport)
	l.Println("Got request!")
	u, err := url.Parse(r.URL.String())
	if err != nil {
		l.Printf("Error parsing URL: %s\n", err.Error())
		return
	}
	queries := u.Query()
	tokenQuery := queries.Get("token")
	hashQuery := queries.Get("hash")
	l.Printf(hashQuery)

	var token string
	var volName string

	if tokenQuery == "" {
		http.Error(w, "Error: Unauthorized - Missing Token", http.StatusUnauthorized)
		return
	}
	if hashQuery == "" {
		http.Error(w, "Error: Unauthorized - Missing Hash", http.StatusUnauthorized)
		return
	}
	err = db.QueryRow("SELECT name, token FROM images WHERE tus_hash = ?", hashQuery).Scan(&volName, &token)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		return
	}

	if tokenQuery != token {
		http.Error(w, "Error: Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+volName+".qcow2.gz")
	http.ServeFile(w, r, ConfigFile.BackupLocation+hashQuery)
	return
}

func startTusServer() (error, string) {
	// Create a new FileStore instance which is responsible for
	// storing the uploaded file on disk in the specified directory.
	// This path _must_ exist before tusd will store uploads in it.
	// If you want to save them on a different medium, for example
	// a remote FTP server, you can implement your own storage backend
	// by implementing the tusd.DataStore interface.
	store := filestore.FileStore{
		Path: ConfigFile.BackupLocation,
	}

	// A storage backend for tusd may consist of multiple different parts which
	// handle upload creation, locking, termination and so on. The composer is a
	// place where all those separated pieces are joined together. In this example
	// we only use the file store but you may plug in multiple.
	composer := tusd.NewStoreComposer()
	store.UseIn(composer)

	// Create a new HTTP handler for the tusd server by providing a configuration.
	// The StoreComposer property must be set to allow the handler to function.
	handler, err := tusd.NewHandler(
		tusd.Config{
			StoreComposer:           composer,
			BasePath:                "/upload/",
			NotifyCompleteUploads:   true,
			NotifyUploadProgress:    true,
			Logger:                  l,
			RespectForwardedHeaders: true,
			PreUploadCreateCallback: func(hook tusd.HookEvent) error {
				hook.Upload.MetaData["filename"] = hook.HTTPRequest.Header.Get("Filename")
				hook.Upload.MetaData["filename"] = hook.HTTPRequest.Header.Get("filename")
				return nil
			},
			PreFinishResponseCallback: func(hook tusd.HookEvent) error {
				hook.Upload.MetaData["filename"] = hook.HTTPRequest.Header.Get("Filename")
				hook.Upload.MetaData["filename"] = hook.HTTPRequest.Header.Get("filename")
				return nil
			},
		},
	)
	if err != nil {
		l.Printf("Error creating tusd handler: %s\n", err.Error())
		return err, ""
	}

	// Start another goroutine for receiving events from the handler whenever
	// an upload is completed. The event will contains details about the upload
	// itself and the relevant HTTP request.
	go func() {
		for {
			event := <-handler.CompleteUploads
			l.Printf("Upload %s finished\n", event.Upload.ID)
			l.Printf("Total Size: %d bytes\n", event.Upload.Size)
			l.Printf("File Name: %s\n", event.Upload.MetaData["filename"])
			token := GenerateSecureToken(24)
			_, err = db.Exec("INSERT INTO images (path, name, token, tus_hash) VALUES (?, ?, ?, ?)", ConfigFile.BackupLocation+event.Upload.ID, event.Upload.MetaData["filename"], token, event.Upload.ID)
			if err != nil {
				l.Printf("Error: %s\n", err.Error())
				return
			}
		}
	}()

	// Right now, nothing has happened since we need to start the HTTP server on
	// our own. In the end, tusd will start listening on and accept request at
	// https://localhost:8080/files
	l.Println("Listening for TUS connections on 0.0.0.0:8741.")
	http.Handle("/upload/", http.StripPrefix("/upload/", handler))
	//netListener, err := net.Listen("tcp", "0.0.0.0:8741")
	//err = http.ServeTLS(netListener, handler, "/etc/ssl/certs/lsapi.crt", "/etc/ssl/keys/lsapi.key")
	http.ListenAndServeTLS("0.0.0.0:8741", "/etc/gammabyte/lsapi/lb.crt", "/etc/gammabyte/lsapi/lb.key", nil)
	if err != nil {
		l.Printf("TUS is unable to listen on port 8741 due to error: %s\n", err.Error())
		return err, ""
	}
	hostname, err := fqdn.FqdnHostname()
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		return err, ""
	}
	return nil, "https://" + hostname + ":8741/upload"
}

func contains(s []string, searchterm string) bool {
	i := sort.SearchStrings(s, searchterm)
	return i < len(s) && s[i] == searchterm
}
