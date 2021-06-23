package main

import (
	"crypto/x509"
	"encoding/json"
	"github.com/Showmax/go-fqdn"
	"github.com/machinebox/progress"
	"github.com/svenwiltink/sparsecat"
	"golang.org/x/net/context"
	"gopkg.in/yaml.v3"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

var (
	l               = log.New(writeLog, "[LibStatsAPI-SAN] ", log.Ldate|log.Ltime|log.LUTC|log.Lmsgprefix|log.Lmicroseconds|log.LstdFlags|log.Llongfile|log.Lshortfile)
	remoteSyslog, _ = syslog.Dial("udp", "localhost:514", syslog.LOG_DEBUG, "[LibStatsAPI-SAN]")
	logFile, _      = os.OpenFile("/var/log/lsapi.log", os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	writeLog        = io.MultiWriter(os.Stdout, logFile, remoteSyslog)
	ConfigFile      = configFile{}
	SparseReq       = sparsecatVolume{}
	rootCAs, _      = x509.SystemCertPool()
)

const (
	GiB = 1073741823
	MiB = 1048576
)

func main() {
	// Check to see if config file exists
	if fileExists("/etc/gammabyte/lsapi/config-storage.yml") {
		l.Println("Config file found.")
	} else {
		l.Println("Config file '/etc/gammabyte/lsapi/config-storage.yml' not found!")
		panic("Config file not found.")
	}

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ = x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	hostname, err := fqdn.FqdnHostname()
	if err != nil {
		l.Printf("Error getting hostname: %s\n", err.Error())
		panic(err.Error())
	}

	// Read in the cert file
	certs, err := ioutil.ReadFile("/etc/pki/tls/certs/" + hostname + ".crt")
	if err != nil {
		l.Printf("Failed to append %q to RootCAs: %v", "/etc/pki/tls/certs/"+hostname+".crt", err.Error())
		panic(err.Error())
	}

	// Append our cert to the system pool
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		l.Println("No certs appended, using system certs only")
	}

	certs, err = ioutil.ReadFile("/etc/pki/ca-trust/source/anchors/master.crt")
	if err != nil {
		l.Printf("Error reading master cert: %s\n", err.Error())
		panic(err.Error())
	}
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		l.Println("Did not append master cert.")
	}

	filename, err := filepath.Abs("/etc/gammabyte/lsapi/config-storage.yml")
	if err != nil {
		l.Printf("Error getting absolute path for config file: %s\n", err.Error())
		panic(err.Error())
	}
	yamlConfig, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err.Error())
	}
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)
	if err != nil {
		l.Printf("Error parsing YAML config: %s\n", err.Error())
		panic(err.Error())
	}
	if ConfigFile.SyslogAddress != "" {
		remoteSyslog, _ = syslog.Dial("udp", ConfigFile.SyslogAddress+":"+ConfigFile.SyslogPort, syslog.LOG_DEBUG, "[LibStatsAPI-SAN]")
	}

	if ConfigFile.MasterKey == "" {
		panic("Missing master key in config")
	} else if ConfigFile.SqlAddress == "" {
		panic("Missing MySQL address in config")
	} else if ConfigFile.SqlUser == "" {
		panic("Missing MySQL user in config")
	} else if ConfigFile.SqlPassword == "" {
		panic("Missing MySQL password in config")
	} else if ConfigFile.VolumePath == "" {
		panic("Missing volume path in config")
	} else if ConfigFile.MasterIP == "" {
		panic("Missing master IP in config")
	} else if ConfigFile.MasterPort == "" {
		panic("Missing master API port in config")
	} else if ConfigFile.AuthServer == "" {
		panic("Missing authentication server in config")
	}

	handleRequests(hostname)
}

func handleRequests(hostname string) {
	http.HandleFunc("/api/san/volume/sparsify", sparsifyVolume)
	l.Fatal(http.ListenAndServeTLS("0.0.0.0:8941", "/etc/pki/tls/certs/"+hostname+".crt", "/etc/pki/tls/private/"+hostname+".key", nil))
}

func sparsifyVolume(w http.ResponseWriter, r *http.Request) {
	l.Printf("Got request from %s to sparsify volume\n", r.RemoteAddr)
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&SparseReq)
	if err != nil {
		l.Printf("Error decoding JSON: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte("500 Internal Server Error: " + err.Error()))
		if err != nil {
			l.Printf("Error writing error response to client: %s\n", err.Error())
			return
		}
		return
	}
	if SparseReq.MasterKey != ConfigFile.MasterKey {
		l.Printf("Unauthorized access from host %s requested!", r.Host)
		w.WriteHeader(http.StatusUnauthorized)
		_, err = w.Write([]byte("401 Unauthorized: Incorrect authorization key!"))
		if err != nil {
			l.Printf("Error writing unauthorized response to client: %s\n", err.Error())
			return
		}
		return
	}

	f, err := os.Open(ConfigFile.VolumePath + SparseReq.VolumeName)
	if err != nil {
		l.Printf("Error opening volume: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte("500 Internal Server Error: " + err.Error()))
		if err != nil {
			l.Printf("Error writing error response to client: %s\n", err.Error())
			return
		}
	}

	l.Printf("Reading large volume...")
	fileStat := syscall.Stat_t{}
	err = syscall.Stat(ConfigFile.VolumePath+SparseReq.VolumeName, &fileStat)
	fileSize := fileStat.Blocks * 512
	if fileSize*int64(GiB) <= 1 {
		l.Printf("Not sparsifying a volume less than 1GiB, as this may lead to an EOF error (volume possibly empty?).")
		w.WriteHeader(http.StatusNotAcceptable)
		_, err = w.Write([]byte("Error 406 - data too small."))
		if err != nil {
			l.Printf("Error writing volume too small response to client: %s\n", err.Error())
			return
		}
		return
	}
	if err != nil {
		l.Printf("Error getting sparse size of volume: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte("500 Internal Server Error: " + err.Error()))
		if err != nil {
			l.Printf("Error writing error response to client: %s\n", err.Error())
			return
		}
		return
	}
	sparseReader, err := sparsecat.NewSparseReader(f)
	if err != nil {
		l.Printf("Error generating sparse stream of data from volume: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte("500 Internal Server Error: " + err.Error()))
		if err != nil {
			l.Printf("Error writing error response to client: %s\n", err.Error())
			return
		}
		return
	}
	l.Printf("Creating sparse volume...")
	newSparseVolume, err := os.OpenFile(ConfigFile.VolumePath+SparseReq.VolumeName+"-SPARSE", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
	if err != nil {
		l.Printf("Error creating new sparse volume to be written to: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte("500 Internal Server Error: " + err.Error()))
		if err != nil {
			l.Printf("Error writing error response to client: %s\n", err.Error())
			return
		}
		return
	}
	rd := progress.NewReader(sparseReader)
	ctx := context.Background()
	var p progress.Progress
	var finishedWriting = make(chan bool)
	go func(finished chan bool) {
		progressChan := progress.NewTicker(ctx, rd, fileSize, 5*time.Second)
		var timeCompleted int64
		var lastRound int64
		for p = range progressChan {
			timeCompleted = timeCompleted + 5
			lastRound = p.N() - lastRound
			//l.Printf("%v remaining...", p.Remaining().Round(time.Second))
			l.Printf("%.2f%% complete - %.3f GiB written - (%dMiB/s)", p.Percent(), float64(p.N())/GiB, lastRound/timeCompleted/MiB)
		}
		l.Printf("Wrote %.3f GiB to %s at an average speed of %d MiB/s", float64(p.N())/GiB, ConfigFile.VolumePath+SparseReq.VolumeName+"-SPARSE", p.N()/timeCompleted/MiB)
		finished <- true
	}(finishedWriting)
	err = sparsecat.ReceiveSparseFile(newSparseVolume, rd)
	if err != nil {
		l.Printf("Error creating sparse volume: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte("500 Internal Server Error: " + err.Error()))
		if err != nil {
			l.Printf("Error writing error response to client: %s\n", err.Error())
			return
		}
		r.Body.Close()
		f.Close()
		os.Remove(ConfigFile.VolumePath + SparseReq.VolumeName + "-SPARSE")
		os.Remove(ConfigFile.VolumePath + SparseReq.VolumeName)
		return
	}

	<-finishedWriting

	f.Close()
	err = secureDelete(ConfigFile.VolumePath + SparseReq.VolumeName)
	if err != nil {
		l.Printf("Error securely deleting volume: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, err = w.Write([]byte("500 Internal Server Error: " + err.Error()))
		if err != nil {
			l.Printf("Error writing error response to client: %s\n", err.Error())
			return
		}
		return
	}
	w.Header().Set("sparseSize", strconv.Itoa(int(p.N())))
	w.WriteHeader(http.StatusOK)
}

func secureDelete(source string) error {
	fi, err := os.OpenFile(source, os.O_TRUNC|os.O_RDWR, 0644)
	if err != nil {
		l.Printf("Error opening file for secure deletion: %s\n", err.Error())
		l.Printf("Attempting to recover by using os.Remove()...")
		err = os.Remove(source)
		if err != nil {
			l.Printf("Error falling back to os.Remove(): %s\n", err.Error())
			return err
		} else {
			l.Printf("Fallback deletion succeeded.")
		}
		return err
	}
	var statStruct syscall.Stat_t
	err = syscall.Stat(source, &statStruct)
	if err != nil {
		l.Printf("Error getting volume info for secure deletion: %s\n", err.Error())
		l.Printf("Attempting to recover by using os.Remove()...")
		err = os.Remove(source)
		if err != nil {
			l.Printf("Error falling back to os.Remove() due to failed deletion: %s\n", err.Error())
			return err
		}
		return err
	}
	l.Printf("Securely wiping volume %s...", source)

	const fileChunk = 12 * (1 << 20)
	fileSize := statStruct.Blocks * 512
	totalPartsNum := uint64(math.Ceil(float64(fileSize) / float64(fileChunk)))
	lastPosition := 0

	var done25 bool
	var done50 bool
	var done75 bool
	var done100 bool

	for i := uint64(0); i < totalPartsNum; i++ {

		partSize := int(math.Min(fileChunk, float64(fileSize-int64(i*fileChunk))))
		partZeroBytes := make([]byte, partSize)

		// fill out the part with zero value
		copy(partZeroBytes[:], "0")

		// over write every byte in the chunk with 0
		_, err = fi.WriteAt(partZeroBytes, int64(lastPosition))
		if err != nil {
			l.Printf("Error writing secure bytes to file: %s\n", err.Error())
			l.Printf("Attempting to recover by using os.Remove()...")
			err = os.Remove(source)
			if err != nil {
				l.Printf("Error falling back to os.Remove(): %s\n", err.Error())
				return err
			}
			return err
		}
		// update last written position
		lastPosition = lastPosition + partSize
		if lastPosition >= int(fileSize)/4 && done25 == false {
			l.Println(" -> 25% complete...")
			done25 = true
		} else if lastPosition >= int(fileSize)/2 && done50 == false {
			l.Println(" -> 50% complete...")
			done50 = true
		} else if lastPosition >= (int(fileSize)/4)*3 && done75 == false {
			l.Println(" -> 75% complete...")
			done75 = true
		} else if lastPosition >= int(fileSize) && done100 == false {
			l.Println(" -> 100% complete!")
			done100 = true
		}
	}

	l.Printf("Wiped %v GiB from %s\n", lastPosition/GiB, source)
	l.Printf("Wiped %v Bytes from %s\n", lastPosition, source)
	fi.Close()
	return err
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
