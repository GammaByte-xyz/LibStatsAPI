package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/Showmax/go-fqdn"
	"github.com/Terry-Mao/goconf"
	"github.com/TwinProduction/go-color"
	_ "github.com/go-sql-driver/mysql"
	"github.com/klauspost/compress/gzhttp"
	"golang.org/x/net/context"
	"gopkg.in/yaml.v3"
	"io"
	ioutil "io/ioutil"
	"log"
	"log/syslog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Set global variables
var (
	remoteSyslog, _ = syslog.Dial("udp", "localhost:514", syslog.LOG_DEBUG, "[LibStatsAPI-ALB]")
	logFile, _      = os.OpenFile("/var/log/lsapi.log", os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	writeLog        = io.MultiWriter(os.Stdout, logFile, remoteSyslog)
	l               = log.New(writeLog, "[LibStatsAPI-ALB] ", log.Ldate|log.Ltime|log.LUTC|log.Lmsgprefix|log.Lmicroseconds|log.LstdFlags|log.Llongfile|log.Lshortfile)
	db              *sql.DB
	filename        string
	yamlConfig      []byte
	err             error
	ConfigFile      configFile
	rootCAs, _      = x509.SystemCertPool()
)

func getSyslogServer() string {
	filename, _ = filepath.Abs("/etc/gammabyte/lsapi/config-lb.yml")
	yamlConfig, err = ioutil.ReadFile(filename)
	if err != nil {
		l.Fatalf("Error: %s\n", err.Error())
		return "localhost:514"
	}
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	return ConfigFile.SyslogAddress
}

func handleRequests(hostname string) {
	http.HandleFunc("/api/auth", proxyRequestsAuth)
	http.HandleFunc("/api/kvm", proxyRequestsKvm)
	http.HandleFunc("/api/vnc", vncProxy)
	http.HandleFunc("/api/data", handleData)
	http.HandleFunc("/api/image", handleImages)
	http.HandleFunc("/image", serveImages)
	http.HandleFunc("/volume", downloadVolumeBackup)
	http.HandleFunc("/api/tls/getcert", sendCert)
	http.HandleFunc("/files/prepare/volume", prepareVolume)

	listenAddr := fmt.Sprintf("%s:%s", ConfigFile.ListenAddress, ConfigFile.ListenPort)

	// Listen on specified port
	l.Fatal(http.ListenAndServeTLS(listenAddr, "/etc/pki/ca-trust/source/anchors/"+hostname+".crt", "/etc/pki/tls/private/"+hostname+".key", nil))
}

func handleFileServer(hostname string) {
	http.HandleFunc("/files/upload/volume", recieveVolumeUpload)
	l.Fatal(http.ListenAndServeTLS("0.0.0.0:4224", "/etc/pki/ca-trust/source/anchors/"+hostname+".crt", "/etc/pki/tls/private/"+hostname+".key", nil))
}

func setup() {
	configTemplate := `##############################################
# EDIT THIS BEFORE STARTING THE LOADBALANCER #
##############################################

listen_port: "8082"
listen_address: "0.0.0.0"

###### CHANGE THESE ######
sql_password: "yourSqlPassword"
sql_user: "yourSqlUser"
##########################

sql_address: "localhost"
syslog_server: "yoursyslog.server.tld:514"
auth_server: "localhost:8083"


# Setting this to true will prevent this host from proxying requests to internal nodes.
lock_node: false
`
	hostConfigTemplate := `# Add a host here with the FQDN (Must be resolvable)
[fqdn.of.yourhost.tld]
addr 1.2.3.4
hostname fqdn.of.yourhost.tld
`
	if _, err := os.Stat("/etc/gammabyte"); os.IsNotExist(err) {
		os.Mkdir("/etc/gammabyte", 0644)
		os.Mkdir("/etc/gammabyte/lsapi", 0644)
		os.Mkdir("/etc/gammabyte/lsapi/vnc", 0644)
		ioutil.WriteFile("/etc/gammabyte/lsapi/vnc/vnc.conf", []byte(nil), 0644)
		ioutil.WriteFile("/etc/gammabyte/lsapi/config-lb.yml", []byte(configTemplate), 0644)
		ioutil.WriteFile("/etc/gammabyte/lsapi/hosts.conf", []byte(hostConfigTemplate), 0644)
		l.Fatal(color.Colorize(color.Red, color.Ize(color.Bold, "Error: Please configure the load balancer in '/etc/gammabyte/lsapi/config-lb.yml' and create a list of hosts in '/etc/gammabyte/lsapi/hosts.conf'.")))
	}
}

func main() {

	wordPtr := flag.Bool("gencert", false, "Generate a CA (certificate authority) and client server certificates.")
	flag.Parse()

	if *wordPtr == true {
		scanner := bufio.NewScanner(os.Stdin)
		fmt.Print("CA Cert [true | false]: ")
		scanner.Scan()
		isCertificateAuthority := scanner.Text()
		var isCa bool
		if isCertificateAuthority == "true" {
			isCa = true
		} else if isCertificateAuthority == "false" {
			isCa = false
		}
		fmt.Print("Certificate Path [ex. /root/master.crt]: ")
		scanner.Scan()
		certPath := scanner.Text()
		fmt.Print("Key Path [ex. /root/master.key]: ")
		scanner.Scan()
		keyPath := scanner.Text()
		fmt.Print("Organization [ex. Google.com]: ")
		scanner.Scan()
		certOrg := scanner.Text()
		fmt.Print("Country Code [ex. USA]: ")
		scanner.Scan()
		countryCode := scanner.Text()
		fmt.Print("Province/State [ex. California]: ")
		scanner.Scan()
		province := scanner.Text()
		fmt.Print("Locality [ex. Los Angeles]: ")
		scanner.Scan()
		locality := scanner.Text()
		fmt.Print("FQDN [ex. server.mydomain.com]: ")
		scanner.Scan()
		fullyQDN := scanner.Text()
		fmt.Print("Organizational Unit [ex. Information Technology]: ")
		scanner.Scan()
		orgUnit := scanner.Text()
		fmt.Print("Street Address [ex. 8234 Street NE]: ")
		scanner.Scan()
		streetAddress := scanner.Text()
		fmt.Print("ZIP/Postal Code [ex. 90001]: ")
		scanner.Scan()
		zipCode := scanner.Text()
		fmt.Print("IP Address [ex. 192.168.33.200]: ")
		scanner.Scan()
		ipAddress := scanner.Text()
		genCert(certPath, keyPath, certOrg, countryCode, province, locality, zipCode, isCa, fullyQDN, orgUnit, streetAddress, ipAddress)
		os.Exit(1)
	}

	setup()

	// Check to see if config file exists
	if fileExists("/etc/gammabyte/lsapi/config-lb.yml") {
		l.Println("Config file found.")
	} else {
		l.Println("Config file '/etc/gammabyte/lsapi/config-lb.yml' not found!")
		panic("Config file not found.")
	}

	// Get the SystemCertPool, continue with an empty pool on error
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	// Get hostname
	hostname, err := fqdn.FqdnHostname()
	if err != nil {
		l.Printf("Error getting hostname: %s\n", err.Error())
		panic(err.Error())
	}
	// Read in the cert file
	certs, err := ioutil.ReadFile("/etc/pki/ca-trust/source/anchors/" + hostname + ".crt")
	if err != nil {
		l.Fatalf("Failed to append %q to RootCAs: %v", "/etc/pki/ca-trust/source/anchors/"+hostname+".crt", err.Error())
	}

	// Append our cert to the system pool
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		l.Println("No certs appended, using system certs only")
	}

	// Parse the config file
	filename, err = filepath.Abs("/etc/gammabyte/lsapi/config-lb.yml")
	if err != nil {
		l.Fatalf("Error: %s\n", err.Error())
	}
	yamlConfig, err = ioutil.ReadFile(filename)
	if err != nil {
		panic(err.Error())
	}
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)
	if err != nil {
		l.Fatalf("Error: %s\n", err.Error())
	}
	if ConfigFile.LockNode != "false" {
		l.Fatal(color.Colorize(color.Red, color.Ize(color.Bold, "Error: 'lock_node' must be set to 'false' in '/etc/gammabyte/lsapi/config-lb.yml' for application to run.")))
	}

	ctx, cancelfunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelfunc()

	remoteSyslog, _ = syslog.Dial("udp", getSyslogServer(), syslog.LOG_INFO, "")
	logFile, err = os.OpenFile("/var/log/lsapi.log", os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		l.Fatalf("Error: %s\n", err.Error())
	}
	writeLog = io.MultiWriter(os.Stdout, logFile, remoteSyslog)
	l = log.New(writeLog, "[LibStatsAPI-ALB] ", log.Ldate|log.Ltime|log.LUTC|log.Lmsgprefix|log.Lmicroseconds|log.LstdFlags|log.Llongfile|log.Lshortfile)

	// Connect to MariaDB
	dbConnectString := fmt.Sprintf("%s:%s@tcp(%s:3306)/", ConfigFile.SqlUser, ConfigFile.SqlPassword, ConfigFile.SqlAddress)
	db, err = sql.Open("mysql", dbConnectString)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		panic(err.Error())
	}

	res, err := db.Exec("CREATE DATABASE IF NOT EXISTS lsapi")
	if err != nil {
		l.Printf("Error %s when creating lsapi DB\n", err.Error())
		panic(err.Error())
	}

	dbConnectString = fmt.Sprintf("%s:%s@tcp(%s:3306)/lsapi", ConfigFile.SqlUser, ConfigFile.SqlPassword, ConfigFile.SqlAddress)
	db, err = sql.Open("mysql", dbConnectString)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		panic(err.Error())
	}

	query := `CREATE TABLE IF NOT EXISTS users(username text, full_name text, user_token text, email_address text, max_vcpus int, max_ram int, max_block_storage int, used_vcpus int, used_ram int, used_block_storage int, join_date text, uuid text, password varchar(255) DEFAULT NULL)`

	res, err = db.ExecContext(ctx, query)
	if err != nil {
		l.Printf("Error %s when creating users table\n", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		l.Printf("Error %s when getting rows affected\n", err)
	}
	l.Printf("Rows affected when creating table: %d\n", rows)

	query = `CREATE TABLE IF NOT EXISTS domaininfo(domain_name text, network text, host_binding text, mac_address text, ram int, vcpus int, storage int, ip_address text, disk_path text, time_created text, user_email text, user_full_name text, username text, user_token text, disk_secret text)`

	ctx, cancelfunc = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelfunc()

	res, err = db.ExecContext(ctx, query)
	if err != nil {
		l.Printf("Error %s when creating domaininfo table\n", err)
	}

	rows, err = res.RowsAffected()
	if err != nil {
		l.Printf("Error %s when getting rows affected\n", err)
	}
	l.Printf("Rows affected when creating table: %d\n", rows)

	if err != nil {
		l.Printf("Error - could not connect to MySQL DB:\n %s\n", err.Error())
		panic(err.Error())
	}

	err = db.Ping()
	if err != nil {
		l.Printf("Error - could not connect to MySQL DB:\n %s\n", err.Error())
		panic(err.Error())
	} else {
		l.Printf("Successfully connected to MySQL DB.\n")
	}

	query = `CREATE TABLE IF NOT EXISTS hostinfo(host_ip text, geolocation text, host_ip_public text, ram_gb int, cpu_cores int, linux_distro text, kernel_version text, hostname text, api_port int, kvm_api_port int)`

	ctx, cancelfunc = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelfunc()

	res, err = db.ExecContext(ctx, query)
	if err != nil {
		l.Printf("Error %s when creating domaininfo table\n", err)
	}

	rows, err = res.RowsAffected()
	if err != nil {
		l.Printf("Error %s when getting rows affected\n", err)
	}
	l.Printf("Rows affected when creating table hostinfo: %d\n", rows)

	err = db.Ping()
	if err != nil {
		l.Printf("Error - could not connect to MySQL DB:\n %s\n", err)
		panic(err.Error())
	} else {
		l.Printf("Successfully connected to MySQL DB.\n")
	}

	hostnames, hostIPs, err := parseHostFile()
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		return
	}
	l.Printf("Hosts: %s\n", hostnames)
	l.Printf("Host IPs: %s\n", hostIPs)
	for i := range hostnames {
		l.Printf("%s\n", hostnames[i])
	}
	go startVncWebsocket()
	go handleFileServer(hostname)
	handleRequests(hostname)
}

type configFile struct {
	VolumePath      string `yaml:"volume_path"`
	ListenPort      string `yaml:"listen_port"`
	ListenAddress   string `yaml:"listen_address"`
	SqlPassword     string `yaml:"sql_password"`
	SqlAddress      string `yaml:"sql_address"`
	Manufacturer    string `yaml:"vm_manufacturer"`
	SqlUser         string `yaml:"sql_user"`
	DomainBandwidth int    `yaml:"domain_bandwidth"`
	Subnet          string `yaml:"virtual_network_subnet"`
	MasterKey       string `yaml:"master_key"`
	MasterIP        string `yaml:"master_ip"`
	MasterPort      string `yaml:"master_port"`
	SyslogAddress   string `yaml:"syslog_server"`
	AuthServer      string `yaml:"auth_server"`
	LockNode        string `yaml:"lock_node"`
	LegacyStorage   bool   `yaml:"legacy_storage"`
	StorageServer   string `yaml:"storage_server"`
	BackupLocation  string `yaml:"backup_dir"`
}

type requestProxyValue struct {
	Type       string `json:"ProxyType"`
	DomainName string `json:"DomainName"`
}

type dbValues struct {
	hostBinding string
	hostPort    string
}
type hostStatsRespBody struct {
	RamUsage  int    `json:"RamUsage,omitempty,string"`
	CpuUsage  int    `json:"CpuUsage,omitempty,string"`
	DomainCap string `json:"DomainCap"`
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func handleData(w http.ResponseWriter, r *http.Request) {
	file, handler, err := r.FormFile("file")
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
	}
	defer file.Close()

	// copy example
	f, err := os.OpenFile(handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		panic(err) //please dont
	}
	defer f.Close()
	io.Copy(f, file)
}

type imageHandler struct {
	ImagePath  string `json:"ImagePath"`
	ProxyType  string `json:"ProxyType"`
	DomainName string `json:"DomainName"`
}

func GenerateSecureToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func handleImages(w http.ResponseWriter, r *http.Request) {
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		return
	}
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	var handler = &imageHandler{}

	err := decoder.Decode(&handler)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		return
	}

	var token string
	var tusHash string

	if handler.ProxyType == "genURI" {
		err = db.QueryRow("SELECT token, tus_hash FROM images WHERE path = ?", handler.ImagePath).Scan(&token, &tusHash)
		if err != nil {
			l.Printf("Error: %s\n", err.Error())
			return
		}
		fmt.Fprintf(w, "{\"URL\": \"https://gammabyte.xyz/volume?hash=%s&token=%s\"}", tusHash, token)
		l.Printf("{\"URL\": \"https://gammabyte.xyz/volume?hash=%s&token=%s\"}", tusHash, token)
		return
	}
}

func serveImages(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.String())
	if err != nil {
		l.Printf("Error parsing request URL: %s\n", err.Error())
		return
	}
	queries := u.Query()
	l.Println("Query strings: ")
	for key, value := range queries {
		l.Printf("  %v = %v\n", key, value)
	}
	token := queries.Get("token")
	imagename := queries.Get("image")

	var name string
	var path string
	err = db.QueryRow("SELECT name, path FROM images WHERE token = ?", token).Scan(&name, &path)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		return
	}
	if name != imagename {
		fmt.Fprintf(w, "Unauthorized")
		l.Printf("Unauthorized access to %s requested", name)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename="+name+".qcow2.gz")
	http.ServeFile(w, r, path)

	l.Println("User has accessed image. Timer to remove image has started and will be purged in two days.")
	time.AfterFunc(48*time.Hour, func() {
		err := os.Remove(path)
		if err != nil {
			l.Printf("Error removing image: %s\n", err.Error())
			return
		}
		result, err := db.Exec("DELETE FROM images WHERE token = ?", token)
		if err != nil {
			l.Printf("Error removing old entry from images DB: %s\n", err.Error())
			return
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			l.Printf("Error getting rows affected: %s\n", err.Error())
			return
		}
		l.Printf("Rows affected when deleting image entry from MySQL: %d\n", rowsAffected)
	})

}

func proxyRequestsAuth(w http.ResponseWriter, r *http.Request) {
	l.Println("Proxy request made for authentication node!")
	// Set the maximum bytes able to be consumed by the API to prevent denial of service
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	r.Header.Set("Access-Control-Allow-Origin", "*.repl.co")
	w.Header().Set("Access-Control-Allow-Origin", "*.repl.co")
	r.Header.Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	r.Header.Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")

	// Same request body is being stored because after reading r.Body, it can't be read again:
	bodyBytes, _ := ioutil.ReadAll(r.Body)
	r.Body.Close()
	var reqBodyStored = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	var reqBodyStored2 = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	decoder := json.NewDecoder(reqBodyStored)
	var rpv = &requestProxyValue{}

	// Decode the struct internally
	err = decoder.Decode(&rpv)
	if err != nil {
		l.Println(err.Error())
		return
	}

	bodyBytesFiltered, malice, err := filterRequests(reqBodyStored2, rpv.Type)
	if err != nil {
		l.Printf("Error %s\n", err.Error())
		return
	}
	if malice == true {
		l.Printf("Malicious request: %t", malice)
	}

	var proxyURI string
	if rpv.Type == "createUser" {
		proxyURI = "api/auth/user/create"
	} else if rpv.Type == "getUserDomains" {
		proxyURI = "api/auth/user/vms"
	} else if rpv.Type == "authDomain" {
		proxyURI = "api/auth/vm"
	} else if rpv.Type == "userLogin" {
		proxyURI = "api/auth/login"
	} else if rpv.Type == "verifyToken" {
		proxyURI = "api/auth/login/verify"
	} else if rpv.Type == "notify" {
		proxyURI = "api/auth/notify"
	}
	l.Printf("Request made to %s!", proxyURI)

	httpUrl := fmt.Sprintf("https://%s/%s", ConfigFile.AuthServer, proxyURI)
	returnValues, err := http.Post(httpUrl, "application/json", bytes.NewReader(bodyBytesFiltered))
	if err != nil {
		fmt.Fprintf(w, "Error: %s\n", err.Error())
		returnValues.Body.Close()
		r.Body.Close()
		return
	}
	b, err := ioutil.ReadAll(returnValues.Body)
	if err != nil {
		returnValues.Body.Close()
		r.Body.Close()
		fmt.Fprintf(w, "Error: %s\n", err.Error())
		return
	}
	fmt.Fprintf(w, "%s\n", string(b))

	returnValues.Body.Close()
	reqBodyStored.Close()
	reqBodyStored2.Close()
}

func proxyRequestsKvm(w http.ResponseWriter, r *http.Request) {
	l.Println("Proxy request made for KVM node(s)!")
	// Set the maximum bytes able to be consumed by the API to prevent denial of service
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	r.Header.Set("Access-Control-Allow-Origin", "*.repl.co")
	w.Header().Set("Access-Control-Allow-Origin", "*.repl.co")
	r.Header.Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	r.Header.Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")

	// Same request body is being stored because after reading r.Body, it can't be read again:
	bodyBytes, _ := ioutil.ReadAll(r.Body)
	r.Body.Close()
	var reqBodyStored = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	var reqBodyStored2 = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	// Create decoder & define var rpv
	decoder := json.NewDecoder(reqBodyStored)
	var rpv = &requestProxyValue{}

	// Define var dbvar for use later
	var dbvar = &dbValues{}

	// Decode the struct internally
	err := decoder.Decode(&rpv)
	if err != nil {
		l.Println(err.Error())
		return
	}

	bodyBytesFiltered, malice, err := filterRequests(reqBodyStored2, rpv.Type)
	if err != nil {
		l.Printf("Error %s\n", err.Error())
		return
	}
	if malice == true {
		l.Printf("Malicious request: %t", malice)
	}

	// Retrieve the proper URI to proxy to from the "Type" JSON field
	var proxyURI string
	if rpv.Type == "kvmStats" {
		proxyURI = "api/kvm/stats"
	} else if rpv.Type == "kvmDomains" {
		proxyURI = "api/kvm/domains"
	} else if rpv.Type == "domainRamUsage" {
		proxyURI = "api/kvm/ram-usage"
	} else if rpv.Type == "createDomain" {
		proxyURI = "api/kvm/create/domain"
	} else if rpv.Type == "deleteDomain" {
		proxyURI = "api/kvm/delete/domain"
	} else if rpv.Type == "togglePower" {
		proxyURI = "api/kvm/power/toggle"
	} else {
		l.Println("Proxy type destination is not one of: [kvmStats, kvmDomains, domainRamUsage, createDomain, deleteDomain, togglePower]!")
	}
	l.Printf("Request made to %s!", proxyURI)

	var i = 0
	var hostStats []string
	var hostStatsRam []int
	if proxyURI == "api/kvm/stats" {

	}

	if proxyURI == "api/kvm/create/domain" {
		hostnames, hostIPs, err := parseHostFile()
		if err != nil {
			l.Printf("Error: %s\n", err.Error())
			return
		}
		l.Printf("Hosts: %s\n", hostnames)
		l.Printf("Host IPs: %s\n", hostIPs)
		for i = range hostnames {
			l.Printf("Checking host %s\n...", hostnames[i])
			hostURL := fmt.Sprintf("https://%s:4234/api/host/stats", hostnames[i])
			req, err := http.NewRequest("GET", hostURL, nil)
			if err != nil {
				l.Printf("Error generating client stats request: %s\n", err.Error())
				return
			}
			transport := &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:   rootCAs,
					ClientCAs: rootCAs,
				},
			}
			client := &http.Client{
				Transport: transport,
			}
			resp, err := client.Do(req)
			if err != nil {
				l.Printf("Error getting host stats: %s\n", err.Error())
				return
			}
			defer resp.Body.Close()
			decoder := json.NewDecoder(resp.Body)
			var respBody = &hostStatsRespBody{}
			err = decoder.Decode(&respBody)
			if err != nil {
				l.Println(err.Error())
				return
			}
			hostStatsJson := fmt.Sprintf(`{"Hostname": "%s", "HostRamUsage": "%d", "HostCpuUsage": "%s"}`, hostnames[i], respBody.RamUsage, respBody.CpuUsage)
			hostStats = append(hostStats, hostStatsJson)
			hostStatsRam = append(hostStatsRam, respBody.RamUsage)
		}
		i = 0
		minRamHost, err := Min(hostStatsRam)
		if err != nil {
			l.Printf("Error getting host with minimum RAM usage: %s\n", err.Error())
			r.Body.Close()
		}
		index := Search(len(hostStatsRam), func(i int) bool { return hostStatsRam[i] >= minRamHost })
		if i < len(hostStatsRam) && hostStatsRam[i] == minRamHost {
			l.Printf("Found RAM usage %dMB at slice index %d in %v\n", minRamHost, i, hostStatsRam)
		} else if i > len(hostStatsRam) && hostStatsRam[i] != minRamHost {
			l.Printf("Ram usage %dMB not found in %v\n", minRamHost, hostStatsRam)
		}
		hostChosen := hostnames[index]
		l.Printf("Host chosen: %s\n", hostChosen)

		result, err := db.Query("SELECT kvm_api_port FROM hostinfo WHERE hostname = ?", hostChosen)
		if err != nil {
			l.Printf("Error: %s\n", err.Error())
			l.Printf("Error quering DB for host port for host %s!", hostChosen)
			r.Body.Close()
			return
		}
		for result.Next() {
			result.Scan(&dbvar.hostPort)
		}
		if dbvar.hostPort == "" {
			l.Printf("Error: Host %s API has no port binding!", dbvar.hostBinding)
			r.Body.Close()
			return
		}

		httpUrl := fmt.Sprintf("https://%s:%s/%s", hostChosen, dbvar.hostPort, proxyURI)
		bodyBytesFilteredBuffered := bytes.NewBuffer(bodyBytesFiltered)
		l.Printf(string(bodyBytesFiltered))
		req, err := http.NewRequest("POST", httpUrl, bodyBytesFilteredBuffered)
		if err != nil {
			l.Printf("Error: %s\n", err.Error())
			return
		}
		transport := gzhttp.Transport(&http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:   rootCAs,
				ClientCAs: rootCAs,
			},
		})
		client := &http.Client{
			Transport: transport,
		}
		returnValues, err := client.Do(req)
		if err != nil {
			l.Printf("Error: %s\n", err.Error())
			fmt.Fprintf(w, "Error: %s\n", err.Error())
			returnValues.Body.Close()
			r.Body.Close()
			return
		}
		b, err := ioutil.ReadAll(returnValues.Body)
		if err != nil {
			returnValues.Body.Close()
			r.Body.Close()
			fmt.Fprintf(w, "Error: %s\n", err.Error())
			return
		}
		fmt.Fprintf(w, "%s\n", string(b))

		returnValues.Body.Close()
		r.Body.Close()

		return
	}

	// Get values from DB
	//queryString := fmt.Sprintf("SELECT host_binding FROM domaininfo WHERE domain_name = '%s'", rpv.DomainName)
	result, err := db.Query("SELECT host_binding FROM domaininfo WHERE domain_name = ?", rpv.DomainName)
	if err != nil {
		l.Printf("Error querying DB for host binding for VM %s!", rpv.DomainName)
		l.Printf("Error: %s\n", err.Error())
		r.Body.Close()
		return
	}
	for result.Next() {
		result.Scan(&dbvar.hostBinding)
	}
	if dbvar.hostBinding == "" {
		l.Printf("Error: Domain %s has no host binding!", rpv.DomainName)
		r.Body.Close()
		return
	}
	l.Printf("Domain %s is bound to host %s!", rpv.DomainName, dbvar.hostBinding)

	//queryString = fmt.Sprintf("SELECT kvm_api_port FROM hostinfo WHERE hostname = '%s'", dbvar.hostBinding)
	result, err = db.Query("SELECT kvm_api_port FROM hostinfo WHERE hostname = ?", dbvar.hostBinding)
	if err != nil {
		l.Printf("Error querying DB for port on host %s!", dbvar.hostBinding)
		r.Body.Close()
		return
	}
	for result.Next() {
		result.Scan(&dbvar.hostPort)
	}
	if dbvar.hostPort == "" {
		l.Printf("Error: Host %s API has no port binding!", dbvar.hostBinding)
		r.Body.Close()
		return
	}
	l.Printf("Host %s API has port binding %s!", dbvar.hostBinding, dbvar.hostPort)

	// Setup the forward proxy
	httpUrl := fmt.Sprintf("https://%s:%s/%s", dbvar.hostBinding, dbvar.hostPort, proxyURI)
	returnValues, err := http.Post(httpUrl, "application/json", bytes.NewBuffer(bodyBytesFiltered))
	if err != nil {
		r.Body.Close()
		l.Printf("Error: %s\n", err.Error())
		return
	}
	b, err := ioutil.ReadAll(returnValues.Body)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		r.Body.Close()
		return
	}
	fmt.Fprintf(w, "%s\n", string(b))
}

func proxyRequestsVnc(w http.ResponseWriter, r *http.Request) {
	l.Println("Proxy request made for VNC node(s)!")
	// Set the maximum bytes able to be consumed by the API to prevent denial of service
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	r.Header.Set("Access-Control-Allow-Origin", "*.repl.co")
	w.Header().Set("Access-Control-Allow-Origin", "*.repl.co")
	r.Header.Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	r.Header.Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")

	// Define var dbvar for use later
	var dbvar = &dbValues{}

	// Same request body is being stored because after reading r.Body, it can't be read again:
	bodyBytes, _ := ioutil.ReadAll(r.Body)
	r.Body.Close()
	var reqBodyStored = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
	var reqBodyStored2 = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

	decoder := json.NewDecoder(reqBodyStored)
	var rpv = &requestProxyValue{}

	// Decode the struct internally
	err = decoder.Decode(&rpv)
	if err != nil {
		l.Println(err.Error())
		return
	}

	bodyBytesFiltered, malice, err := filterRequests(reqBodyStored2, rpv.Type)
	if err != nil {
		l.Printf("Error %s\n", err.Error())
		return
	}
	if malice == true {
		l.Printf("Malicious request: %t", malice)
	}

	var proxyURI string
	if rpv.Type == "createVncProxy" {
		proxyURI = "api/vnc/proxy/create"
	}
	l.Printf("Request made to %s!", proxyURI)

	result, err := db.Query("SELECT host_binding FROM domaininfo WHERE domain_name = ?", rpv.DomainName)
	if err != nil {
		l.Printf("Error querying DB for host binding for VM %s!", rpv.DomainName)
		l.Printf("Error: %s\n", err.Error())
		r.Body.Close()
		return
	}
	for result.Next() {
		result.Scan(&dbvar.hostBinding)
	}
	if dbvar.hostBinding == "" {
		l.Printf("Error: Domain %s has no host binding!", rpv.DomainName)
		r.Body.Close()
		return
	}
	l.Printf("Domain %s is bound to host %s!", rpv.DomainName, dbvar.hostBinding)

	//queryString = fmt.Sprintf("SELECT kvm_api_port FROM hostinfo WHERE hostname = '%s'", dbvar.hostBinding)
	result, err = db.Query("SELECT kvm_api_port FROM hostinfo WHERE hostname = ?", dbvar.hostBinding)
	if err != nil {
		l.Printf("Error querying DB for port on host %s!", dbvar.hostBinding)
		r.Body.Close()
		return
	}
	for result.Next() {
		result.Scan(&dbvar.hostPort)
	}
	if dbvar.hostPort == "" {
		l.Printf("Error: Host %s API has no port binding!", dbvar.hostBinding)
		r.Body.Close()
		return
	}
	l.Printf("Host %s API has port binding %s!", dbvar.hostBinding, dbvar.hostPort)

	httpUrl := fmt.Sprintf("https://%s:%s/%s", dbvar.hostBinding, dbvar.hostPort, proxyURI)
	returnValues, err := http.Post(httpUrl, "application/json", bytes.NewReader(bodyBytesFiltered))
	if err != nil {
		fmt.Fprintf(w, "Error: %s\n", err.Error())
		returnValues.Body.Close()
		r.Body.Close()
		return
	}
	b, err := ioutil.ReadAll(returnValues.Body)
	if err != nil {
		returnValues.Body.Close()
		r.Body.Close()
		fmt.Fprintf(w, "Error: %s\n", err.Error())
		return
	}
	fmt.Fprintf(w, "%s\n", string(b))

	returnValues.Body.Close()
	reqBodyStored.Close()
	reqBodyStored2.Close()
}

type hostConfig struct {
	Hostname string `goconf:":hostname"`
	Address  string `goconf:":address"`
}

func parseHostFile() ([]string, []string, error) {
	conf := goconf.New()
	if err := conf.Parse("/etc/gammabyte/lsapi/hosts.conf"); err != nil {
		l.Println(err.Error())
		return nil, nil, err
	}

	tf := &hostConfig{}
	if err := conf.Unmarshal(tf); err != nil {
		l.Println(err.Error())
		return nil, nil, err
	}

	var hostnames []string
	var hostIPs []string
	var i = 0
	sections := conf.Sections()
	for i = range conf.Sections() {
		sect := conf.Get(sections[i])

		hostname, err := sect.String("hostname")
		if err != nil {
			l.Println(err)
			return nil, nil, err
		}

		addr, err := sect.String("addr")
		if err != nil {
			l.Println(err)
			return nil, nil, err
		}
		hostnames = append(hostnames, hostname)
		hostIPs = append(hostIPs, addr)
	}
	l.Printf("Number of hosts: %d\n", len(hostnames))
	return hostnames, hostIPs, nil
}

func Min(values []int) (min int, e error) {
	if len(values) == 0 {
		return 0, errors.New("Cannot detect a minimum value in an empty slice")
	}

	min = values[0]
	for _, v := range values {
		if v < min {
			min = v
		}
	}

	return min, nil
}

func Search(n int, f func(int) bool) int {
	// Define f(-1) == false and f(n) == true.
	// Invariant: f(i-1) == false, f(j) == true.
	i, j := 0, n
	for i < j {
		h := i + (j-i)/2 // avoid overflow when computing h
		// i ≤ h < j
		if !f(h) {
			i = h + 1 // preserves f(i-1) == false
		} else {
			j = h // preserves f(j) == true
		}
	}
	// i == j, f(i-1) == false, and f(j) (= f(i)) == true  =>  answer is i.
	return i
}

func filterRequests(r io.Reader, proxyType string) ([]byte, bool, error) {
	var returnBytes []byte
	var prohibtedStrings = []string{";", "%", "DROP", "TABLE", "TABLES", "tables", "drop", "table", "*", "SELECT", "select"}

	if proxyType == "createUser" {
		prohibtedStrings = []string{";", "%", "DROP", "TABLE", "TABLES", "tables", "drop", "table", "*", "SELECT", "select", "?", "-", "/"}
		decoder := json.NewDecoder(r)
		var jrq = &jsonRequestCreateUser{}

		// Decode the struct internally
		err = decoder.Decode(&jrq)
		if err != nil {
			l.Println(err.Error())
			return nil, false, err
		}

		jrq.Email = strings.ToLower(jrq.Email)
		jrq.UserName = strings.ToLower(jrq.UserName)
		jrq.FullName = strings.ToLower(jrq.FullName)

		for i := 0; i < len(prohibtedStrings); {
			if strings.Contains(jrq.Email, prohibtedStrings[i]) == true {
				l.Println("Email field contains malicious string! (Potential SQL Injection?)")
				l.Printf("Offending field: %s\n", jrq.Email)
				return nil, false, errors.New("MALICE")
			}
			i++
		}
		for i := 0; i < len(prohibtedStrings); {
			if strings.Contains(jrq.UserName, prohibtedStrings[i]) == true {
				l.Println("Username field contains malicious string! (Potential SQL Injection?)")
				l.Printf("Offending field: %s\n", jrq.UserName)
				return nil, false, errors.New("MALICE")
			}
			i++
		}
		for i := 0; i < len(prohibtedStrings); {
			if strings.Contains(jrq.FullName, prohibtedStrings[i]) == true {
				l.Println("Full name field contains malicious string! (Potential SQL Injection?)")
				l.Printf("Offending field: %s\n", jrq.FullName)
				return nil, false, errors.New("MALICE")
			}
			i++
		}

		returnBytes = []byte(fmt.Sprintf(`{"FullName": "%s", "Email": "%s", "Password": "%s", "UserName": "%s"}`, jrq.FullName, jrq.Email, jrq.Password, jrq.UserName))
	} else {
		l.Printf("Filtering request with type %s...\n", proxyType)
		body, err := ioutil.ReadAll(r)
		if err != nil {
			l.Printf("Error: %s\n", err.Error())
		}
		for i := 0; i < len(prohibtedStrings); {
			if strings.Contains(string(body), prohibtedStrings[i]) == true {
				l.Printf("Request body contains malicious string! (Potential SQL injection?)")
				l.Printf("Offending field: %s\n", string(body))
				return nil, false, errors.New("MALICE")
			}
			i++
		}
		returnBytes = body
	}

	return returnBytes, false, nil
}

type jsonRequestCreateUser struct {
	FullName string `json:"FullName"`
	Email    string `json:"Email"`
	Password string `json:"Password"`
	UserName string `json:"UserName"`
}

type vncProxyValues struct {
	UserToken string `json:"UserToken"`
	VpsName   string `json:"DomainName"`
	Email     string `json:"Email"`
}

// Verifies the ownership of a user to a VPS
func verifyOwnership(userToken string, vpsName string, userEmail string) bool {
	// Make sure all values exist
	if userToken == "" {
		return false
	}
	if vpsName == "" {
		return false
	}
	if userEmail == "" {
		return false
	}

	// Execute the query checking for the user binding to the VPS
	//checkQuery := fmt.Sprintf("select domain_name from domaininfo where user_token = '%s' and domain_name = '%s' and user_email = '%s'", userToken, vpsName, userEmail)
	checkOwnership := db.QueryRow("SELECT domain_name FROM domaininfo WHERE user_token = ? AND domain_name = ? AND user_email = ?", userToken, vpsName, userEmail)

	var ownsVps bool

	switch err := checkOwnership.Scan(&vpsName); err {
	case sql.ErrNoRows:
		ownsVps = false
		return ownsVps
	case nil:
		ownsVps = true
	default:
		l.Println(err.Error())
	}

	l.Printf("Owns VPS: %t", ownsVps)

	if ownsVps == false {
		l.Printf("Unauthorized access to %s requested!", vpsName)
	}

	/*if checkOwnership.Next(); bool(ownsVps) {
		ownsVps = false
		l.Printf("Owns VPS: %t", ownsVps)
		return ownsVps
	} else {
		l.Printf("Unauthorized access to %s requested!", vpsName)
		fmt.Println(checkOwnership.Next())
		ownsVps = true
		l.Printf("Owns VPS: %t", ownsVps)
		return ownsVps
	}*/
	return ownsVps
}

func vncProxy(w http.ResponseWriter, r *http.Request) {

	r.Header.Set("Access-Control-Allow-Origin", "*.repl.co")
	w.Header().Set("Access-Control-Allow-Origin", "*.repl.co")
	r.Header.Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	r.Header.Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	decoder := json.NewDecoder(r.Body)
	var t *vncProxyValues = &vncProxyValues{}

	// Set the maximum bytes able to be consumed by the API to prevent denial of service

	// Decode the struct internally
	err := decoder.Decode(&t)
	if err != nil {
		l.Println(err.Error())
		return
	}

	if t.Email == "" {
		fmt.Fprintf(w, `{"MissingEmail": "true"}`)
		return
	}
	if t.UserToken == "" {
		fmt.Fprintf(w, `{"MissingUserToken": "true"}`)
		return
	}
	if t.VpsName == "" {
		fmt.Fprintf(w, `{"MissingDomainName": "true"}`)
		return
	}

	ownsVps := verifyOwnership(t.UserToken, t.VpsName, t.Email)

	if ownsVps != true {
		authJsonString := fmt.Sprintf(`{"Unauthorized": "true"}`)
		fmt.Fprintf(w, "%s\n", authJsonString)
		l.Printf("%t\n", ownsVps)
		return
	}

	// Open the config file
	f, err := os.OpenFile("/etc/gammabyte/lsapi/vnc/vnc.conf",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		l.Println(err.Error())
		return
	}
	defer f.Close()

	dbvar := dbValues{}
	result, err := db.Query("SELECT host_binding FROM domaininfo WHERE domain_name = ?", t.VpsName)
	if err != nil {
		l.Printf("Error querying DB for host binding for VM %s!", t.VpsName)
		l.Printf("Error: %s\n", err.Error())
		r.Body.Close()
		return
	}
	for result.Next() {
		result.Scan(&dbvar.hostBinding)
	}
	if dbvar.hostBinding == "" {
		l.Printf("Error: Domain %s has no host binding!", t.VpsName)
		r.Body.Close()
		return
	}
	l.Printf("Domain %s is bound to host %s!", t.VpsName, dbvar.hostBinding)

	result, err = db.Query("SELECT kvm_api_port FROM hostinfo WHERE hostname = ?", dbvar.hostBinding)
	if err != nil {
		l.Printf("Error querying DB for kvm port on host %s\n", dbvar.hostBinding)
		l.Printf("Error: %s\n", err.Error())
		r.Body.Close()
		return
	}
	for result.Next() {
		result.Scan(&dbvar.hostPort)
	}
	if dbvar.hostPort == "" {
		l.Printf("Error: host %s has no KVM api port binding!", dbvar.hostBinding)
		r.Body.Close()
		return
	}

	url := fmt.Sprintf("https://%s:%s/api/vnc/proxy/create", dbvar.hostBinding, dbvar.hostPort)
	sendBody := strings.NewReader(fmt.Sprintf(`{"UserToken": "%s", "Email": "%s", "DomainName": "%s"}`, t.UserToken, t.Email, t.VpsName))
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
	}
	resp, err := http.Post(url, "application/json", sendBody)

	returnValues := returnVncValues{}
	decoder = json.NewDecoder(resp.Body)
	err = decoder.Decode(&returnValues)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
	}

	// Append the string we generated earlier to the config file
	if _, err := f.WriteString(fmt.Sprintf("%s\n", returnValues.AppendString)); err != nil {
		l.Println(err.Error())
		return
	}

	time.AfterFunc(3*time.Hour, func() { destroyVncToken(returnValues.AppendString) })

	// Generate a URL that specifies the token & proper host:port combination, then send it to the API request endpoint as a JSON string
	l.Printf("%s\n", returnValues.VncURL)
	fmt.Fprintf(w, "{\"VncURL\": \"%s\"}\n", returnValues.VncURL)
}

type returnVncValues struct {
	VncURL       string `json:"VncURL"`
	AppendString string `json:"AppendString"`
}

func destroyVncToken(stringToDestroy string) {

	read, err := ioutil.ReadFile("/etc/gammabyte/lsapi/vnc/vnc.conf")
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		panic(err)
	}
	newContents := strings.Replace(string(read), stringToDestroy, "", -1)
	err = ioutil.WriteFile("/etc/gammabyte/lsapi/vnc/vnc.conf", []byte(newContents), 0)
	if err != nil {
		l.Printf("Error: %s\n")
		panic(err)
	}

	l.Printf("Destroyed string in VNC config file matching value %s.\n", stringToDestroy)

}

func startVncWebsocket() {
	FQDN, err := fqdn.FqdnHostname()
	if err != nil {
		l.Printf("Error getting FQDN! Error: %s\n", err.Error())
		panic(err)
	}
	l.Printf("Successfully started VNC proxy with URL: https://%s:8401/vnc.html", FQDN)
	cmd := exec.Command("/srv/noVNC/utils/websockify/run", "0.0.0.0:8401", "--token-plugin=TokenFile", "--token-source=/etc/gammabyte/lsapi/vnc/vnc.conf", "--log-file=/var/log/lsapi-vnc.log", "--record=/var/log/lsapi-vnc.session", "--web=/srv/noVNC")
	start := time.Now()
	err = cmd.Run()
	if err != nil {
		l.Printf("Error starting VNC websocket: %s\n", err.Error())
		panic(err)
	}
	fmt.Printf("pid=%d duration=%s err=%s\n", cmd.Process.Pid, time.Since(start), err)
	time.AfterFunc(1*time.Second, func() {
		err := cmd.Process.Kill()
		if err != nil {
			return
		}
	})
}
