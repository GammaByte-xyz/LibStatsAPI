package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Terry-Mao/goconf"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/net/context"
	"gopkg.in/yaml.v3"
	"io"
	ioutil "io/ioutil"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Set global variables
var (
	remoteSyslog, _ = syslog.Dial("udp", "localhost:514", syslog.LOG_DEBUG, "[LibStatsAPI-ALB]")
	logFile, _      = os.OpenFile("/var/log/lsapi.log", os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	writeLog        = io.MultiWriter(os.Stdout, logFile, remoteSyslog)
	l               = log.New(writeLog, "[LibStatsAPI-ALB] ", 2)
	db              *sql.DB
	filename        string
	yamlConfig      []byte
	err             error
	ConfigFile      configFile
)

func getSyslogServer() string {
	filename, _ = filepath.Abs("/etc/gammabyte/lsapi/config.yml")
	yamlConfig, err = ioutil.ReadFile(filename)
	if err != nil {
		l.Fatalf("Error: %s\n", err.Error())
		return "localhost:514"
	}
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	return ConfigFile.SyslogAddress
}

func handleRequests() {
	http.HandleFunc("/api/auth", proxyRequestsAuth)
	http.HandleFunc("/api/kvm", proxyRequestsKvm)
	http.HandleFunc("/api/vnc", vncProxy)

	listenAddr := fmt.Sprintf("%s:%s", ConfigFile.ListenAddress, ConfigFile.ListenPort)

	// Listen on specified port
	l.Fatal(http.ListenAndServe(listenAddr, nil))
}

func main() {
	// Check to see if config file exists
	if fileExists("/etc/gammabyte/lsapi/config.yml") {
		l.Println("Config file found.")
	} else {
		l.Println("Config file '/etc/gammabyte/lsapi/config.yml' not found!")
		panic("Config file not found.")
	}

	// Parse the config file
	filename, err = filepath.Abs("/etc/gammabyte/lsapi/config.yml")
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

	ctx, cancelfunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelfunc()

	remoteSyslog, _ = syslog.Dial("udp", getSyslogServer(), syslog.LOG_DEBUG, "[LibStatsAPI-ALB]")
	logFile, err = os.OpenFile("/var/log/lsapi.log", os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		l.Fatalf("Error: %s\n", err.Error())
	}
	writeLog = io.MultiWriter(os.Stdout, logFile, remoteSyslog)
	l = log.New(writeLog, "[LibStatsAPI-ALB] ", log.Ldate|log.Ltime|log.LUTC|log.Lmsgprefix|log.Lmicroseconds|log.LstdFlags)

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

	query = `CREATE TABLE IF NOT EXISTS domaininfo(domain_name text, network text, host_binding text, mac_address text, ram int, vcpus int, storage int, ip_address text, disk_path text, time_created text, user_email text, user_full_name text, username text, user_token text)`

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
	l.Printf("Rpws affected when creating table hostinfo: %d\n", rows)

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
	}

	var i = 0
	hostnames, hostIPs, err = parseHostFile()
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		return
	}
	l.Printf("Hosts: %s\n", hostnames)
	l.Printf("Host IPs: %s\n", hostIPs)
	for i = range hostnames {
		l.Printf("%s\n", hostnames[i])
	}
	handleRequests()

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
	SyslogAddress   string `yaml:"syslog_server"`
	AuthServer      string `yaml:"auth_server"`
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

	httpUrl := fmt.Sprintf("http://%s/%s", ConfigFile.AuthServer, proxyURI)
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
			hostURL := fmt.Sprintf("http://%s:4234/api/host/stats", hostnames[i])
			resp, err := http.Get(hostURL)
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

		httpUrl := fmt.Sprintf("http://%s:%s/%s", hostChosen, dbvar.hostPort, proxyURI)
		bodyBytesFilteredBuffered := bytes.NewBuffer(bodyBytesFiltered)
		l.Printf(string(bodyBytesFiltered))
		returnValues, err := http.Post(httpUrl, "application/json", bodyBytesFilteredBuffered)
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
	httpUrl := fmt.Sprintf("http://%s:%s/%s", dbvar.hostBinding, dbvar.hostPort, proxyURI)
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

	httpUrl := fmt.Sprintf("http://%s:%s/%s", dbvar.hostBinding, dbvar.hostPort, proxyURI)
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
		return nil, nil, err
		l.Println(err)
	}

	tf := &hostConfig{}
	if err := conf.Unmarshal(tf); err != nil {
		return nil, nil, err
		l.Println(err)
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

	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config.yml")
	yamlConfig, err := ioutil.ReadFile(filename)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

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
		return
	}
	if t.UserToken == "" {
		return
	}
	if t.VpsName == "" {
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

	url := fmt.Sprintf("http://%s:%s/api/vnc/proxy/create", dbvar.hostBinding, dbvar.hostPort)
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

	// Generate a URL that specifies the token & proper host:port combination, then send it to the API request endpoint as a JSON string
	l.Printf("%s\n", returnValues.VncURL)
	fmt.Fprintf(w, "{\"VncURL\": \"%s\"}\n", returnValues.VncURL)
}

type returnVncValues struct {
	VncURL       string `json:"VncURL"`
	AppendString string `json:"AppendString"`
}
