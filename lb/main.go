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
	"time"
)

// Set logging facility
var remoteSyslog, _ = syslog.Dial("udp", "localhost:514", syslog.LOG_DEBUG, "[LibStatsAPI-ALB]")
var logFile, err = os.OpenFile("/var/log/lsapi.log", os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
var writeLog = io.MultiWriter(os.Stdout, logFile, remoteSyslog)
var l = log.New(writeLog, "[LibStatsAPI-foo] ", 2)

// Set global SQL connection
var db *sql.DB

func getSyslogServer() string {
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config.yml")
	yamlConfig, err := ioutil.ReadFile(filename)
	if err != nil {
		l.Fatalf("Error: %s\n", err.Error())
		return "localhost:514"
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	return ConfigFile.SyslogAddress
}

func handleRequests() {
	http.HandleFunc("/api/auth", proxyRequestsAuth)
	http.HandleFunc("/api/kvm", proxyRequestsKvm)
	http.HandleFunc("/api/vnc", proxyRequestsVnc)
	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config.yml")
	yamlConfig, err := ioutil.ReadFile(filename)

	if err != nil {
		panic(err)
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

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
	}

	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config.yml")
	yamlConfig, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err.Error())
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	ctx, cancelfunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelfunc()

	remoteSyslog, _ = syslog.Dial("udp", getSyslogServer(), syslog.LOG_DEBUG, "[LibStatsAPI-ALB]")
	logFile, err = os.OpenFile("/var/log/lsapi.log", os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		l.Fatalf("Error: %s\n", err.Error())
	}
	writeLog = io.MultiWriter(os.Stdout, logFile, remoteSyslog)
	l = log.New(writeLog, "[LibStatsAPI-ALB] ", 2)

	// Connect to MariaDB
	dbConnectString := fmt.Sprintf("%s:%s@tcp(%s:3306)/", ConfigFile.SqlUser, ConfigFile.SqlPassword, ConfigFile.SqlAddress)
	db, err := sql.Open("mysql", dbConnectString)

	createDB := `CREATE DATABASE IF NOT EXISTS lsapi`

	res, err := db.Exec(createDB)
	if err != nil {
		l.Printf("Error %s when creating lsapi DB\n", err)
	}

	db.Close()

	dbConnectString = fmt.Sprintf("%s:%s@tcp(%s:3306)/lsapi", ConfigFile.SqlUser, ConfigFile.SqlPassword, ConfigFile.SqlAddress)
	db, err = sql.Open("mysql", dbConnectString)

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
		l.Printf("Error - could not connect to MySQL DB:\n %s\n", err)
		panic(err)
	}

	err = db.Ping()
	if err != nil {
		l.Printf("Error - could not connect to MySQL DB:\n %s\n", err)
		panic(err)
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
		panic(err)
	} else {
		l.Printf("Successfully connected to MySQL DB.\n")
	}

	hostnames, hostIPs, err := parseHostFile()
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
	}
	l.Printf("Hosts: %s\n", hostnames)
	l.Printf("Host IPs: %s\n", hostIPs)

	var i = 0
	var hostStats []string
	var hostStatsRam []int
	hostnames, hostIPs, err = parseHostFile()
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		return
	}
	l.Printf("Hosts: %s\n", hostnames)
	l.Printf("Host IPs: %s\n", hostIPs)
	for i = range hostnames {
		l.Printf("Checking host %s\n...", hostnames[i])
		//hostURL := fmt.Sprintf("http://%s/api/host")
		//resp, err := http.Get(hostURL)
		if err != nil {
			l.Printf("Error getting host stats: %s\n", err.Error())
			return
		}
		//defer resp.Body.Close()
		//decoder := json.NewDecoder(resp.Body)
		var respBody = &hostStatsRespBody{}
		respBody.RamUsage = 4 + i
		respBody.CpuUsage = 0
		//err = decoder.Decode(&respBody)
		if err != nil {
			l.Println(err.Error())
			return
		}
		hostStatsJson := fmt.Sprintf(`{"Hostname": "%s", "HostRamUsage": "%d", "HostCpuUsage": "%s"}`, hostnames[i], respBody.RamUsage, respBody.CpuUsage)
		hostStats = append(hostStats, hostStatsJson)
		hostStatsRam = append(hostStatsRam, respBody.RamUsage)
	}
	i = 0
	//minRamHost, err := Min(hostStatsRam)
	minRamHost := 4
	if err != nil {
		l.Printf("Error getting host with minimum RAM usage: %s\n", err.Error())
	}
	index := Search(len(hostStatsRam), func(i int) bool { return hostStatsRam[i] >= minRamHost })
	if i < len(hostStatsRam) && hostStatsRam[i] == minRamHost {
		l.Printf("Found %d at index %d in %v\n", minRamHost, i, hostStatsRam)
	} else if i > len(hostStatsRam) && hostStatsRam[i] != minRamHost {
		l.Printf("%d not found in %v\n", minRamHost, hostStatsRam)
	}
	l.Println(index)

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

	decoder := json.NewDecoder(r.Body)
	var rpv = &requestProxyValue{}

	// Decode the struct internally
	err := decoder.Decode(&rpv)
	if err != nil {
		l.Println(err.Error())
		return
	}

	var proxyURI string
	if rpv.Type == "createUser" {
		proxyURI = "/api/auth/user/create"
	}
	if rpv.Type == "getUserDomains" {
		proxyURI = "/api/auth/user/vms"
	}
	if rpv.Type == "authDomain" {
		proxyURI = "/api/auth/vm"
	}
	if rpv.Type == "userLogin" {
		proxyURI = "/api/auth/login"
	}
	if rpv.Type == "verifyToken" {
		proxyURI = "/api/auth/login/verify"
	}
	if rpv.Type == "notify" {
		proxyURI = "/api/auth/notify"
	}
	l.Printf("Request made to %s!", proxyURI)

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
	decoder := json.NewDecoder(reqBodyStored2)
	var rpv = &requestProxyValue{}

	// Define var dbvar for use later
	var dbvar = &dbValues{}

	// Decode the struct internally
	err := decoder.Decode(&rpv)
	if err != nil {
		l.Println(err.Error())
		return
	}

	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config.yml")
	yamlConfig, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

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
		}
		index := Search(len(hostStatsRam), func(i int) bool { return hostStatsRam[i] >= minRamHost })
		if i < len(hostStatsRam) && hostStatsRam[i] == minRamHost {
			l.Printf("Found RAM usage %dMB at slice index %d in %v\n", minRamHost, i, hostStatsRam)
		} else if i > len(hostStatsRam) && hostStatsRam[i] != minRamHost {
			l.Printf("Ram usage %dMB not found in %v\n", minRamHost, hostStatsRam)
		}
		hostChosen := hostnames[index]
		l.Printf("Host chosen: %s\n", hostChosen)

		dbConnectString := fmt.Sprintf("%s:%s@tcp(%s:3306)/lsapi", ConfigFile.SqlUser, ConfigFile.SqlPassword, ConfigFile.SqlAddress)
		db, err = sql.Open("mysql", dbConnectString)

		result, err := db.Query("SELECT kvm_api_port FROM hostinfo WHERE hostname = ?", hostChosen)
		if err != nil {
			l.Printf("Error: %s\n", err.Error())
			l.Printf("Error quering DB for host port for host %s!", hostChosen)
			return
		}
		for result.Next() {
			result.Scan(&dbvar.hostPort)
		}
		if dbvar.hostPort == "" {
			l.Printf("Error: Host %s API has no port binding!", dbvar.hostBinding)
			return
		}

		httpUrl := fmt.Sprintf("http://%s:%s/%s", hostChosen, dbvar.hostPort, proxyURI)
		returnValues, err := http.Post(httpUrl, "application/json", reqBodyStored)
		if err != nil {
			fmt.Fprintf(w, "Error: %s\n", err.Error())
			return
		}
		b, err := ioutil.ReadAll(returnValues.Body)
		if err != nil {
			fmt.Fprintf(w, "Error: %s\n", err.Error())
			return
		}
		fmt.Fprintf(w, "%s\n", string(b))
		return
	}

	// Get values from DB
	dbConnectString := fmt.Sprintf("%s:%s@tcp(%s:3306)/lsapi", ConfigFile.SqlUser, ConfigFile.SqlPassword, ConfigFile.SqlAddress)
	db, err := sql.Open("mysql", dbConnectString)
	if err != nil {
		l.Printf("Error - could not connect to MySQL DB:\n %s\n", err.Error())
		panic(err)
	}
	queryString := fmt.Sprintf("SELECT host_binding FROM domaininfo WHERE domain_name = '%s'", rpv.DomainName)
	result, err := db.Query(queryString)
	if err != nil {
		l.Printf("Error querying DB for host binding for VM %s!", rpv.DomainName)
		l.Printf("Error: %s\n", err.Error())
		return
	}
	for result.Next() {
		result.Scan(&dbvar.hostBinding)
	}
	if dbvar.hostBinding == "" {
		l.Printf("Error: Domain %s has no host binding!", rpv.DomainName)
		return
	}
	l.Printf("Domain %s is bound to host %s!", rpv.DomainName, dbvar.hostBinding)

	queryString = fmt.Sprintf("SELECT kvm_api_port FROM hostinfo WHERE hostname = '%s'", dbvar.hostBinding)
	result, err = db.Query(queryString)
	if err != nil {
		l.Printf("Error querying DB for port on host %s!", dbvar.hostBinding)
		return
	}
	for result.Next() {
		result.Scan(&dbvar.hostPort)
	}
	if dbvar.hostPort == "" {
		l.Printf("Error: Host %s API has no port binding!", dbvar.hostBinding)
		return
	}
	l.Printf("Host %s API has port binding %s!", dbvar.hostBinding, dbvar.hostPort)

	// Setup the forward proxy
	httpUrl := fmt.Sprintf("http://%s:%s/%s", dbvar.hostBinding, dbvar.hostPort, proxyURI)
	returnValues, err := http.Post(httpUrl, "application/json", reqBodyStored)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
	}
	b, err := ioutil.ReadAll(returnValues.Body)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
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

	decoder := json.NewDecoder(r.Body)
	var rpv = &requestProxyValue{}

	// Decode the struct internally
	err := decoder.Decode(&rpv)
	if err != nil {
		l.Println(err.Error())
		return
	}

	var proxyURI string
	if rpv.Type == "createVncProxy" {
		proxyURI = "/api/vnc/proxy/create"
	}
	l.Printf("Request made to %s!", proxyURI)

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
func indexOf(word int, data []int) int {
	for k, v := range data {
		if word == v {
			return k
		}
	}
	return -1
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