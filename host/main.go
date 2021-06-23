package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/Showmax/go-fqdn"
	"github.com/go-ini/ini"
	_ "github.com/go-sql-driver/mysql"
	"github.com/pbnjay/memory"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"golang.org/x/net/context"
	"gopkg.in/yaml.v3"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Set global variables
var (
	remoteSyslog, _ = syslog.Dial("udp", "localhost:514", syslog.LOG_DEBUG, "[LibStatsAPI-Host]")
	logFile, err2   = os.OpenFile("/var/log/lsapi.log", os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	writeLog        = io.MultiWriter(os.Stdout, logFile, remoteSyslog)
	l               = log.New(writeLog, "[LibStatsAPI-Host] ", 2)
	db              *sql.DB
)

func getSyslogServer() string {
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config-kvm.yml")
	yamlConfig, err := ioutil.ReadFile(filename)
	if err != nil {
		l.Fatalf("Error: %s\n", err.Error())
		return "localhost:514"
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	return ConfigFile.SyslogAddress
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
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
	ListenPortHost  string `yaml:"host_listen_port"`
	SyslogAddress   string `yaml:"syslog_server"`
	MasterPort      string `yaml:"master_port"`
	MetricsPollRate int    `yaml:"metrics_poll_rate"`
	StoreMetrics    bool   `yaml:"store_metrics"`
}

func main() {
	// Check to see if config file exists
	if fileExists("/etc/gammabyte/lsapi/config-kvm.yml") {
		l.Println("Config file found.")
	} else {
		l.Println("Config file '/etc/gammabyte/lsapi/config-kvm.yml' not found!")
	}

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
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
		l.Fatalf("Failed to append %q to RootCAs: %v", "/etc/gammabyte/lsapi/lsapi-host.crt", err.Error())
	}

	// Append our cert to the system pool
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		l.Println("No certs appended, using system certs only")
	}

	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config-kvm.yml")
	yamlConfig, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	remoteSyslog, _ = syslog.Dial("udp", getSyslogServer(), syslog.LOG_DEBUG, "[LibStatsAPI-Host]")
	logFile, err = os.OpenFile("/var/log/lsapi.log", os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		l.Fatalf("Error: %s\n", err.Error())
	}
	writeLog = io.MultiWriter(os.Stdout, logFile, remoteSyslog)
	l = log.New(writeLog, "[LibStatsAPI-Host] ", 2)

	ctx, cancelfunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelfunc()

	// Connect to MariaDB
	dbConnectString := fmt.Sprintf("%s:%s@tcp(%s:3306)/", ConfigFile.SqlUser, ConfigFile.SqlPassword, ConfigFile.SqlAddress)
	db, err = sql.Open("mysql", dbConnectString)
	if err != nil {
		l.Printf("Error connecting to DB: %s\n", err.Error())
	}

	createDB := `CREATE DATABASE IF NOT EXISTS lsapi`

	res, err := db.Exec(createDB)
	if err != nil {
		l.Printf("Error %s when creating lsapi DB\n", err.Error())
	}

	db.Close()

	dbConnectString = fmt.Sprintf("%s:%s@tcp(%s:3306)/lsapi", ConfigFile.SqlUser, ConfigFile.SqlPassword, ConfigFile.SqlAddress)
	db, err = sql.Open("mysql", dbConnectString)

	query := `CREATE TABLE IF NOT EXISTS users(username text, full_name text, user_token text, email_address text, max_vcpus int, max_ram int, max_block_storage int, used_vcpus int, used_ram int, used_block_storage int, join_date text, uuid text, password varchar(255) DEFAULT NULL)`

	res, err = db.ExecContext(ctx, query)
	if err != nil {
		l.Printf("Error %s when creating users table\n", err.Error())
	}
	rows, err := res.RowsAffected()
	if err != nil {
		l.Printf("Error %s when getting rows affected\n", err.Error())
	}
	l.Printf("Rows affected when creating table: %d\n", rows)

	query = `CREATE TABLE IF NOT EXISTS domaininfo(domain_name text, network text, host_binding text, mac_address text, ram int, vcpus int, storage int, ip_address text, disk_path text, time_created text, user_email text, user_full_name text, username text, user_token text, disk_secret text)`

	ctx, cancelfunc = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelfunc()

	res, err = db.ExecContext(ctx, query)
	if err != nil {
		l.Printf("Error %s when creating domaininfo table\n", err.Error())
	}

	rows, err = res.RowsAffected()
	if err != nil {
		l.Printf("Error %s when getting rows affected\n", err.Error())
	}
	l.Printf("Rows affected when creating table: %d\n", rows)

	if err != nil {
		l.Printf("Error - could not connect to MySQL DB:\n %s\n", err.Error())
		panic(err)
	}

	err = db.Ping()
	if err != nil {
		l.Printf("Error - could not connect to MySQL DB:\n %s\n", err.Error())
		panic(err)
	} else {
		l.Printf("Successfully connected to MySQL DB.\n")
	}

	query = `CREATE TABLE IF NOT EXISTS hostinfo(host_ip text, geolocation text, host_ip_public text, ram_gb int, cpu_cores int, linux_distro text, kernel_version text, hostname text, api_port int, kvm_api_port int)`

	ctx, cancelfunc = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelfunc()

	res, err = db.ExecContext(ctx, query)
	if err != nil {
		l.Printf("Error %s when creating domaininfo table\n", err.Error())
	}

	rows, err = res.RowsAffected()
	if err != nil {
		l.Printf("Error %s when getting rows affected\n", err.Error())
	}
	l.Printf("Rows affected when creating table hostinfo: %d\n", rows)

	err = db.Ping()
	if err != nil {
		l.Printf("Error - could not connect to MySQL DB:\n %s\n", err.Error())
		panic(err)
	} else {
		l.Printf("Successfully connected to MySQL DB.\n")
	}
	hostnameFqdn, err := fqdn.FqdnHostname()
	if err != nil {
		l.Printf("Error: could not get hostname!\n%s\n", err.Error())
		panic(err)
	}
	//query = fmt.Sprintf(`DELETE FROM hostinfo WHERE hostname = '%s'`, hostnameFqdn)
	res, err = db.Exec("DELETE FROM hostinfo WHERE hostname = ?", hostnameFqdn)
	if err != nil {
		l.Println("Could not purge old host info!")
		l.Printf("Error: %s\n", err.Error())
		panic(err)
	}
	rows, err = res.RowsAffected()
	if err != nil {
		l.Printf("Error %s when getting rows affected\n", err.Error())
	}
	l.Printf("Rows affected when purging old host config: %d\n", rows)
	//l.Printf("Local IPv4: %s\n", GetOutboundIP().String())
	hostIP, geolocation, hostIPWAN, ramGb, cpuCores, distro, kernelVersion, hostname, err := getHostInfo()
	if err != nil {
		l.Printf("Error getting host info: %s\n", err.Error())
	}
	//query = fmt.Sprintf(`INSERT INTO hostinfo (host_ip, geolocation, host_ip_public, ram_gb, cpu_cores, linux_distro, kernel_version, hostname, api_port, kvm_api_port) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s')`, hostIP, geolocation, hostIPWAN, ramGb, cpuCores, distro, kernelVersion, hostname, 4234, ConfigFile.ListenPort)
	res, err = db.Exec("INSERT INTO hostinfo (host_ip, geolocation, host_ip_public, ram_gb, cpu_cores, linux_distro, kernel_version, hostname, api_port, kvm_api_port) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", hostIP, geolocation, hostIPWAN, ramGb, cpuCores, distro, kernelVersion, hostname, 4234, ConfigFile.ListenPort)
	if err != nil {
		l.Printf("Error inserting host info: %s\n", err.Error())
		panic(err)
	}

	go gatherMetrics(&ConfigFile)
	handleRequests(&ConfigFile, rootCAs, hostname)

}

func sendCert(w http.ResponseWriter, r *http.Request) {
	crtBytes, err := ioutil.ReadFile("/etc/gammabyte/lsapi/lsapi-host.crt")
	if err != nil {
		l.Printf("Error reading file: %s\n", err.Error())
		return
	}
	_, err = fmt.Fprint(w, string(crtBytes))
	if err != nil {
		l.Printf("Error sending client response: %s\n", err.Error())
		return
	}
}

func getMasterCert(ConfigFile *configFile) ([]byte, error) {
	var t int
	if len(ConfigFile.MasterKey) >= 32 {
		t = 32
	} else if len(ConfigFile.MasterKey) <= 32 && len(ConfigFile.MasterKey) >= 24 {
		t = 24
	} else if len(ConfigFile.MasterKey) <= 24 && len(ConfigFile.MasterKey) >= 16 {
		t = 16
	}

	key := []byte(ConfigFile.MasterKey[:t])
	plainText := []byte("K{eR8]:pP:$z}xSogwQ(tzjK#=io_6M:yT;fFdNrbL%Ce*}K[XO>;r[G")
	block, err := aes.NewCipher(key)
	if err != nil {
		l.Printf("Error creating new cipher block: %s\n", err.Error())
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		l.Printf("Error creating new aesGCM cipher: %s\n", err.Error())
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	ciphertext := aesGCM.Seal(nonce, nonce, plainText, nil)

	r := strings.NewReader(string(ciphertext))
	req, err := http.NewRequest("POST", "https://"+ConfigFile.MasterIP+":"+ConfigFile.MasterPort+"/api/tls/getcert", r)
	if err != nil {
		l.Printf("Error generating certificate request: %s\n", err.Error())
		return nil, err
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport}
	hostname, err := fqdn.FqdnHostname()
	if err != nil {
		l.Printf("Error getting hostname: %s\n", err.Error())
		return nil, err
	}
	req.Header.Set("hostname", hostname)
	req.Header.Set("listenport", "4234")
	resp, err := client.Do(req)
	if err != nil {
		l.Printf("Error sending request: %s\n", err.Error())
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		l.Printf("Error: Master node rejected the request due to an invalid authphrase")
		return nil, fmt.Errorf("master node rejected the request due to an invalid authphrase")
	}
	if resp.StatusCode != http.StatusOK {
		l.Printf("Error: Master node did not respond with HTTP 200, they responded with %s\n", resp.Status)
		return nil, fmt.Errorf("master node did not respond with HTTP 200, they responded with %s\n", resp.Status)
	}

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		l.Printf("Error reading response body: %s\n", err.Error())
		return nil, err
	}
	return respBytes, nil
}

func handleRequests(ConfigFile *configFile, rootCAs *x509.CertPool, hostname string) {
	http.HandleFunc("/api/host/stats", getStats)
	http.HandleFunc("/api/getcert", sendCert)
	http.HandleFunc("/api/metrics/average", averageEndpoint)
	http.HandleFunc("/api/metrics/by/timestamp", timestampMetricsEndpoint)
	// Listen on specified port
	l.Fatal(http.ListenAndServeTLS(":4234", "/etc/pki/tls/certs/"+hostname+".crt", "/etc/pki/tls/private/"+hostname+".key", nil))
}

func getStats(w http.ResponseWriter, r *http.Request) {
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		return
	}
	l.Printf("Host RAM usage: %s%%\n", strconv.FormatFloat(vmStat.UsedPercent, 'f', 2, 64))
	ramUsage := strconv.FormatFloat(vmStat.UsedPercent, 'f', 2, 64)
	ramUsage = strings.ReplaceAll(ramUsage, ".", "")

	// cpu - get CPU number of cores and speed
	percentage, err := cpu.Percent(0, true)
	if err != nil {
		l.Printf("Error getting CPU cores & speed: %s\n", err.Error())
	}

	var usageCombined int = 0
	var i int = 0
	for _, cpupercent := range percentage {
		usageCombined = int(cpupercent) + usageCombined
		i++
	}
	i++
	cpuUsage := usageCombined / i

	fmt.Fprintf(w, `{"RamUsage": "%s", "CpuUsage": "%d"}`, ramUsage, cpuUsage)
}

// Get preferred outbound ip of this machine
func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err.Error())
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

// Get geo location of this Machine
func getGeoLocation(wanIP string) string {

	// Use freegeoip.net to get a JSON response
	// There is also /xml/ and /csv/ formats available
	response, err = http.Get("http://api.ipstack.com/" + wanIP + "?access_key=c812ab47e0a61807ce9de69d29050268")
	if err != nil {
		l.Printf("Error getting WAN IP: %s\n", err.Error())
	}
	defer func(Body io.ReadCloser) {
		err = Body.Close()
		if err != nil {
			l.Println(err.Error())
		}
	}(response.Body)
	// response.Body() is a reader type. We have
	// to use ioutil.ReadAll() to read the data
	// in to a byte slice(string)
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		l.Printf("Error reading response body for WAN IP: %s\n", err.Error())
	}

	// Unmarshal the JSON byte slice to a GeoIP struct
	err = json.Unmarshal(body, &geo)
	if err != nil {
		l.Printf("Error unmarshaling response body for WAN IP: %s\n", err.Error())
	}

	locationString := fmt.Sprintf("%s, %s, %s, %s", geo.City, geo.RegionName, geo.Zipcode, geo.CountryName)
	return locationString
}

func getHostInfo() (string, string, string, string, string, string, string, string, error) {
	lanIP := GetOutboundIP().String()
	l.Printf("Lan IP: %s\n", lanIP)
	wanIP, err := exec.Command("curl", "ifconfig.me").Output()
	if err != nil {
		l.Printf("Failed to get WAN IP due to error: %s\n", err.Error())
	}
	l.Printf("WAN IP: %s\n", string(wanIP))
	geoLocation := getGeoLocation(string(wanIP))
	l.Printf("Geolocation: %s\n", geoLocation)
	ramGB := strconv.FormatUint((memory.TotalMemory() / 1000000000), 10)
	l.Printf("Total RAM (GB): %s\n", ramGB)
	cpuCoresInt, err := cpu.Counts(true)
	if err != nil {
		l.Printf("Failed to get CPU cores due to error: %s\n", err.Error())
	}
	cpuCores := strconv.Itoa(cpuCoresInt)
	l.Printf("Total CPU cores: %s\n", cpuCores)
	OSInfo := ReadOSRelease("/etc/os-release")
	linuxDistro := OSInfo["PRETTY_NAME"]
	l.Printf("Distro: %s\n", linuxDistro)
	kernelVersionByte, err := exec.Command("uname", "-r").Output()
	l.Printf("Kernel Version: %s\n", string(kernelVersionByte))
	hostname, err := fqdn.FqdnHostname()
	l.Printf("Hostname: %s\n", hostname)

	return lanIP, geoLocation, string(wanIP), ramGB, cpuCores, linuxDistro, string(kernelVersionByte), hostname, nil
}

func ReadOSRelease(configfile string) map[string]string {
	cfg, err := ini.Load(configfile)
	if err != nil {
		log.Fatal("Fail to read file: ", err.Error())
	}

	ConfigParams := make(map[string]string)
	ConfigParams["ID"] = cfg.Section("").Key("ID").String()
	ConfigParams["PRETTY_NAME"] = cfg.Section("").Key("PRETTY_NAME").String()

	return ConfigParams
}

type GeoIP struct {
	// The right side is the name of the JSON variable
	Ip          string  `json:"ip"`
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name""`
	RegionCode  string  `json:"region_code"`
	RegionName  string  `json:"region_name"`
	City        string  `json:"city"`
	Zipcode     string  `json:"zip"`
	Lat         float32 `json:"latitude"`
	Lon         float32 `json:"longitude"`
	MetroCode   int     `json:"metro_code"`
	AreaCode    int     `json:"area_code"`
}

var (
	address  string
	err      error
	geo      GeoIP
	response *http.Response
	body     []byte
)
