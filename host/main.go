package main

import (
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
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

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
		panic(err)
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	ctx, cancelfunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelfunc()

	// Connect to MariaDB
	dbConnectString := fmt.Sprintf("%s:%s@tcp(%s:3306)/", ConfigFile.SqlUser, ConfigFile.SqlPassword, ConfigFile.SqlAddress)
	db, err := sql.Open("mysql", dbConnectString)
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

	query = `CREATE TABLE IF NOT EXISTS domaininfo(domain_name text, network text, host_binding text, mac_address text, ram int, vcpus int, storage int, ip_address text, disk_path text, time_created text, user_email text, user_full_name text, username text, user_token text)`

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

	query = `CREATE TABLE IF NOT EXISTS hostinfo(host_ip text, geolocation text, host_ip_public text, ram_gb int, cpu_cores int, linux_distro text, kernel_version text, hostname text, api_port int)`

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
		panic(err)
	} else {
		l.Printf("Successfully connected to MySQL DB.\n")
	}
	hostnameFqdn, err := fqdn.FqdnHostname()
	if err != nil {
		l.Printf("Error: could not get hostname!\n%s\n", err.Error())
		panic(err)
	}
	query = fmt.Sprintf(`DELETE FROM hostinfo WHERE hostname = '%s'`, hostnameFqdn)
	res, err = db.Exec(query)
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
	query = fmt.Sprintf(`INSERT INTO hostinfo (host_ip, geolocation, host_ip_public, ram_gb, cpu_cores, linux_distro, kernel_version, hostname, api_port) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d')`, hostIP, geolocation, hostIPWAN, ramGb, cpuCores, distro, kernelVersion, hostname, 4234)
	res, err = db.Exec(query)
	if err != nil {
		l.Printf("Error inserting host info: %s\n", err.Error())
		panic(err)
	}
	handleRequests()
}

// Set logging facility
var l = log.New(os.Stdout, "[LibStatsAPI-Host] ", 2)

func handleRequests() {
	http.HandleFunc("/api/host/stats", getStats)

	// Listen on specified port
	l.Fatal(http.ListenAndServe("0.0.0.0:4234", nil))
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
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

// Get geo location of this Machine
func getGeoLocation(wanIP string) string {

	// Use freegeoip.net to get a JSON response
	// There is also /xml/ and /csv/ formats available
	response, err := http.Get("http://api.ipstack.com/" + wanIP + "?access_key=c812ab47e0a61807ce9de69d29050268")
	if err != nil {
		l.Printf("Error getting WAN IP: %s\n", err.Error())
	}
	defer response.Body.Close()
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
		log.Fatal("Fail to read file: ", err)
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
