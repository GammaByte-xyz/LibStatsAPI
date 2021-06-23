package main

import (
	"archive/tar"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/machinebox/progress"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"math"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"net/smtp"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/Showmax/go-fqdn"
	"github.com/eventials/go-tus"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/klauspost/compress/gzhttp"
	gzip "github.com/klauspost/pgzip"
	"github.com/libvirt/libvirt-go"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/context"
	"gopkg.in/yaml.v3"
	libvirtxml "libvirt.org/libvirt-go-xml"
)

// Set global variables
var (
	remoteSyslog, _ = syslog.Dial("udp", "localhost:514", syslog.LOG_DEBUG, "[LibStatsAPI-KVM]")
	logFile, _      = os.OpenFile("/var/log/lsapi.log", os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	writeLog        = io.MultiWriter(os.Stdout, logFile, remoteSyslog)
	l               = log.New(writeLog, "[LibStatsAPI-KVM] ", log.Ldate|log.Ltime|log.LUTC|log.Lmsgprefix|log.Lmicroseconds|log.LstdFlags|log.Llongfile|log.Lshortfile)
	db              *sql.DB
	rootCAs, _      = x509.SystemCertPool()
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

// Verify functionality of API with the "/" URI path
func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "API Endpoint Hit\n")
}

// Handle all HTTP requests on different paths
func handleRequests(hostname string) {
	http.HandleFunc("/", homePage)
	http.HandleFunc("/api/kvm/stats", getStats)
	http.HandleFunc("/api/kvm/domains", getDomains)
	http.HandleFunc("/api/kvm/ram-usage", getRamUsage)
	http.HandleFunc("/api/kvm/create/domain", createDomain)
	http.HandleFunc("/api/kvm/delete/domain", deleteDomain)
	http.HandleFunc("/api/kvm/delete/domain/wildcard", DeleteMatchingDomains)
	http.HandleFunc("/api/vnc/proxy/create", vncProxy)
	http.HandleFunc("/api/kvm/power/toggle", togglePower)
	http.DefaultClient.Timeout = time.Minute * 10

	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config-kvm.yml")
	yamlConfig, err := ioutil.ReadFile(filename)

	if err != nil {
		panic(err.Error())
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	listenAddr := fmt.Sprintf("%s:%s", ConfigFile.ListenAddress, ConfigFile.ListenPort)

	// Listen on specified port
	l.Fatal(http.ListenAndServeTLS(listenAddr, "/etc/pki/tls/certs/"+hostname+".crt", "/etc/pki/tls/private/"+hostname+".key", nil))
}

// This is 1 GiB (gibibyte) in bytes
const (
	GiB = 1073741824 // 1 GiB = 2^30 bytes
	MiB = 1048576
)

// Main function that always runs first
func main() {

	// Check to see if config file exists
	if fileExists("/etc/gammabyte/lsapi/config-kvm.yml") {
		l.Println("Config file found.")
	} else {
		l.Println("Config file '/etc/gammabyte/lsapi/config-kvm.yml' not found!")
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

	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config-kvm.yml")
	yamlConfig, err := ioutil.ReadFile(filename)

	if err != nil {
		l.Printf("Error reading config file: %s\n", err.Error())
		panic(err.Error())
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	remoteSyslog, _ = syslog.Dial("udp", getSyslogServer(), syslog.LOG_DEBUG, "[LibStatsAPI-KVM]")
	logFile, err = os.OpenFile("/var/log/lsapi.log", os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		l.Fatalf("Error: %s\n", err.Error())
	}

	// Connect to MariaDB
	dbConnectString := fmt.Sprintf("%s:%s@tcp(%s:3306)/", ConfigFile.SqlUser, ConfigFile.SqlPassword, ConfigFile.SqlAddress)
	db, err = sql.Open("mysql", dbConnectString)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		panic(err.Error())
	}
	createDB := `CREATE DATABASE IF NOT EXISTS lsapi`

	ctx, cancelfunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelfunc()

	res, err := db.ExecContext(ctx, createDB)
	if err != nil {
		l.Fatalf("Error %s when creating lsapi DB\n", err.Error())
	}

	db.Close()

	dbConnectString = fmt.Sprintf("%s:%s@tcp(%s:3306)/lsapi", ConfigFile.SqlUser, ConfigFile.SqlPassword, ConfigFile.SqlAddress)
	db, err = sql.Open("mysql", dbConnectString)

	query := `CREATE TABLE IF NOT EXISTS users(username text, full_name text, user_token text, email_address text, max_vcpus int, max_ram int, max_block_storage int, used_vcpus int, used_ram int, used_block_storage int, join_date text, uuid text, password varchar(255) DEFAULT NULL)`

	ctx, cancelfunc = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelfunc()

	res, err = db.ExecContext(ctx, query)
	if err != nil {
		l.Fatalf("Error %s when creating users table\n", err.Error())
	}
	rows, err := res.RowsAffected()
	if err != nil {
		l.Fatalf("Error %s when getting rows affected\n", err.Error())
	}
	l.Printf("Rows affected when creating table: %d\n", rows)

	query = `CREATE TABLE IF NOT EXISTS domaininfo(domain_name text, network text, host_binding text, mac_address text, ram int, vcpus int, storage int, ip_address text, disk_path text, time_created text, user_email text, user_full_name text, username text, user_token text, disk_secret text)`

	ctx, cancelfunc = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelfunc()

	res, err = db.ExecContext(ctx, query)
	if err != nil {
		l.Fatalf("Error %s when creating domaininfo table\n", err.Error())
	}

	rows, err = res.RowsAffected()
	if err != nil {
		l.Fatalf("Error %s when getting rows affected\n", err.Error())
	}
	l.Printf("Rows affected when creating table: %d\n", rows)

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
		panic(err.Error())
	} else {
		l.Printf("Successfully connected to MySQL DB.\n")
	}
	go func() {
		l.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	handleRequests(hostname)
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

	// Connect to libvirt
	conn, err := libvirt.NewConnect("qemu:///system?socket=/var/run/libvirt/libvirt-sock")
	if err != nil {
		l.Println(err.Error())
		return
	}
	defer conn.Close()

	// Find the VPS by name provided by the frontend UI
	vps, err := conn.LookupDomainByName(t.VpsName)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		return
	}

	// Get the XML data of the VPS, then parse it
	xmlData, err := vps.GetXMLDesc(0)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		return
	}
	v := ParseDomainXML(xmlData)

	// Check to see if the VNC port is -1. If it is, we can't connect.
	var vncPort string
	if v.Devices.Graphics.VNCPort == "-1" {
		l.Printf("Could not get VNC port for domain %s!\n", t.VpsName)
	}

	// Define the VNC port from the domain XML
	vncPort = v.Devices.Graphics.VNCPort

	// Generate a one-time, secure 24 character token
	vncToken := GenerateSecureToken(24)

	// Generate the string that will be appended to /etc/gammabyte/lsapi/vnc.conf
	FQDN, err := fqdn.FqdnHostname()
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
	}
	vncAppend := fmt.Sprintf("%s: %s:%s", vncToken, FQDN, vncPort)

	// Open the config file
	f, err := os.OpenFile("/etc/gammabyte/lsapi/vnc/vnc.conf",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		l.Println(err.Error())
		return
	}
	defer f.Close()

	// Append the string we generated earlier to the config file
	if _, err := f.WriteString(vncAppend); err != nil {
		l.Println(err)
		return
	}

	// Print the data to the log
	l.Printf("Domain: %s\n", t.VpsName)
	l.Printf("VNC Port: %s\n", vncPort)

	// Removes old VNC tokens after 3 hour expiration period
	configPath := "/etc/gammabyte/lsapi/vnc/vnc.conf"
	time.AfterFunc(3*time.Hour, func() { purgeOldConfig(vncToken, configPath, t.VpsName) })

	// Generate a URL that specifies the token & proper host:port combination, then send it to the API request endpoint as a JSON string
	URL := fmt.Sprintf(`{"VncURL": "https://vnc.gammabyte.xyz/vnc.html?host=vnc.gammabyte.xyz&port=443&path=websockify?token=%s", "AppendString": "%s"}`, vncToken, vncAppend)
	l.Printf("%s\n", URL)
	fmt.Fprintf(w, URL)
}

func purgeOldConfig(vncToken string, configPath string, vpsName string) {
	// Open the config file
	exec.Command("sed", "-i", "'/"+vncToken+"/d'", configPath)
	l.Printf("Removed VNC token created 3 hours ago for VPS %s at %s", vpsName, time.Now())
}

type togglePowerVars struct {
	Token      string `json:"Token"`
	DomainName string `json:"DomainName"`
	Email      string `json:"Email"`
}

func togglePower(w http.ResponseWriter, r *http.Request) {
	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config-kvm.yml")
	yamlConfig, err := ioutil.ReadFile(filename)

	// Set the maximum bytes able to be consumed by the API to mitigate denial of service
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)
	r.Header.Set("Access-Control-Allow-Origin", "*.repl.co")
	w.Header().Set("Access-Control-Allow-Origin", "*.repl.co")
	r.Header.Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	r.Header.Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")

	if err != nil {
		l.Println(err.Error())
		return
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	decoder := json.NewDecoder(r.Body)
	var togglePower *togglePowerVars = &togglePowerVars{}

	// Decode the struct internally
	err = decoder.Decode(&togglePower)
	if err != nil {
		l.Println(err.Error())
		return
	}
	if togglePower.DomainName == "" {
		return
	}
	if togglePower.Token == "" {
		return
	}
	if togglePower.Email == "" {
		return
	}

	ownsDomain := verifyOwnership(togglePower.Token, togglePower.DomainName, togglePower.Email)
	if ownsDomain == false {
		returnJson := fmt.Sprintf(`{"Unauthorized": "true"}`)
		fmt.Fprintf(w, "%s\n", returnJson)
		return
	}

	// Connect to qemu-kvm
	conn, err := libvirt.NewConnect("qemu:///system?socket=/var/run/libvirt/libvirt-sock")
	if err != nil {
		l.Printf("Failed to connect to qemu/kvm. Error: %s\n", err.Error())
		return
	} else {
		l.Printf("Successfully connected to QEMU-KVM to query for domain statistics.\n")
	}
	defer conn.Close()

	dom, err := conn.LookupDomainByName(togglePower.DomainName)
	State, _, err := dom.GetState()
	if State == libvirt.DOMAIN_RUNNING {
		err = dom.Destroy()
		if err != nil {
			l.Println(err.Error())
			returnJson := fmt.Sprintf(`{"Success": "false"}`)
			fmt.Fprintf(w, "%s\n", returnJson)
			return
		} else {
			l.Println(err.Error())
			returnJson := fmt.Sprintf(`{"Success": "true", "State": "Off"}`)
			fmt.Fprintf(w, "%s\n", returnJson)
		}
	} else if State == libvirt.DOMAIN_SHUTOFF {
		err = dom.Create()
		if err != nil {
			l.Println(err.Error())
			returnJson := fmt.Sprintf(`{"Success": "false"}`)
			fmt.Fprintf(w, "%s\n", returnJson)
			return
		} else if State == 2 {
			err = dom.Create()
			if err != nil {
				l.Printf("Error: %s\n", err.Error())
				returnJson := fmt.Sprintf(`{"Success": "false"`)
				fmt.Fprintf(w, "%s\n", returnJson)
				return
			}
		} else {
			l.Println(err.Error())
			returnJson := fmt.Sprintf(`{"Success": "true", "State": "On"}`)
			fmt.Fprintf(w, "%s\n", returnJson)
		}
	}

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
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config-kvm.yml")
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

/*type userCreateStruct struct {
	FullName string `json:"FullName"`
	Email    string `json:"Email"`
	Password string `json:"Password"`
	UserName string `json:"UserName"`
}*/

/*func createUser(w http.ResponseWriter, r *http.Request) {
	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config-kvm.yml")
	yamlConfig, err := ioutil.ReadFile(filename)

	if err != nil {
		panic(err.Error())
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	// Decode JSON & assign the json value struct to a variable we can use here
	decoder := json.NewDecoder(r.Body)
	var user *userCreateStruct = &userCreateStruct{}

	// Set the maximum bytes able to be consumed by the API to prevent denial of service
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	r.Header.Set("Access-Control-Allow-Origin", "*.repl.co")
	w.Header().Set("Access-Control-Allow-Origin", "*.repl.co")
	r.Header.Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	r.Header.Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")

	// Decode the struct internally
	err = decoder.Decode(&user)
	if err != nil {
		l.Println(err.Error())
		return
	}

	l.Printf("%s\n%s\n%s\n%s\n", user.UserName, user.FullName, user.Email, user.Password)

	// Connect to MariaDB
	dbConnectString := fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/lsapi", ConfigFile.SqlUser, ConfigFile.SqlPassword)
	db, err := sql.Open("mysql", dbConnectString)
	// if there is an error opening the connection, handle it
	if err != nil {
		panic(err.Error())
	}
	// defer the close till after the main function has finished
	// executing
	defer db.Close()

	checkQueryEmail := fmt.Sprintf(`SELECT email_address FROM users WHERE email_address='%s'`, user.Email)
	checkQueryUserName := fmt.Sprintf(`SELECT username FROM users WHERE username='%s'`, user.UserName)
	// Check if user exists already
	checkEmailExists, err := db.Query(checkQueryEmail)
	if checkEmailExists.Next() {
		fmt.Fprintf(w, `{"UserExists": "true"}`)
		l.Printf("Email %s already exists!", user.Email)
		return
	}

	checkUserNameExists, err := db.Query(checkQueryUserName)
	if checkUserNameExists.Next() {
		fmt.Fprintf(w, `{"UserExists": "true"}\n`)
		l.Printf("User %s already exists!", user.UserName)
		return
	}

	// Create the users table if it doesn't exist, also add the columns
	query := `CREATE TABLE IF NOT EXISTS users(username text, full_name text, user_token text, email_address text, join_date text, uuid text, password varchar(255) DEFAULT NULL)`

	ctx, cancelfunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelfunc()

	res, err := db.ExecContext(ctx, query)
	if err != nil {
		l.Fatalf("Error %s when creating users table\n", err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		l.Fatalf("Error %s when getting rows affected\n", err)
	}
	l.Printf("Rows affected when creating table: %d\n", rows)

	// Generate arbitrary user binding data
	joinDate := time.Now()
	uuidValue, err := uuid.NewUUID()
	if err != nil {
		l.Fatalf("Error %s when generating UUID\n", err)
	}
	token := GenerateSecureToken(24)

	// Gather information from JSON input to generate user data, then put it in MariaDB.
	insertQuery := fmt.Sprintf("INSERT INTO users (username, full_name, user_token, email_address, join_date, uuid, password) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', SHA('%s'));", user.UserName, user.FullName, token, user.Email, joinDate.String(), uuidValue.String(), user.Password)

	res, err = db.ExecContext(ctx, insertQuery)
	if err != nil {
		l.Fatalf("Error %s when inserting user info\n", err)
	}

	rows, err = res.RowsAffected()
	if err != nil {
		l.Fatalf("Error %s when getting rows affected\n", err)
	}
	l.Printf("Rows affected when creating table: %d\n", rows)

	returnJson := fmt.Sprintf(`{"Token": "%s", "JoinDate": "%s", "UUID": "%s"}`, token, joinDate, uuidValue)
	fmt.Fprintf(w, "%s\n", returnJson)
}
*/
func GenerateSecureToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// Generate a MAC address to use for the VPS
func genMac() string {
	buf := make([]byte, 6)
	_, err := rand.Read(buf)
	if err != nil {
		l.Println("error:", err.Error())
		return ""
	}
	buf[0] = (buf[0] | 2) & 0xfe // Set local bit, ensure unicast address
	macAddr := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])
	return macAddr
}

// Retrieve statistics of the host
func getStats(w http.ResponseWriter, r *http.Request) {
	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config-kvm.yml")
	yamlConfig, err := ioutil.ReadFile(filename)
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	r.Header.Set("Access-Control-Allow-Origin", "*.repl.co")
	w.Header().Set("Access-Control-Allow-Origin", "*.repl.co")
	r.Header.Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	r.Header.Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")

	// Connect to qemu-kvm
	conn, err := libvirt.NewConnect("qemu:///system?socket=/var/run/libvirt/libvirt-sock")
	if err != nil {
		l.Printf("Failed to connect to qemu/kvm. Error: %s\n", err.Error())
		return
	} else {
		l.Printf("Successfully connected to QEMU-KVM to query for domain statistics.\n")
	}
	defer conn.Close()

	decoder := json.NewDecoder(r.Body)
	var t = &domainStats{}
	err = decoder.Decode(&t)

	ownsVps := verifyOwnership(t.Token, t.DomainName, t.EmailAddress)
	if ownsVps == false {
		authJsonString := fmt.Sprintf(`{"Unauthorized": "true"}`)
		fmt.Fprintf(w, "%s\n", authJsonString)
		l.Printf("User %s owns VPS %s: %t\n", t.EmailAddress, t.DomainName, ownsVps)
		return
	}
	l.Printf("User %s owns VPS %s: %t\n", t.EmailAddress, t.DomainName, ownsVps)

	// Get power state
	dom, err := conn.LookupDomainByName(t.DomainName)
	if err != nil {
		l.Printf("Error lookup up domain %s\n: %s\n", t.DomainName, err.Error())
		return
	}
	_, domState, err := dom.GetState()
	l.Printf("Power state of %s: %d\n", t.DomainName, domState)

	var powerState string
	if domState == 1 {
		powerState = "On"
	} else if domState == 2 {
		powerState = "Off"
	}

	// TODO This is broken right now. The array size ranges from either 0-12, or 0-3.
	// TODO Why it does this is unknown. It seems to be entirely random.
	// TODO Get memory stats
	/*mem, err := dom.MemoryStats(6, 0)
	if err != nil {
		l.Println(err)
	}
	domMaxMem, err := dom.GetMaxMemory()
	if err != nil {
		l.Println(err)
		return
	}

	mem5Value := func() uint64 {
		mem5Var := mem[5].Val
		if err := recover(); err != nil {
			l.Println(err)
		}
		return mem5Var
	}

	l.Printf("Available memory for domain %s: %d\n", t.DomainName, domMaxMem)
	l.Printf("Unused memory for domain %s: %d\n", t.DomainName, mem5Value)
	UsedMemoryKb := domMaxMem - mem5Value()
	usedMemoryGb := uint64(UsedMemoryKb) / uint64(1000000)
	l.Printf("Used memory in Kilobytes for domain %s: %d\n", t.DomainName, UsedMemoryKb)
	l.Printf("Used memory in Gigabytes for domain %s: %d\n", t.DomainName, usedMemoryGb)*/
	// TODO END

	// Get CPU Stats
	cpuStats1, err := dom.GetCPUStats(-1, 1, 0)
	if err != nil {
		l.Println(err.Error())
		return
	}
	time.Sleep(2 * time.Second)
	cpuStats2, err := dom.GetCPUStats(-1, 1, 0)
	if err != nil {
		l.Println(err.Error())
		return
	}
	l.Println(cpuStats1[0].CpuTime)
	cpuTime1 := cpuStats1[0].CpuTime
	l.Println(cpuStats2[0].CpuTime)
	cpuTime2 := cpuStats2[0].CpuTime
	cpuUsage := (100 * (cpuTime2 - cpuTime1) / 2000000000)

	l.Printf("CPU Usage: %d%%\n", cpuUsage)

	// Get disk statistics
	var diskPath string
	//diskLocationQueryString := fmt.Sprintf(`SELECT disk_path FROM domaininfo WHERE domain_name = '%s'`, t.DomainName)
	rows, err := db.Query("SELECT disk_path FROM domaininfo WHERE domain_name = ?", t.DomainName)
	for rows.Next() {
		err := rows.Scan(&diskPath)
		if err != nil {
			l.Println(err.Error())
			return
		}
	}
	rows.Close()

	fileSizeMB, err := GetFileSize(diskPath)
	if err != nil {
		l.Println(err.Error())
		return
	}
	fileSizeGB := fileSizeMB / 1000

	l.Printf("Disk path for domain %s: %s\n", t.DomainName, diskPath)
	l.Printf("Disk size (MB) for domain %s: %d\n", t.DomainName, fileSizeMB)
	l.Printf("Disk size (GB) for domain %s: %d\n", t.DomainName, fileSizeGB)

	returnJson := fmt.Sprintf(`{"PowerState": "%s", "UsageCPU": "%d", "UsageDiskMB": "%d", "UsageDiskGB": "%d"}`, powerState, cpuUsage, fileSizeMB, fileSizeGB)
	l.Printf("%s\n", returnJson)
	fmt.Fprintf(w, "%s\n", returnJson)
}

type domainStats struct {
	EmailAddress string `json:"Email"`
	Token        string `json:"Token"`
	DomainName   string `json:"DomainName"`
}

func GetFileSize(filename string) (uint64, error) {
	args := []string{"-v", filename}
	cmd := exec.Command("./getStats.sh", args...)
	stdout, err := cmd.Output()
	l.Printf("Stdout: %s\n", string(stdout))
	parsedString := strings.TrimSuffix(string(stdout), "\n")
	number, err := strconv.ParseUint(parsedString, 10, 64)
	l.Printf("Parsed value: %d\n", number)
	return number, err
}

// Retrieve the ram usage of the host
func getRamUsage(w http.ResponseWriter, r *http.Request) {
	args := []string{"getStats.sh", "-r"}

	cmd := exec.Command("bash", args...)
	stdout, err := cmd.Output()

	if err != nil {
		l.Println(err.Error())
		return
	}

	l.Println(cmd)
	l.Println(string(stdout))
	fmt.Fprintf(w, string(stdout))
}

// Set values for alphabetic random string generation
const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
)

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
	MasterPort      string `yaml:"master_port"`
	MasterFqdn      string `yaml:"master_fqdn"`
}

// Values parsed from JSON API input that can be used later
type createDomainStruct struct {
	// VM Specs
	RamSize            int    `json:"RamSize,string,omitempty"`
	CpuSize            int    `json:"CpuSize,string,omitempty"`
	DiskSize           int    `json:"DiskSize,string,omitempty"`
	OperatingSystem    string `json:"OperatingSystem"`
	Network            string `json:"Network"`
	VncPasswordEnabled bool   `json:"VncPasswordEnabled"`
	VncPassword        string `json:"VncPassword"`
	NetworkFilter      string `json:"NetworkFilter"`

	// User Information
	UserEmail string `json:"UserEmail"`
	UserID    int    `json:"UserID,string,omitempty"`
	FullName  string `json:"FullName"`
	UserRole  string `json:"UserRole"`
	Username  string `json:"Username"`
	UserToken string `json:"Token"`

	// Misc. Data
	CreationDate string `json:"CreationDate"`
}

type vncProxyValues struct {
	UserToken string `json:"UserToken"`
	VpsName   string `json:"DomainName"`
	Email     string `json:"Email"`
}

// Generate a random integer for the VPS ID
func random(min int, max int) int {
	return rand.Intn(max-min) + min
}

type maxResources struct {
	vcpus   int
	ram     int
	storage int
}

type usedResources struct {
	vcpus   int
	ram     int
	storage int
}

func notifyMaster(message string) string {
	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config-kvm.yml")
	yamlConfig, err := ioutil.ReadFile(filename)
	if err != nil {
		l.Println(err.Error())
		return "Error"
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	if ConfigFile.MasterKey == "" {
		l.Println("No master node key in config file! Failed.")
		return "Error"
	}
	if ConfigFile.MasterIP == "" {
		l.Println("No master node IP in config file! Failed.")
		return "Error"
	}

	masterUrl := fmt.Sprintf("https://%s/api/auth/notify", ConfigFile.AuthServer)

	curlBody := fmt.Sprintf("'%s'", message)
	curlCmd := []string{"-X", "POST", "-fSsL", "-d", curlBody, masterUrl}
	cmd := exec.Command("curl", curlCmd...)
	stdout, err := cmd.Output()
	if err != nil {
		l.Println(err.Error())
		return err.Error()
	}
	l.Println(stdout)

	return string(stdout)

}

// This validates that the user has purchased enough resources to provision a VM.
func ableToCreate(userToken string, ramSize int, cpuSize int, diskSize int) bool {

	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config-kvm.yml")
	yamlConfig, err := ioutil.ReadFile(filename)
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	// Get struct Values
	resourcesMax := maxResources{}
	resourcesUsed := usedResources{}

	// Execute the queries checking for the user's max resources
	//query := fmt.Sprintf("select max_vcpus, max_ram, max_block_storage from users where user_token = '%s'", userToken)
	rows, err := db.Query("SELECT max_vcpus, max_ram, max_block_storage FROM users WHERE user_token = ?", userToken)

	defer rows.Close()
	for rows.Next() {
		err = rows.Scan(&resourcesMax.vcpus, &resourcesMax.ram, &resourcesMax.storage)
		if err != nil {
			l.Println(err.Error())
			return false
		}
		l.Println(resourcesMax)
	}
	err = rows.Err()
	if err != nil {
		l.Println(err.Error())
		return false
	}
	rows.Close()

	// Execute the queries checking for the user's used resources
	//query = fmt.Sprintf("select used_vcpus, used_ram, used_block_storage from users where user_token = '%s'", userToken)
	rows, err = db.Query("SELECT used_vcpus, used_ram, used_block_storage FROM users WHERE user_token = ?", userToken)

	defer rows.Close()
	for rows.Next() {
		err = rows.Scan(&resourcesUsed.vcpus, &resourcesUsed.ram, &resourcesUsed.storage)
		if err != nil {
			l.Println(err.Error())
			return false
		}
		l.Println(resourcesUsed)
	}
	err = rows.Err()
	if err != nil {
		l.Println(err.Error())
		return false
	}
	rows.Close()

	var hasEnoughRam bool
	var hasEnoughCpus bool
	var hasEnoughStorage bool
	var hasEnoughResources bool

	if ramSize+resourcesUsed.ram > resourcesMax.ram {
		hasEnoughRam = false
		l.Println("Has enough RAM: false")
	} else if ramSize+resourcesUsed.ram < resourcesMax.ram {
		hasEnoughRam = true
		l.Println("Has enough RAM: true")
	}

	if cpuSize+resourcesUsed.vcpus > resourcesMax.vcpus {
		hasEnoughCpus = false
		l.Println("Has enough CPUs: false")
	} else if cpuSize+resourcesUsed.vcpus < resourcesMax.vcpus {
		hasEnoughCpus = true
		l.Println("Has enough CPUs: true")
	}

	if diskSize+resourcesUsed.storage > resourcesMax.storage {
		hasEnoughStorage = false
		l.Println("Has enough storage: false")
	} else if diskSize+resourcesUsed.storage < resourcesMax.storage {
		hasEnoughStorage = true
		l.Println("Has enough storage: true")
	}

	if (hasEnoughRam && hasEnoughCpus && hasEnoughStorage) == true {
		newRamSize := resourcesUsed.ram + ramSize
		newCpuSize := resourcesUsed.vcpus + cpuSize
		newStorageSize := resourcesUsed.storage + diskSize
		//query := fmt.Sprintf("UPDATE users SET used_ram = %d, used_vcpus = %d, used_block_storage = %d WHERE user_token = '%s'", newRamSize, newCpuSize, newStorageSize, userToken)
		//l.Printf("MySQL ==> %s\n", query)
		db.Exec("UPDATE users SET used_ram = ?, used_vcpus = ?, used_block_storage = ? WHERE user_token = ?", newRamSize, newCpuSize, newStorageSize, userToken)
		hasEnoughResources = true
	} else {
		hasEnoughResources = false
	}

	l.Println("--------------")
	l.Printf("Has enough RAM: %t\n", hasEnoughRam)
	l.Printf("Has enough CPUs: %t\n", hasEnoughCpus)
	l.Printf("Has enough storage: %t\n", hasEnoughStorage)
	l.Printf("Has enough total resources: %t\n", hasEnoughResources)
	return hasEnoughResources
}

// Create the VPS
func createDomain(w http.ResponseWriter, r *http.Request) {

	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config-kvm.yml")
	yamlConfig, err := ioutil.ReadFile(filename)

	if err != nil {
		l.Println(err.Error())
		return
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	// Decode JSON & assign the json value struct to a variable we can use here
	decoder := json.NewDecoder(r.Body)
	var t *createDomainStruct = &createDomainStruct{}

	// Set the maximum bytes able to be consumed by the API to prevent denial of service
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	// Decode the struct internally
	err = decoder.Decode(&t)
	if err != nil {
		l.Printf("Error parsing request body: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"Error": "CouldNotParseRequestBody"}`)
		return
	}

	switch {
	case t.RamSize == 0:
		l.Println("API did not send RAM size")
		w.WriteHeader(http.StatusPartialContent)
		w.Write([]byte(fmt.Sprintf("Error: Missing RAM size (GB)")))
		return
	case t.CpuSize == 0:
		l.Println("API did not send CPU size")
		w.Write([]byte(fmt.Sprintf("Error: Missing CPU size")))
		w.WriteHeader(http.StatusPartialContent)
		return
	case t.DiskSize == 0:
		l.Println("API did not send disk size")
		w.Write([]byte(fmt.Sprintf("Error: Missing disk size (GB)")))
		w.WriteHeader(http.StatusPartialContent)
		return
	case t.Username == "":
		l.Println("API did not send Username")
		w.Write([]byte(fmt.Sprintf("Error: Missing username")))
		w.WriteHeader(http.StatusPartialContent)
		return
	case t.UserEmail == "":
		l.Println("API did not send Email")
		w.Write([]byte(fmt.Sprintf("Error: Missing email address")))
		w.WriteHeader(http.StatusPartialContent)
		return
	case t.UserToken == "":
		l.Println("API did not send user token")
		w.Write([]byte(fmt.Sprintf("Error: Missing authentication token")))
		w.WriteHeader(http.StatusPartialContent)
		return
	case t.OperatingSystem == "":
		l.Println("API did not send operating system")
		w.WriteHeader(http.StatusPartialContent)
		w.Write([]byte(fmt.Sprintf("Error: Missing operating system")))
		return
	}
	var iso string
	switch t.OperatingSystem {
	case "rocky8.4":
		iso = ConfigFile.VolumePath + "isos/Rocky-8.4-x86_64-dvd1.iso"
	case "centos8.4":
		iso = ConfigFile.VolumePath + "isos/CentOS-8.4.2105-x86_64-dvd1.iso"
	case "netboot":
		iso = ConfigFile.VolumePath + "isos/netboot.xyz.iso"
	default:
		l.Printf("Invalid operating system requested by %s", r.RemoteAddr)
		fmt.Fprint(w, `{"Error": "InvalidOperatingSystem"}`)
		w.WriteHeader(http.StatusNotImplemented)
		return
	}

	// Validate the user's ability to create the VM.
	// If the user does not have enough resources purchased, the request will be denied.
	enoughUserResources := ableToCreate(t.UserToken, t.RamSize, t.CpuSize, t.DiskSize)
	if enoughUserResources == false {
		deniedString := fmt.Sprintf(`{"EnoughResources": "false"}`)
		l.Printf("%s\n", deniedString)
		return
	}

	l.Printf("[1/6] Request received! Provisioning VM...\n")
	l.Printf("RAM => %dGB\n", t.RamSize)
	l.Printf("vCPUs => %d\n", t.CpuSize)
	l.Printf("Disk Size => %dGB\n", t.DiskSize)
	l.Printf("Operating System => %s\n", t.OperatingSystem)
	l.Printf("User Email => %s\n", t.UserEmail)
	l.Printf("User ID => %d\n", t.UserID)
	l.Printf("Full Name => %s\n", t.FullName)
	l.Printf("Username => %s\n", t.Username)
	l.Printf("User Role => %s\n", t.UserRole)
	l.Printf("VM Creation Date: %s\n", t.CreationDate)

	// Set random ID
	rand.Seed(time.Now().UnixNano())
	randID := random(1, 99999999999)
	l.Printf("Random Domain ID: %d", randID)
	domainID := randID

	domainName := fmt.Sprintf("%s-VPS-%d", t.Username, domainID)

	// ConfigFile.VolumePath REQUIRES A TRAILING SLASH
	qcow2Name := fmt.Sprintf("%s%s", ConfigFile.VolumePath, domainName)
	qcow2Size := fmt.Sprintf("%d%s", t.DiskSize, "G")

	masterSecret := GenerateSecureToken(25)
	masterUUID := func() string {
		id := uuid.New()
		return id.String()
	}()

	// Provision VPS at specified location
	qcow2Args := []string{"create", "--object", "secret,id=sec0,data=" + masterSecret, "-f", "qcow2", "-o", "encrypt.format=luks,encrypt.key-secret=sec0", "-o", "preallocation=metadata", qcow2Name, qcow2Size}
	cmd := exec.Command("qemu-img", qcow2Args...)
	_, err = cmd.Output()
	if err != nil {
		l.Printf("[2/6] Error, VPS disk failed to provision: %s\n", err.Error())
		os.Remove(qcow2Name)
		return
	}
	l.Printf("[2/6] VPS disk successfully created!\n")

	// Change permissions of VPS disk so that qemu can interface with it over NFS
	err = os.Chmod(qcow2Name, 0600)
	if err != nil {
		l.Printf("[2.5/6] Error, changing permissions of VPS disk failed: %s\n", err.Error())
		return
	}
	qemuUser, err := user.Lookup("qemu")
	if err != nil {
		l.Printf("Error getting Qemu user: %s\n", err.Error())
	}
	qg, err := strconv.Atoi(qemuUser.Gid)
	if err != nil {
		l.Printf("Error getting Qemu group ID: %s\n")
	}
	qu, err := strconv.Atoi(qemuUser.Uid)
	if err != nil {
		l.Printf("Error getting qemu user ID: %s\n", err.Error())
	}
	err = os.Chown(qcow2Name, qu, qg)
	if err != nil {
		l.Printf("Error changing ownership of %s: %s\n", qcow2Name, err.Error())
	}
	// ALl the variables below set the pointers that libvirt-go can understand
	var macAddr = genMac()

	var ramConfMemory *libvirtxml.DomainMemory = &libvirtxml.DomainMemory{
		Unit:  "GiB",
		Value: uint(t.RamSize),
	}

	var ramConfCurrentMemory *libvirtxml.DomainCurrentMemory = &libvirtxml.DomainCurrentMemory{
		Value: uint(t.RamSize),
		Unit:  "GiB",
	}

	var cpuConfVCPU *libvirtxml.DomainVCPU = &libvirtxml.DomainVCPU{
		Current: uint(t.CpuSize),
		Value:   uint(t.CpuSize),
	}

	var confDomainOS *libvirtxml.DomainOS = &libvirtxml.DomainOS{
		Type: &libvirtxml.DomainOSType{
			Type:    "hvm",
			Machine: "pc-q35-rhel8.2.0",
			Arch:    "x86_64",
		},
		FirmwareInfo: &libvirtxml.DomainOSFirmwareInfo{
			Features: nil,
		},
		InitUser:  "root",
		InitGroup: "root",
		BootMenu: &libvirtxml.DomainBootMenu{
			Enable:  "yes",
			Timeout: "4000",
		},
		SMBios: &libvirtxml.DomainSMBios{
			Mode: "sysinfo",
		},
	}

	var confSysInfo = []libvirtxml.DomainSysInfo{
		libvirtxml.DomainSysInfo{
			SMBIOS: &libvirtxml.DomainSysInfoSMBIOS{
				BIOS: &libvirtxml.DomainSysInfoBIOS{
					Entry: []libvirtxml.DomainSysInfoEntry{
						libvirtxml.DomainSysInfoEntry{
							Name:  "vendor",
							Value: ConfigFile.Manufacturer,
						},
					},
				},
				System: &libvirtxml.DomainSysInfoSystem{
					Entry: []libvirtxml.DomainSysInfoEntry{
						libvirtxml.DomainSysInfoEntry{
							Name:  "manufacturer",
							Value: ConfigFile.Manufacturer,
						},
						libvirtxml.DomainSysInfoEntry{
							Name:  "product",
							Value: "HPC VPS",
						},
						libvirtxml.DomainSysInfoEntry{
							Name:  "version",
							Value: "v4.8.1",
						},
					},
				},
				BaseBoard: []libvirtxml.DomainSysInfoBaseBoard{
					libvirtxml.DomainSysInfoBaseBoard{
						Entry: []libvirtxml.DomainSysInfoEntry{
							libvirtxml.DomainSysInfoEntry{
								Name:  "manufacturer",
								Value: ConfigFile.Manufacturer,
							},
							libvirtxml.DomainSysInfoEntry{
								Name:  "product",
								Value: "HPC VPS",
							},
							libvirtxml.DomainSysInfoEntry{
								Name:  "version",
								Value: "v4.8.1",
							},
						},
					},
				},
				Chassis: &libvirtxml.DomainSysInfoChassis{
					Entry: []libvirtxml.DomainSysInfoEntry{
						libvirtxml.DomainSysInfoEntry{
							Name:  "manufacturer",
							Value: ConfigFile.Manufacturer,
						},
						libvirtxml.DomainSysInfoEntry{
							Name:  "version",
							Value: "v4.8.1",
						},
						libvirtxml.DomainSysInfoEntry{
							Name:  "sku",
							Value: ConfigFile.Manufacturer,
						},
					},
				},
				Processor: []libvirtxml.DomainSysInfoProcessor{
					libvirtxml.DomainSysInfoProcessor{
						Entry: []libvirtxml.DomainSysInfoEntry{
							libvirtxml.DomainSysInfoEntry{
								Name:  "manufacturer",
								Value: ConfigFile.Manufacturer,
							},
						},
					},
				},
			},
		},
	}

	var confCPUType *libvirtxml.DomainCPU = &libvirtxml.DomainCPU{
		Mode:       "host-passthrough",
		Migratable: "on",
		Check:      "none",
		Topology: &libvirtxml.DomainCPUTopology{
			Sockets: 2,
			Cores:   t.CpuSize / 2,
			Threads: 1,
		},
		Cache: &libvirtxml.DomainCPUCache{
			Level: 3,
			Mode:  "emulate",
		},
	}

	var confClock *libvirtxml.DomainClock = &libvirtxml.DomainClock{
		TimeZone: "utc",
	}

	// Generate outbound/inbound peak in kilobytes from megabits per second
	var outboundPeak int = ConfigFile.DomainBandwidth * 1000

	// Check input values for sanity (GammaByte.xyz Specific)

	var confDevices *libvirtxml.DomainDeviceList = &libvirtxml.DomainDeviceList{
		Channels: []libvirtxml.DomainChannel{
			libvirtxml.DomainChannel{
				Source: &libvirtxml.DomainChardevSource{
					UNIX: &libvirtxml.DomainChardevSourceUNIX{
						Mode:      "",
						Path:      "",
						Reconnect: nil,
						SecLabel: []libvirtxml.DomainDeviceSecLabel{
							libvirtxml.DomainDeviceSecLabel{
								Model: "selinux",
								Label: "dynamic",
							},
						},
					},
				},
				Protocol: &libvirtxml.DomainChardevProtocol{
					Type: "unix",
				},
				Target: &libvirtxml.DomainChannelTarget{
					VirtIO: &libvirtxml.DomainChannelTargetVirtIO{
						Name: "org.qemu.guest_agent.0",
					},
				},
			},
		},
		Disks: []libvirtxml.DomainDisk{
			libvirtxml.DomainDisk{
				Device: "cdrom",
				Driver: &libvirtxml.DomainDiskDriver{
					Name: "qemu",
					Type: "raw",
				},
				Source: &libvirtxml.DomainDiskSource{
					File: &libvirtxml.DomainDiskSourceFile{
						File: iso,
					},
				},
				Target: &libvirtxml.DomainDiskTarget{
					Dev: "vdb",
					Bus: "sata",
				},
				Boot: &libvirtxml.DomainDeviceBoot{
					Order: 2,
				},
			},
			libvirtxml.DomainDisk{
				Driver: &libvirtxml.DomainDiskDriver{
					Type:        "qcow2",
					Cache:       "directsync",
					ErrorPolicy: "stop",
					IO:          "native",
					DetectZeros: "unmap",
				},
				Source: &libvirtxml.DomainDiskSource{
					File: &libvirtxml.DomainDiskSourceFile{
						File:     fmt.Sprintf("%s%s", ConfigFile.VolumePath, domainName),
						SecLabel: nil,
					},
					Encryption: &libvirtxml.DomainDiskEncryption{
						Format: "luks",
						Secret: &libvirtxml.DomainDiskSecret{
							Type: "passphrase",
							UUID: masterUUID,
						},
					},
				},
				BlockIO: &libvirtxml.DomainDiskBlockIO{
					LogicalBlockSize:  512,
					PhysicalBlockSize: 8192,
				},
				Target: &libvirtxml.DomainDiskTarget{
					Dev: "vda",
					Bus: "virtio",
				},
				IOTune: &libvirtxml.DomainDiskIOTune{
					ReadBytesSec:  146800640,
					WriteBytesSec: 89128960,
				},
				/*Encryption: &libvirtxml.DomainDiskEncryption{
					Format: "luks",
					Secret: &libvirtxml.DomainDiskSecret{
						Type: "passphrase",
						UUID: masterSecret,
					},
				},*/
				Boot: &libvirtxml.DomainDeviceBoot{
					Order: 1,
				},
				Alias: &libvirtxml.DomainAlias{
					Name: domainName,
				},
			},
		},
		Interfaces: []libvirtxml.DomainInterface{
			libvirtxml.DomainInterface{
				MAC: &libvirtxml.DomainInterfaceMAC{
					Address: macAddr,
				},
				Source: &libvirtxml.DomainInterfaceSource{
					Network: &libvirtxml.DomainInterfaceSourceNetwork{
						Network: "default",
					},
				},
				Model: &libvirtxml.DomainInterfaceModel{
					Type: "virtio",
				},
				FilterRef: &libvirtxml.DomainInterfaceFilterRef{
					Filter: "no-localnet",
				},
				Bandwidth: &libvirtxml.DomainInterfaceBandwidth{
					Outbound: &libvirtxml.DomainInterfaceBandwidthParams{
						Peak:    &outboundPeak,
						Average: &outboundPeak,
						Burst:   &outboundPeak,
					},
					Inbound: &libvirtxml.DomainInterfaceBandwidthParams{
						Peak:    &outboundPeak,
						Average: &outboundPeak,
						Burst:   &outboundPeak,
					},
				},
			},
		},
		Graphics: []libvirtxml.DomainGraphic{
			libvirtxml.DomainGraphic{
				VNC: &libvirtxml.DomainGraphicVNC{
					AutoPort:    "yes",
					SharePolicy: "ignore",
					Listen:      "0.0.0.0",
				},
			},
		},
		Videos: []libvirtxml.DomainVideo{
			libvirtxml.DomainVideo{
				Model: libvirtxml.DomainVideoModel{
					Type: "qxl",
				},
			},
		},
	}

	secretConfig := &libvirtxml.Secret{
		Ephemeral:   "no",
		Private:     "yes",
		Description: fmt.Sprintf("Encryption for domain: %s", domainName),
		UUID:        masterUUID,
		Usage: &libvirtxml.SecretUsage{
			Type:   "volume",
			Volume: ConfigFile.VolumePath + domainName,
			Name:   domainName,
		},
	}

	// Assign the variables shown above to the domcfg var, which is of the type "&libvirtxml.domain"
	domcfg := &libvirtxml.Domain{
		XMLName:       xml.Name{},
		Type:          "kvm",
		ID:            &domainID,
		Name:          domainName,
		Title:         domainName,
		Description:   domainName,
		Memory:        ramConfMemory,
		CurrentMemory: ramConfCurrentMemory,
		VCPU:          cpuConfVCPU,
		IOThreads:     6,
		SysInfo:       confSysInfo,
		OS:            confDomainOS,
		CPU:           confCPUType,
		Clock:         confClock,
		OnPoweroff:    "destroy",
		OnReboot:      "restart",
		OnCrash:       "restart",
		Devices:       confDevices,
	}

	// Parse the values into human readable XML
	xmldoc, err := domcfg.Marshal()
	if err != nil {
		l.Printf("Failed to parse generated XML buffer into readable output. Exiting.\n")
		l.Printf("Err --> %s\n", err.Error())
		os.Remove(qcow2Name)
		return
	}

	// Connect to qemu-kvm
	conn, err := libvirt.NewConnect("qemu:///system?socket=/var/run/libvirt/libvirt-sock")
	if err != nil {
		l.Printf("Failed! \nReason: %s\n", err.Error())
		l.Printf("Failed to connect to qemu.n\n")
		os.Remove(qcow2Name)
		return
	} else {
		l.Printf("[3/6] Successfully connected to QEMU-KVM!\n")

	}
	defer conn.Close()

	// Finally, define the VPS
	dom, err := conn.DomainDefineXML(xmldoc)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		os.Remove(qcow2Name)
		l.Println(dom)
		return
	} else {
		l.Printf("[4/6] Successfully defined new VPS!\n")
	}

	xmldocSecret, err := secretConfig.Marshal()
	secretXml, err := conn.SecretDefineXML(xmldocSecret, 0)
	if err != nil {
		l.Printf("Error defining secret XML: %s\n", err.Error())
		err := os.Remove(qcow2Name)
		if err != nil {
			return
		}
		l.Println(secretXml)
		return
	}
	l.Printf("[5/6] Successfully defined encryption configuration!")

	err = secretXml.SetValue([]byte(masterSecret), 0)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		return
	}

	// Enable autostart
	err = dom.SetAutostart(true)
	if err != nil {
		l.Printf("Error enabling autostart: %s\n", err.Error())
	}
	// Start the VPS now
	err = dom.Create()
	if err != nil {
		l.Printf("Error starting domain: %s\n", err.Error())
	}
	l.Printf("[6/6] Successfully started VPS!\n")
	l.Printf("VPS Name: %s\n", domainName)
	l.Printf("VPS MAC Address: %s\n", macAddr)

	domIP := setIP(t.Network, macAddr, domainName, qcow2Name, t.UserEmail, t.FullName, t.Username, t.UserToken, t.RamSize, t.CpuSize, t.DiskSize, masterSecret)
	if domIP == "" {
		l.Println("Could not assign local IP to VM")
		return
	}
	l.Printf("VPS IP: %s\n", domIP)
	_, err = fmt.Fprintf(w, `{"Status": "Success", "DomainName": "%s", "DomainID": %d, "MacAddress": "%s"}`, domainName, domainID, macAddr)
	if err != nil {
		l.Printf("Error writing data back to client: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

}

type domainNetworkDomainName struct {
	DomainName string `json:"DomainName"`
	Details    domainNetworks
}

// Write values to JSON file with this data struct
type domainNetworks struct {
	NetworkName string `json:"NetworkName"`
	MacAddress  string `json:"MacAddress"`
	IpAddress   string `json:"IpAddress"`
}

type dbValues struct {
	DomainName   string
	NetworkName  string
	MacAddress   string
	IpAddress    string
	DiskPath     string
	TimeCreated  string
	UserEmail    string
	UserFullName string
	UserName     string
	UserToken    string
	Ram          int
	Vcpus        int
	Storage      int
}

// Set the IP address of the VM based on the MAC
func setIP(network string, macAddr string, domainName string, qcow2Name string, userEmail string, userFullName string, userName string, userToken string, domainRam int, domainCpus int, domainStorage int, diskSecret string) string {

	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config-kvm.yml")
	yamlConfig, err := ioutil.ReadFile(filename)
	if err != nil {
		l.Printf("Error reading config file: %s\n", err.Error())
		return ""
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	// Connect to Qemu
	conn, err := libvirt.NewConnect("qemu:///system?socket=/var/run/libvirt/libvirt-sock")
	if err != nil {
		l.Printf("Failed to connect to qemu: %s\n", err.Error())
		return ""
	}
	defer conn.Close()

	net, err := conn.LookupNetworkByName(network)
	l.Printf("Network: %s\n", network)
	if err != nil {
		l.Printf("Error: Could not find network %s: %s\n", network, err.Error())
		return ""
	}
	leases, err := net.GetDHCPLeases()
	if err != nil {
		l.Printf("Error: Could not get leases: %s\n", err.Error())
		return ""
	}

	ipMap := map[string]struct{}{}

	var i int
	for _, lease := range leases {
		ipMap[lease.IPaddr] = struct{}{}
		i++
		if i > 256 {
			l.Println("Error: Could not find IPv4 to allocate.")
			return ""
		}
	}

	rand.Seed(time.Now().Unix())
	//randIP := fmt.Sprintf("%d.%d.%d.%d", 192, 168, 2, rand.Intn(254))
	randIP := fmt.Sprintf("%s.%d", ConfigFile.Subnet, rand.Intn(254))

	_, exists := ipMap[randIP]
	l.Printf("  IP Exists: %t\n", exists)
	l.Printf("  Random IP: %s\n\n", randIP)

	if exists == false {
		dhLease := &libvirtxml.NetworkDHCPHost{
			MAC:  macAddr,
			Name: domainName,
			IP:   randIP,
		}
		dhSection := libvirt.NetworkUpdateSection(4)

		var dhLeaseString, _ = xml.Marshal(dhLease)
		l.Printf("Inserted network info: %s\n\n", dhLeaseString)

		netUpdateFlags0 := libvirt.NetworkUpdateFlags(0)

		// This one only updates the live state of the network, which is not what we want. We want persistent AND live updates
		//netUpdateFlags1 := libvirt.NetworkUpdateFlags(1)

		netUpdateFlags2 := libvirt.NetworkUpdateFlags(2)

		net.Update(libvirt.NETWORK_UPDATE_COMMAND_ADD_LAST, dhSection, -1, string(dhLeaseString), netUpdateFlags0)

		// This one only updates the live state of the network, which is not what we want. We want persistent AND live updates
		//net.Update(libvirt.NETWORK_UPDATE_COMMAND_ADD_LAST, dhSection, -1, string(dhLeaseString), netUpdateFlags1)

		net.Update(libvirt.NETWORK_UPDATE_COMMAND_ADD_LAST, dhSection, -1, string(dhLeaseString), netUpdateFlags2)
		if err != nil {
			l.Printf("Failed to update network: %s\n", err.Error())
			return ""
		}

	} else if exists == true {
		setIP(network, macAddr, domainName, qcow2Name, userEmail, userFullName, userName, userToken, domainRam, domainCpus, domainStorage, diskSecret)
	}

	// Get hostname
	hostname, err := fqdn.FqdnHostname()

	// Get the current date/time
	dt := time.Now()
	// Generate the insert string
	//insertData := fmt.Sprintf("INSERT INTO domaininfo (domain_name, network, mac_address, ram, vcpus, storage, ip_address, disk_path, time_created, user_email, user_full_name, username, user_token, host_binding) VALUES ('%s', '%s', '%s', '%d', '%d', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')", domainName, network, macAddr, domainRam, domainCpus, domainStorage, randIP, qcow2Name, dt.String(), userEmail, userFullName, userName, userToken, hostname)
	//l.Printf("MySQL ==> %s\n\n", insertData)

	_, err = db.Exec("INSERT INTO domaininfo (domain_name, network, mac_address, ram, vcpus, storage, ip_address, disk_path, time_created, user_email, user_full_name, username, user_token, host_binding, disk_secret) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", domainName, network, macAddr, domainRam, domainCpus, domainStorage, randIP, qcow2Name, dt.String(), userEmail, userFullName, userName, userToken, hostname, diskSecret)
	if err != nil {
		l.Printf("Error inserting new domain info values: %s\n", err.Error())
		return ""
	}

	return randIP
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func checkFile(filename string) error {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		_, err := os.Create(filename)
		if err != nil {
			return err
		}
	}
	return nil
}

// Get the existing domains and print them
func getDomains(w http.ResponseWriter, r *http.Request) {
	// Read the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config-kvm.yml")
	yamlConfig, err := ioutil.ReadFile(filename)

	// Parse the config file
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	conn, err := libvirt.NewConnect("qemu:///system?socket=/var/run/libvirt/libvirt-sock")
	if err != nil {
		l.Println("failed to connect to qemu")
		return
	}
	defer conn.Close()

	doms, err := conn.ListAllDomains(libvirt.CONNECT_LIST_DOMAINS_ACTIVE)

	l.Printf("All VMs:\n")
	fmt.Fprintf(w, "All VMs:\n")
	for _, dom := range doms {
		name, err := dom.GetName()
		if err == nil {
			l.Printf("  %s\n", name)
			fmt.Fprintf(w, "  %s\n", name)
		}
		dom.Free()
	}

	// Execute MySQL Query to get all managed VMs
	//query := `SELECT domain_name FROM domaininfo`
	dbVars, err := db.Query("SELECT domain_name FROM domaininfo")
	if err != nil {
		l.Println("Could not get domains from MySQL.")
	}

	l.Printf("All LibStatsAPI Managed VMs:\n")
	fmt.Fprintf(w, "All LibStatsAPI Managed VMs:\n")
	var d dbValues
	var totalLsapiVMs int
	for dbVars.Next() {
		err := dbVars.Scan(&d.DomainName)
		totalLsapiVMs = totalLsapiVMs + 1
		if err != nil {
			l.Println(err)
		}
		fmt.Fprintf(w, "  %s\n", d.DomainName)
		l.Printf("  %s\n", d.DomainName)
	}

	l.Printf("\nTotal VMs: %d\n", len(doms))
	fmt.Fprintf(w, "\nTotal VMs: %d\n", len(doms))
	l.Printf("Total LibStatsAPI Managed VMs: %d\n", totalLsapiVMs)
	fmt.Fprintf(w, "total LibStatsAPI Managed VMs: %d\n", totalLsapiVMs)
}

// Delete domain based on values
type deleteDomainStruct struct {
	VpsName       string `json:"DomainName"`
	Token         string `json:"Token"`
	UserEmail     string `json:"Email"`
	RetainImage   string `json:"RetainImage"`
	EncryptBackup string `json:"EncryptBackup"`
	MatchKey      string `json:"MatchKey"`
}

func DeleteMatchingDomains(w http.ResponseWriter, r *http.Request) {
	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config-kvm.yml")
	yamlConfig, err := ioutil.ReadFile(filename)

	if err != nil {
		l.Println(err.Error())
		return
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)
	if err != nil {
		l.Println(err.Error())
		return
	}

	// Create a new decoder
	decoder := json.NewDecoder(r.Body)
	var t *deleteDomainStruct = &deleteDomainStruct{}

	// Set the maximum bytes able to be consumed by the API to prevent denial of service
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	// Decode the struct internally
	err = decoder.Decode(&t)
	if err != nil {
		l.Println(err.Error())
		return
	}
	if t.MatchKey == "" {
		fmt.Fprintf(w, "{\"Missing\": \"MatchKey\"}\n")
		l.Println("Request missing MatchKey field.")
		return
	} else if t.Token == "" {
		fmt.Fprintf(w, "{\"Missing\": \"Token\"}\n")
		l.Println("Request missing Token field.")
		return
	} else if t.UserEmail == "" {
		fmt.Fprintf(w, "{\"Missing\": \"Email\"}\n")
		l.Println("Request missing Email field.")
		return
	}
	// Connect to Qemu-KVM/Libvirt
	conn, err := libvirt.NewConnect("qemu:///system?socket=/var/run/libvirt/libvirt-sock")
	if err != nil {
		l.Println("Failed to connect to qemu")
	}
	defer conn.Close()
	l.Printf("Removing domains with string matching: %s\n", t.MatchKey)

	rows, err := db.Query("SELECT domain_name FROM domaininfo WHERE user_email = ? AND domain_name LIKE ?", t.UserEmail, "%"+t.MatchKey+"%")
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		return
	}

	var fullDomainName string
	for rows.Next() {
		err = rows.Scan(&fullDomainName)
		if err != nil {
			l.Printf("Error scanning value into variable: %s\n", err.Error())
			continue
		}
		if verifyOwnership(t.Token, fullDomainName, t.UserEmail) != true {
			l.Printf("User with email %s requested unauthorized access to %s.", t.UserEmail, fullDomainName)
			continue
		}

		if fullDomainName == "" {
			continue
		}
		l.Printf("Looking up domain %s...\n", fullDomainName)
		domain, err := conn.LookupDomainByName(fullDomainName)
		if err != nil {
			l.Printf("Error looking up domain: %s\n", err.Error())
			continue
		}
		_ = domain.Destroy()

		var d dbValues
		//queryData := fmt.Sprintf("SELECT domain_name, ip_address, mac_address, ram, vcpus, storage, network, disk_path, time_created, user_email, user_full_name, username FROM domaininfo WHERE domain_name ='%s'", t.VpsName)
		//l.Println(queryData)
		err = db.QueryRow("SELECT domain_name, ip_address, mac_address, ram, vcpus, storage, network, disk_path, time_created, user_email, user_full_name, username FROM domaininfo WHERE domain_name = ?", fullDomainName).Scan(&d.DomainName, &d.IpAddress, &d.MacAddress, &d.Ram, &d.Vcpus, &d.Storage, &d.NetworkName, &d.DiskPath, &d.TimeCreated, &d.UserEmail, &d.UserFullName, &d.UserName)
		//l.Printf("Domain name: %s\n Ip Address: %s\n Mac Address: %s\n RAM: %dGB\n vCPUS: %d\n Storage: %dGB\n Network Name: %s\n Disk Path: %s\n Date Created: %s\n User Email: %s\n User's Full Name: %s\n Username: %s\n", d.DomainName, d.IpAddress, d.MacAddress, d.Ram, d.Vcpus, d.Storage, d.NetworkName, d.DiskPath, d.TimeCreated, d.UserEmail, d.UserFullName, d.UserName)
		if err != nil {
			l.Println(err.Error())
			return
		}

		var deleteImage bool
		if t.RetainImage == "true" {
			l.Printf("Sending file %s to API...", d.DiskPath)
			fmt.Fprintf(w, "{\"Status\": \"SendingImageToAPI\", \"DomainName\": \"%s\"}\n", fullDomainName)
			go func() {
				var imageSecret string
				l.Println("Retrieving image secret...")
				err = db.QueryRow("SELECT disk_secret FROM domaininfo WHERE domain_name = ?", fullDomainName).Scan(&imageSecret)
				if err != nil {
					l.Printf("Error getting image secret: %s\n", err.Error())
				}

				err, ImageURI := sendFile(d.DiskPath, fullDomainName, t.EncryptBackup, imageSecret)
				if err != nil {
					l.Printf("Error: %s\n", err.Error())
					return
				}

				l.Printf("Generated image URI: %s\n", ImageURI)

				notifyUser(ImageURI, d.UserEmail, imageSecret, fullDomainName)
				res, err := db.Exec("DELETE FROM domaininfo WHERE domain_name = ?", fullDomainName)
				if err != nil {
					l.Fatalf("Failed to remove row from DB.\n %s\n %s\n", err.Error(), res)
				} else {
					l.Printf("Successfully removed domain %s from MySQL database.\n", fullDomainName)
				}
			}()
			deleteImage = false
		} else {
			deleteImage = true
		}

		dhSection := libvirt.NetworkUpdateSection(4)

		dhLeaseString := fmt.Sprintf("<host mac='%s'/>", d.MacAddress)
		l.Printf("XML to query and delete from network %s: %s\n", d.NetworkName, dhLeaseString)

		netUpdateFlags0 := libvirt.NetworkUpdateFlags(0)

		// This one only updates the live state of the network, which is not what we want. We want persistent AND live updates
		// netUpdateFlags1 := libvirt.NetworkUpdateFlags(1)

		netUpdateFlags2 := libvirt.NetworkUpdateFlags(2)

		net, err := conn.LookupNetworkByName(d.NetworkName)
		if err != nil {
			l.Printf("Could could find network %s\n", d.NetworkName)
			return
		} else {
			l.Printf("Successfully queried network %s\n", d.NetworkName)
		}

		err = net.Update(libvirt.NETWORK_UPDATE_COMMAND_DELETE, dhSection, -1, string(dhLeaseString), netUpdateFlags0)
		if err != nil {
			l.Printf("Failed to update network. Error: \n%s\n", err.Error())
		} else {
			l.Printf("Successfully updated the live state of network %s\n", d.NetworkName)
		}

		// This one only updates the live state of the network, which is not what we want. We want persistent AND live updates
		/* err = net.Update(libvirt.NETWORK_UPDATE_COMMAND_ADD_LAST, dhSection, -1, string(dhLeaseString), netUpdateFlags1)
		if err != nil {
			l.Printf("Failed to check live network. Error: \n%s\n", err)
			fmt.Fprintf(w, "Failed to check live network. Error: \n  %s\n", err)
		} else {
			l.Printf("Successfully checked the update status on the live network.\n")
			fmt.Fprintf(w, "Succesfully checked the update status on the live network.\n")
		} */

		err = net.Update(libvirt.NETWORK_UPDATE_COMMAND_DELETE, dhSection, -1, string(dhLeaseString), netUpdateFlags2)
		if err != nil {
			l.Printf("Failed to update network. Error: \n%s\n", err.Error())
		} else {
			l.Printf("Successfully updated the persistent network.")
		}

		e := domain.Undefine()
		if e != nil {
			l.Printf("Error undefining the domain %s\n.", fullDomainName)
		} else {
			l.Printf("Domain %s was undefined successfully.\n", fullDomainName)
		}

		if deleteImage == true {
			e = os.Remove(d.DiskPath)
			if e != nil {
				l.Printf("Domain disk (%s) has failed to purge.\n", d.DiskPath)
				l.Println(e)
			}
			stillExists := fileExists(d.DiskPath)
			if stillExists == true {
				l.Printf("Domain disk (%s) failed to purge.")
			} else {
				l.Printf("Domain disk (%s) was successfully wiped & purged.\n", d.DiskPath)
			}
		}
		if deleteImage == true {
			res, err := db.Exec("DELETE FROM domaininfo WHERE domain_name = ?", fullDomainName)
			if err != nil {
				l.Fatalf("Failed to remove row from DB.\n %s\n %s\n", err.Error(), res)
			} else {
				l.Printf("Successfully removed domain %s from MySQL database.\n", fullDomainName)
			}
		}

		fmt.Fprintf(w, "{\"Removed\": \"%s\"}\n", fullDomainName)

		var resources struct {
			usedVcpus   int
			usedRam     int
			usedStorage int
		}
		var r = resources
		err = db.QueryRow("SELECT used_vcpus, used_ram, used_block_storage FROM users WHERE email_address = ? AND user_token = ?", t.UserEmail, t.Token).Scan(&r.usedVcpus, &r.usedRam, &r.usedStorage)
		if err != nil {
			l.Printf("Error getting used resources for user: %s\n", err.Error())
		}
		_, err = db.Exec("UPDATE users SET used_vcpus = ?, used_ram = ?, used_block_storage = ? WHERE email_address = ? AND user_token = ?", r.usedVcpus-d.Vcpus, r.usedRam-d.Ram, r.usedStorage-d.Storage, t.UserEmail, t.Token)
		if err != nil {
			l.Printf("Error updating used resources for user: %s\n", err.Error())
		}

	}

}

func deleteDomain(w http.ResponseWriter, r *http.Request) {
	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config-kvm.yml")
	yamlConfig, err := ioutil.ReadFile(filename)

	if err != nil {
		l.Println(err.Error())
		return
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)
	if err != nil {
		l.Println(err.Error())
		return
	}

	// Create a new decoder
	decoder := json.NewDecoder(r.Body)
	var t *deleteDomainStruct = &deleteDomainStruct{}

	// Set the maximum bytes able to be consumed by the API to prevent denial of service
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	// Decode the struct internally
	err = decoder.Decode(&t)
	if err != nil {
		l.Println(err.Error())
		return
	}
	if t.VpsName == "" {
		fmt.Fprintf(w, "{\"Missing\": \"DomainName\"}\n")
		l.Println("Request missing DomainName field.")
		return
	} else if t.Token == "" {
		fmt.Fprintf(w, "{\"Missing\": \"Token\"}\n")
		l.Println("Request missing Token field.")
		return
	} else if t.UserEmail == "" {
		fmt.Fprintf(w, "{\"Missing\": \"Email\"}\n")
		l.Println("Request missing Email field.")
		return
	}

	// Connect to Qemu-KVM/Libvirt
	conn, err := libvirt.NewConnect("qemu:///system?socket=/var/run/libvirt/libvirt-sock")
	if err != nil {
		l.Println("Failed to connect to qemu")
	}
	defer conn.Close()

	if verifyOwnership(t.Token, t.VpsName, t.UserEmail) != true {
		fmt.Fprintf(w, "{\"Unauthorized\": \"true\"}\n")
		l.Printf("User with email %s requested unauthorized access to %s.", t.UserEmail, t.VpsName)
		return
	}

	// Check to see if the VPS name has been defined. If not, notify endpoint & exit.
	if t.VpsName != "" {
		l.Printf("Got request to remove domain: %s\n", t.VpsName)
		domain, _ := conn.LookupDomainByName(t.VpsName)
		fmt.Fprintf(w, "Domain to delete: %s\n", t.VpsName)

		var d dbValues
		//queryData := fmt.Sprintf("SELECT domain_name, ip_address, mac_address, ram, vcpus, storage, network, disk_path, time_created, user_email, user_full_name, username FROM domaininfo WHERE domain_name ='%s'", t.VpsName)
		//l.Println(queryData)
		err = db.QueryRow("SELECT domain_name, ip_address, mac_address, ram, vcpus, storage, network, disk_path, time_created, user_email, user_full_name, username FROM domaininfo WHERE domain_name = ?", t.VpsName).Scan(&d.DomainName, &d.IpAddress, &d.MacAddress, &d.Ram, &d.Vcpus, &d.Storage, &d.NetworkName, &d.DiskPath, &d.TimeCreated, &d.UserEmail, &d.UserFullName, &d.UserName)
		l.Printf("Domain name: %s\n Ip Address: %s\n Mac Address: %s\n RAM: %dGB\n vCPUS: %d\n Storage: %dGB\n Network Name: %s\n Disk Path: %s\n Date Created: %s\n User Email: %s\n User's Full Name: %s\n Username: %s\n", d.DomainName, d.IpAddress, d.MacAddress, d.Ram, d.Vcpus, d.Storage, d.NetworkName, d.DiskPath, d.TimeCreated, d.UserEmail, d.UserFullName, d.UserName)
		if err != nil {
			l.Println(err.Error())
			return
		}

		err := domain.Destroy()
		if err != nil {
			l.Printf("Error destroying domain: %s\n", err.Error())
		}
		var deleteImage bool
		if t.RetainImage == "true" {
			l.Printf("Sending file %s to API...", d.DiskPath)
			fmt.Fprintf(w, "{\"Status\": \"SendingImageToAPI\"}\n")
			go func() {
				var imageSecret string
				l.Println("Retrieving image secret...")
				err = db.QueryRow("SELECT disk_secret FROM domaininfo WHERE domain_name = ?", d.DomainName).Scan(&imageSecret)
				if err != nil {
					l.Printf("Error getting image secret: %s\n", err.Error())
				}

				err, ImageURI := sendFile(d.DiskPath, d.DomainName, t.EncryptBackup, imageSecret)
				if err != nil {
					l.Printf("Error: %s\n", err.Error())
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				l.Printf("Generated image URI: %s\n", ImageURI)

				notifyUser(ImageURI, d.UserEmail, imageSecret, t.VpsName)
				res, err := db.Exec("DELETE FROM domaininfo WHERE domain_name = ?", t.VpsName)
				if err != nil {
					l.Printf("Failed to remove row from DB.\n %s\n %s\n", err.Error(), res)
				} else {
					l.Printf("Successfully removed domain %s from MySQL database.\n", t.VpsName)
				}
			}()
			deleteImage = false
		} else {
			deleteImage = true
		}

		dhSection := libvirt.NetworkUpdateSection(4)

		dhLeaseString := fmt.Sprintf("<host mac='%s'/>", d.MacAddress)
		l.Printf("XML to query and delete from network %s: %s\n", d.NetworkName, dhLeaseString)

		netUpdateFlags0 := libvirt.NetworkUpdateFlags(0)

		// This one only updates the live state of the network, which is not what we want. We want persistent AND live updates
		// netUpdateFlags1 := libvirt.NetworkUpdateFlags(1)

		netUpdateFlags2 := libvirt.NetworkUpdateFlags(2)

		net, err := conn.LookupNetworkByName(d.NetworkName)
		if err != nil {
			fmt.Fprintf(w, "Could not find network %s\n", d.NetworkName)
			l.Printf("Could could find network %s\n", d.NetworkName)
			return
		} else {
			fmt.Fprintf(w, "Successfully queried network %s\n", d.NetworkName)
			l.Printf("Successfully queried network %s\n", d.NetworkName)
		}

		err = net.Update(libvirt.NETWORK_UPDATE_COMMAND_DELETE, dhSection, -1, string(dhLeaseString), netUpdateFlags0)
		if err != nil {
			l.Printf("Failed to update network. Error: \n%s\n", err.Error())
			fmt.Fprintf(w, "Failed to update network. Error: \n  %s\n", err.Error())
		} else {
			l.Printf("Successfully updated the live state of network %s\n", d.NetworkName)
			fmt.Fprintf(w, "Successfully updated the live state of network %s\n", d.NetworkName)
		}

		// This one only updates the live state of the network, which is not what we want. We want persistent AND live updates
		/* err = net.Update(libvirt.NETWORK_UPDATE_COMMAND_ADD_LAST, dhSection, -1, string(dhLeaseString), netUpdateFlags1)
		if err != nil {
			l.Printf("Failed to check live network. Error: \n%s\n", err)
			fmt.Fprintf(w, "Failed to check live network. Error: \n  %s\n", err)
		} else {
			l.Printf("Successfully checked the update status on the live network.\n")
			fmt.Fprintf(w, "Succesfully checked the update status on the live network.\n")
		} */

		err = net.Update(libvirt.NETWORK_UPDATE_COMMAND_DELETE, dhSection, -1, string(dhLeaseString), netUpdateFlags2)
		if err != nil {
			l.Printf("Failed to update network. Error: \n%s\n", err.Error())
			fmt.Fprintf(w, "Failed to update network. Error: \n  %s\n", err.Error())
		} else {
			l.Printf("Successfully updated the persistent network.")
			fmt.Fprintf(w, "Successfully updated the persistent network.")
		}

		e := domain.Undefine()
		if e != nil {
			fmt.Fprintf(w, "Error undefining the domain %s\n.", t.VpsName)
			l.Printf("Error undefining the domain %s\n.", t.VpsName)
		} else {
			fmt.Fprintf(w, "Domain %s was undefined successfully.\n", t.VpsName)
			l.Printf("Domain %s was undefined successfully.\n", t.VpsName)
		}

		if deleteImage == true {
			e = os.Remove(d.DiskPath)
			if e != nil {
				fmt.Fprintf(w, "Domain disk (%s) has failed to purge.\n", d.DiskPath)
				l.Printf("Domain disk (%s) has failed to purge.\n", d.DiskPath)
				l.Println(e)
			}
			stillExists := fileExists(d.DiskPath)
			if stillExists == true {
				l.Printf("Domain disk (%s) failed to purge.")
				fmt.Fprintf(w, "Domain disk (%s) failed to purge.\n", d.DiskPath)
			} else {
				fmt.Fprintf(w, "Domain disk (%s) was successfully wiped & purged.\n", d.DiskPath)
				l.Printf("Domain disk (%s) was successfully wiped & purged.\n", d.DiskPath)
			}
		}
		if deleteImage == true {
			res, err := db.Exec("DELETE FROM domaininfo WHERE domain_name = ?", t.VpsName)
			if err != nil {
				fmt.Fprintf(w, "Failed to remove row from DB.\n %s\n %s\n", err, res)
				l.Fatalf("Failed to remove row from DB.\n %s\n %s\n", err.Error(), res)
			} else {
				fmt.Fprintf(w, "Successfully removed domain %s from MySQL database.\n", t.VpsName)
				l.Printf("Successfully removed domain %s from MySQL database.\n", t.VpsName)
			}
		}

		var resources struct {
			usedVcpus   int
			usedRam     int
			usedStorage int
		}
		var r = resources
		err = db.QueryRow("SELECT used_vcpus, used_ram, used_block_storage FROM users WHERE email_address = ? AND user_token = ?", t.UserEmail, t.Token).Scan(&r.usedVcpus, &r.usedRam, &r.usedStorage)
		if err != nil {
			l.Printf("Error getting used resources for user: %s\n", err.Error())
		}
		_, err = db.Exec("UPDATE users SET used_vcpus = ?, used_ram = ?, used_block_storage = ? WHERE email_address = ? AND user_token = ?", r.usedVcpus-d.Vcpus, r.usedRam-d.Ram, r.usedStorage-d.Storage, t.UserEmail, t.Token)
		if err != nil {
			l.Printf("Error updating used resources for user: %s\n", err.Error())
		}

	} else if t.VpsName == "" {
		fmt.Fprintf(w, "Please specify a domain with the JSON parameter: 'VpsName'\n")
	}

}

type smtpConfig struct {
	SenderEmail string `yaml:"sender_email"`
	Password    string `yaml:"password"`
	Server      string `yaml:"server"`
	Port        string `yaml:"port"`
}

func notifyUser(imageURL string, userEmail string, imageSecret string, vpsName string) {
	var SmtpConfig smtpConfig
	reader, err := ioutil.ReadFile("/etc/gammabyte/lsapi/mailer.yml")
	if err != nil {
		l.Printf("Error opening mailer config: %s\n", err.Error())
		return
	}
	err = yaml.Unmarshal(reader, &SmtpConfig)
	if err != nil {
		l.Printf("Error unmarshalling mailer config: %s\n", err.Error())
		return
	}
	if err := yaml.Unmarshal(reader, &SmtpConfig); err != nil {
		l.Printf("Error unmarshalling mailer config: %s\n", err.Error())
		return
	}
	to := []string{
		userEmail,
	}

	mailMessage := []byte(fmt.Sprintf("From: GammaByte Backups <billing@gammabyte.xyz>\r\n"+
		"To: "+userEmail+"\r\n"+
		"Subject: Your GammaByte.xyz VPS Backup\r\n"+
		"\r\n"+
		"Download your VPS image backup here: %s\nYour LUKS decryption key: %s\n\n\nTo decrypt your VPS, run:\n\ngzip -dv "+vpsName+".qcow2.gz && qemu-img convert -p -c --object secret,id=sec0,data="+imageSecret+" --image-opts driver=qcow2,file.filename="+vpsName+".qcow2,encrypt.key-secret=sec0 -O qcow2 "+vpsName+"-decrypted.qcow2\n\nNote: After this URL is accessed for the first time, it will automatically be removed from our servers in two days.\nIf you wish for it to be removed sooner, please contact support@gammabyte.xyz.  \n\n\nThank you for using GammaByte.xyz!", imageURL, imageSecret) + "\r\n")
	err = smtp.SendMail(SmtpConfig.Server+":"+SmtpConfig.Port, smtp.PlainAuth("", SmtpConfig.SenderEmail, SmtpConfig.Password, SmtpConfig.Server), SmtpConfig.SenderEmail, to, mailMessage)
	if err != nil {
		l.Printf("Error sending image backup URL: %s\n", err.Error())
		return
	}
	l.Printf("Successfully sent image backup to %s!\n", userEmail)
}

func generateImageURI(filePath string, domainName string) (string, error) {
	// Parse the config file
	var ConfigFile configFile
	filename, err := filepath.Abs("/etc/gammabyte/lsapi/config-kvm.yml")
	if err != nil {
		return "", err
	}
	yamlConfig, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", err
	}
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		return "", err
	}

	body := bytes.NewReader([]byte(fmt.Sprintf("{\"ImagePath\": \"%s\", \"ProxyType\": \"genURI\", \"DomainName\": \"%s\"}", filePath, domainName)))
	resp, err := http.Post("https://"+ConfigFile.MasterIP+":8082/api/image", "application/json", body)
	if err != nil {
		l.Printf("Error sending request: %s\n", err.Error())
		return "", err
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		l.Printf("Error reading response body: %s\n", err.Error())
		return "", err
	}
	return string(bodyBytes), nil
}

func sendFileOverNetwork(source string, vpsName string) (error, string) {
	// Set the transport options and apply them to the client
	transport := &http.Transport{
		WriteBufferSize: 125000000,
		ReadBufferSize:  125000000,
		TLSClientConfig: &tls.Config{
			RootCAs: rootCAs,
		},
	}
	client := http.Client{
		Transport: gzhttp.Transport(transport),
	}

	// Parse the config file
	var ConfigFile configFile
	filename, err := filepath.Abs("/etc/gammabyte/lsapi/config-kvm.yml")
	if err != nil {
		l.Printf("Error finding config file: %s\n", err.Error())
		return err, ""
	}
	yamlConfig, err := ioutil.ReadFile(filename)
	if err != nil {
		l.Printf("Error reading config file: %s\n", err.Error())
		return err, ""
	}
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)
	if err != nil {
		l.Printf("Error unmarshaling config file: %s\n", err.Error())
		return err, ""
	}

	l.Println("Sending image preparation request...")

	originalStats := syscall.Stat_t{}
	err = syscall.Stat(source, &originalStats)
	if err != nil {
		l.Printf("Error getting original file stats: %s\n", err.Error())
		return err, ""
	}

	if originalStats.Size*512 <= 2*GiB {
		l.Println("WARNING: Volume too small to sparsify. It looks empty to me, so I'll remove it.")
		err = os.Remove(source)
		if err != nil {
			l.Printf("Error removing source file which was too small to sparsify: %s\n", err.Error())
			return err, ""
		}
		return fmt.Errorf("volume was too small to sparsify & backup. (less than 1GiB)"), "Error: Volume was too small to sparsify & backup. (less than 1GiB)"
	}

	body := strings.NewReader(fmt.Sprintf(`{"MasterKey": "%s", "VolumeName": "%s", "SparsifyVolume":true}`, ConfigFile.MasterKey, vpsName))
	req, err := http.NewRequest("POST", "https://"+ConfigFile.MasterFqdn+":4224/files/prepare/volume", body)
	if err != nil {
		l.Printf("Error generating request for volume preparation: %s\n", err.Error())
		return err, ""
	}
	resp, err := client.Do(req)
	if err != nil {
		l.Printf("Error sending request for volume preparation: %s\n", err.Error())
		return err, ""
	}
	if resp.StatusCode != http.StatusOK {
		l.Printf("Error: Invalid response code '%s'\n", resp.Status)
		return fmt.Errorf("response code invalid: %s", resp.Status), ""
	}
	sparseSize := resp.Header.Get("sparseSize")
	sparseSizeInt, err := strconv.Atoi(sparseSize)
	if err != nil {
		l.Printf("Error converting sparse size string to integer: %s\n", err.Error())
		req.Body.Close()
		resp.Body.Close()
		return err, ""
	}
	req.Body.Close()
	resp.Body.Close()

	// Open the source volume, encrypted Qcow2 format.
	if fileExists(source+"-SPARSE") == false {
		l.Printf("Error: File %s does not exist.", source)
		return fmt.Errorf("file %s does not exist", source), ""
	}

	l.Printf("Opening source file..")
	fi, err := os.Open(source + "-SPARSE")
	if err != nil {
		l.Printf("Error opening source file: %s\n", err.Error())
		return err, ""
	}

	zpr, zpw := io.Pipe()
	go func() {
		defer zpw.Close()
		zip, err := gzip.NewWriterLevel(zpw, gzip.BestSpeed)
		defer zip.Close()
		if err != nil {
			l.Printf("Error creating new gzip writer: %s\n", err.Error())
			return
		}
		err = zip.SetConcurrency(50000000, 24)
		if err != nil {
			l.Printf("Error setting gzip concurrency: %s\n", err.Error())
			return
		}

		buf := bytes.NewBuffer(make([]byte, 4000000))
		if buf.Bytes() == nil {
			l.Printf("Buffer bytes are empty? Closing to prevent a panic...")
			buf.Reset()
			zip.Close()
			return
		}
		defer buf.Reset()
		_, err = io.CopyBuffer(zip, fi, buf.Bytes())
		if err != nil {
			l.Printf("Error copying data to gzip writer: %s\n", err.Error())
			return
		}
	}()

	var pr *progress.Reader
	if sparseSizeInt > 3*GiB {
		pr = progress.NewReader(zpr)

		// Create the HTTP request to be used later
		l.Printf("Generating HTTP request...")
		req, err = http.NewRequest(http.MethodPost, "https://"+ConfigFile.MasterFqdn+":4224/files/upload/volume", pr)
		if err != nil {
			l.Printf("Error generating new volume upload request with destination https://%s:4224/files/upload/volume: %s\n", ConfigFile.MasterIP, err.Error())
			return err, ""
		}
	} else if sparseSizeInt < 3*GiB {
		l.Printf("Generating HTTP request...")
		req, err = http.NewRequest(http.MethodPost, "https://"+ConfigFile.MasterFqdn+":4224/files/upload/volume", zpr)
		defer req.Body.Close()
		if err != nil {
			l.Printf("Error generating new volume upload request with destination https://%s:4224/files/upload/volume: %s\n", ConfigFile.MasterIP, err.Error())
			return err, ""
		}
	}

	// Get the FQDN to be set in a header
	hostname, err := fqdn.FqdnHostname()
	if err != nil {
		l.Printf("Error getting hostname: %s\n", err.Error())
		return err, ""
	}

	// Generate the hash to be used as an object reference for later
	hash := sha1.New()
	hash.Write([]byte(vpsName))

	// Set the proper headers so the master node can authorize the transaction
	req.Host = hostname
	req.Header.Set("filename", vpsName)
	req.Header.Set("masterkey", ConfigFile.MasterKey)
	req.Header.Set("hostname", hostname)
	req.Header.Set("hash", hex.EncodeToString(hash.Sum(nil)))
	req.Header.Set("Content-Type", "application/octet-stream")

	// Show percent complete every 5 seconds, we need the **SPARSE** file size to do this

	req.Header.Set("filesize", sparseSize)
	l.Printf("Size of volume to be sent over the volume backup API: %d GiB\n", sparseSizeInt/GiB)

	// Set the length in time between percentage reporting to prevent spamming the log
	var t time.Duration

	switch size := sparseSizeInt / GiB; {
	case size >= 12:
		t = 30 * time.Second
	case size >= 24:
		t = 1 * time.Minute
	case size >= 75:
		t = 2 * time.Minute
	case size >= 150:
		t = 3 * time.Minute
	case size >= 250:
		t = 5 * time.Minute
	case size >= 500:
		t = 10 * time.Minute
	case size >= 750:
		t = 15 * time.Minute
	case size <= 10:
		t = 10 * time.Second
	}

	/*if fileSize.Blocks*512 / GiB >= 12 {
		t = 30*time.Second
	} else if fileSize.Blocks*512 / GiB >= 24 {
		t = 1*time.Minute
	} else if fileSize.Blocks*512 / GiB >= 75 {
		t = 2*time.Minute
	} else if fileSize.Blocks*512 / GiB >= 150 {
		t = 3*time.Minute
	} else if fileSize.Blocks*512 / GiB >= 250 {
		t = 5*time.Minute
	} else if fileSize.Blocks*512 / GiB >= 500 {
		t = 10*time.Minute
	} else if fileSize.Blocks*512 / GiB >= 750 {
		t = 15*time.Minute
	} else if fileSize.Blocks*512 / GiB <= 10 {
		t = 10*time.Second
	}*/

	if sparseSizeInt > 3*GiB {
		var finishedUploading = make(chan bool)
		ctx := context.Background()
		go func(finished chan bool) {
			progressChan := progress.NewTicker(ctx, pr, int64(sparseSizeInt), t)
			var timeCompleted int64
			var p progress.Progress
			var lastRound int64
			for p = range progressChan {
				timeCompleted = timeCompleted + 5
				lastRound = p.N() - lastRound
				//l.Printf("%v remaining...", p.Remaining().Round(time.Second))
				l.Printf("%.2f%% complete - %.3f GiB uploaded - (%dMiB/s)", p.Percent(), float64(p.N())/GiB, lastRound/timeCompleted/MiB)
			}
			l.Printf("Uploaded %.3f GiB to %s at an average speed of %d MiB/s", float64(p.N())/GiB, ConfigFile.MasterIP, p.N()/timeCompleted/MiB)
			finished <- true
			return
		}(finishedUploading)

		// Run the HTTP POST request
		l.Printf("Executing POST request...")
		resp, err = client.Do(req)
		if err != nil {
			l.Printf("Error sending new HTTP request to https://%s:4224/files/upload/volume: %s\n", ConfigFile.MasterIP, err.Error())
			return err, ""
		}
		zpr.Close()
		<-finishedUploading
	} else if sparseSizeInt < 3*GiB {
		l.Printf("Omitting transfer rate: Volume is less than 3GiB (probably 0), so transfer tracking may hang the application and return inaccurate results.")
		resp, err = client.Do(req)
		if err != nil {
			l.Printf("Error sending new HTTP request to https://%s:4224/files/upload/volume: %s\n", ConfigFile.MasterIP, err.Error())
			return err, ""
		}
		//defer zpr.Close()
	}

	generatedURL := resp.Header.Get("generated_url")
	if resp.StatusCode != http.StatusOK {
		l.Printf("Error: Master node responded with erroneous status code: %s\n", resp.Status)
		err = os.Rename(source+"-SPARSE", ConfigFile.VolumePath+"backupQueue/"+vpsName)
		if err != nil {
			l.Printf("Error moving file to backup queue: %s\n", err.Error())
			return err, ""
		}
		return fmt.Errorf("%s", resp.Status), ""
	}
	l.Printf("Volume backup response status: %s\n", resp.Status)
	l.Printf("Backup URL returned by master: %s\n", generatedURL)

	l.Println("Securely deleting old volume...")
	fi, err = os.OpenFile(source+"-SPARSE", os.O_RDWR|os.O_TRUNC, 0666)
	if err != nil {
		l.Printf("Error reopening file %s for secure deletion : %s\n", source, err.Error())
		return err, generatedURL
	}
	var statStruct syscall.Stat_t
	err = syscall.Stat(source+"-SPARSE", &statStruct)
	if err != nil {
		l.Printf("Error getting volume info for secure deletion: %s\n", err.Error())
		l.Printf("Attempting to recover by using os.Remove()...")
		err = os.Remove(source + "-SPARSE")
		if err != nil {
			l.Printf("Error falling back to os.Remove() due to failed deletion: %s\n", err.Error())
			return err, ""
		}
		return err, generatedURL
	}
	l.Printf("Total filesize (sparse GiB): %d GiB\n", sparseSizeInt/GiB)
	l.Printf("Total filesize (sparse bytes): %d B\n", sparseSizeInt)

	const fileChunk = 12 * (1 << 20)
	totalPartsNum := uint64(math.Ceil(float64(sparseSizeInt) / float64(fileChunk)))
	lastPosition := 0

	var done25 bool
	var done50 bool
	var done75 bool
	var done100 bool

	for i := uint64(0); i < totalPartsNum; i++ {

		partSize := int(math.Min(fileChunk, float64(int64(sparseSizeInt)-int64(i*fileChunk))))
		partZeroBytes := make([]byte, partSize)

		// fill out the part with zero value
		copy(partZeroBytes[:], "0")

		// over write every byte in the chunk with 0
		_, err = fi.WriteAt(partZeroBytes, int64(lastPosition))
		if err != nil {
			l.Printf("Error writing secure bytes to file: %s\n", err.Error())
			l.Printf("Attempting to recover by using os.Remove()...")
			err = os.Remove(source + "-SPARSE")
			if err != nil {
				l.Printf("Error falling back to os.Remove(): %s\n", err.Error())
				return err, ""
			}
			return err, generatedURL
		}
		// update last written position
		lastPosition = lastPosition + partSize
		if lastPosition >= sparseSizeInt/4 && done25 == false {
			l.Println(" -> 25% complete...")
			done25 = true
		} else if lastPosition >= sparseSizeInt/2 && done50 == false {
			l.Println(" -> 50% complete...")
			done50 = true
		} else if lastPosition >= (sparseSizeInt/4)*3 && done75 == false {
			l.Println(" -> 75% complete...")
			done75 = true
		} else if lastPosition >= sparseSizeInt && done100 == false {
			l.Println(" -> 100% complete!")
			done100 = true
		}
	}

	err = fi.Close()
	if err != nil {
		l.Printf("Error closing file: %s\n", err.Error())
	}

	err = os.Remove(source + "-SPARSE")
	if err != nil {
		l.Printf("Error fully removing source (as a precaution it has been overwritten with zeroes): %s\n", err.Error())
		return err, generatedURL
	}
	l.Printf("Secure deletion successful.")

	err = resp.Body.Close()
	if err != nil {
		l.Printf("Error closing response body: %s\n", err.Error())
	}
	return err, generatedURL
}

func sendTusFile(source string, vpsName string) (error, string) {
	// Parse the config file
	var ConfigFile configFile
	filename, err := filepath.Abs("/etc/gammabyte/lsapi/config-kvm.yml")
	if err != nil {
		return err, ""
	}
	yamlConfig, err := ioutil.ReadFile(filename)
	if err != nil {
		return err, ""
	}
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		return err, ""
	}

	tusConfig := tus.Config{
		ChunkSize: 8 * 1024 * 1024,
		HttpClient: &http.Client{
			Transport: gzhttp.Transport(http.DefaultTransport),
		},
	}
	l.Printf("Tus server: https://%s:8741/upload/\n", ConfigFile.MasterIP)
	client, err := tus.NewClient("https://"+ConfigFile.MasterIP+":8741/upload/", &tusConfig)
	if err != nil {
		l.Printf("Error starting new TUS client: %s\n", err.Error)
		return err, ""
	}
	client.Header.Set("Filename", vpsName)
	client.Header.Set("filename", vpsName)
	client.Header.Set("Content-Type", "application/offset+octet-stream")
	l.Println("Creating upload type...")

	f, err := os.Open(source)
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			l.Printf("Failed to close file %s: %s\n", source, err.Error())
		}
	}(f)
	//upload := tus.NewUploadFromBytes(func () []byte { bodyBytes, _ := ioutil.ReadAll(reader); l.Printf("Size of bodyBytes: %d\n", unsafe.Sizeof(bodyBytes)); return bodyBytes}())
	//upload := tus.NewUpload(reader, 0, tus.Metadata{}, base64.StdEncoding.EncodeToString(hmac.New(sha256.New, []byte(source)).Sum(nil)))
	/*upload, err := tus.NewUploadFromFile(f)
	if err != nil {
		l.Printf("Error creating new upload from file: %s\n", err.Error())
		return err, ""
	}*/
	reader := NewGzipReader(vpsName, source)
	upload := tus.NewUploadFromBytes(func() []byte {
		bodyBytes, err := ioutil.ReadAll(reader)
		if err != nil {
			l.Printf("Error reading bytes from io.Reader interface: %s\n", err.Error())
			return nil
		}
		return bodyBytes
	}())
	l.Println("Creating the uploader...")
	uploader, err := client.CreateUpload(upload)
	l.Printf("Size of the uploader: %d\n", unsafe.Sizeof(uploader))
	if err != nil {
		l.Printf("Error creating uploader: %s\n", err.Error())
		return err, ""
	}
	l.Printf("URL: %s\n", uploader.Url())
	l.Printf("Uploading file bytes via the TUS protocol...")
	err = uploader.Upload()
	if err != nil {
		l.Printf("Error starting upload: %s\n", err.Error())
		return err, ""
	}

	urlParsed, err := url.Parse(uploader.Url())
	if err != nil {
		l.Printf("Error parsing response URL: %s\n", err.Error())
		return err, ""
	}
	l.Println("Done uploading file!")

	volHash := strings.TrimPrefix(urlParsed.Path, "/upload/")
	return nil, volHash
}

func NewGzipReader(vpsName string, location string) io.Reader {
	source, err := os.Open(location)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		return nil
	}
	l.Println("Creating new PGZip reader...")
	r, w := io.Pipe()
	l.Println("Created new pipe...")
	go func() {
		defer func(source *os.File) {
			err := source.Close()
			if err != nil {
				l.Printf("Error closing file %s: %s\n", location, err.Error())
			}
		}(source)
		defer func(w *io.PipeWriter) {
			err := w.Close()
			if err != nil {
				l.Printf("Error closing pipewriter: %s\n", err.Error())
			}
		}(w)
		l.Println("Creating new writer...")
		zip, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
		defer func(zip *gzip.Writer) {
			err := zip.Close()
			if err != nil {
				l.Printf("Error closing PGzip writer: %s\n", err.Error())
			}
		}(zip)
		defer func(zip *gzip.Writer) {
			err := zip.Flush()
			if err != nil {
				l.Printf("Error flushing PGzipbuffer: %s\n", err.Error())
			}
		}(zip)
		l.Println("Setting concurrency...")
		err = zip.SetConcurrency(400000, 64)
		if err != nil {
			l.Printf("Error setting PGZip concurrency: %s\n", err.Error())
			return
		}
		zip.Header.Name = vpsName + ".qcow2"

		l.Println("Copying data...")
		_, err = io.Copy(zip, source)
		if err != nil {
			l.Printf("Error copying data: %s\n", err.Error())
			w.CloseWithError(err)
		}
	}()
	return r
}

func sendFile(filePath string, vpsName string, encryptBackup string, imageSecret string) (error, string) {
	// Parse the config file
	var ConfigFile configFile
	filename, err := filepath.Abs("/etc/gammabyte/lsapi/config-kvm.yml")
	if err != nil {
		return err, ""
	}
	yamlConfig, err := ioutil.ReadFile(filename)
	if err != nil {
		return err, ""
	}
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		return err, ""
	}

	l.Println("Sending the file to the LB host... This may take a while depending on the size.")
	err, URL := sendFileOverNetwork(filePath, vpsName)
	if err != nil {
		l.Printf("Error sending file: %s\n", err.Error())
		return err, URL
	}

	l.Println("Done sending file.")
	l.Println("Success!")
	return nil, URL
}

/*func provisionBackupHandler(filePath string, imageSecret string, vpsName string) {
	fi, err := os.Stat(filePath)
	if err != nil {
		l.Printf("Error getting file size: %s\n", err.Error())
		return
	}
	imageSize := fi.Size() / 1073741824
	cmd := exec.Command("qemu-img", "create", "-f", "qcow2", "/tmp/scratch-"+vpsName+"-backup.qcow2", strconv.FormatInt(imageSize+1, 10)+"G")
	if _, err := cmd.Output(); err != nil {
		l.Printf("Error: %s\n", err.Error())
		return
	}

	// Connect to qemu-kvm
	conn, err := libvirt.NewConnect("qemu:///system?socket=/var/run/libvirt/libvirt-sock")
	if err != nil {
		l.Printf("Failed! \nReason: %s\n", err.Error())
		return
	}
	defer conn.Close()

	dom, err := conn.LookupDomainByName(vpsName)
	if err != nil {
		l.Printf("Error looking up domain %s: %s\n", vpsName, err.Error())
		return
	}
	err = dom.Destroy()
	if err != nil {
		l.Printf("Error destroying %s: %s\n", vpsName, err.Error())
	}

	backupHandlerXML := &libvirtxml.DomainDisk{
		Driver: &libvirtxml.DomainDiskDriver{
			Cache:       "directsync",
			Type:        "qcow2",
			ErrorPolicy: "stop",
			IO:          "native",
		},
		Source: &libvirtxml.DomainDiskSource{
			File: &libvirtxml.DomainDiskSourceFile{
				File:     "/var/lib/lsapi/backup_handler.qcow2",
				SecLabel: nil,
			},
		},
		BlockIO: &libvirtxml.DomainDiskBlockIO{
			LogicalBlockSize:  512,
			PhysicalBlockSize: 8192,
		},
		Target: &libvirtxml.DomainDiskTarget{
			Dev: "hda",
			Bus: "virtio",
		},
		IOTune: &libvirtxml.DomainDiskIOTune{
			ReadBytesSec:  146800640,
			WriteBytesSec: 89128960,
		},
		/*Encryption: &libvirtxml.DomainDiskEncryption{
			Format: "luks",
			Secret: &libvirtxml.DomainDiskSecret{
				Type: "passphrase",
				UUID: masterSecret,
			},
		},
		Boot: &libvirtxml.DomainDeviceBoot{
			Order: 1,
		},
		Alias: &libvirtxml.DomainAlias{
			Name: vpsName+"-backup_handler",
		},
	}
	NewImageXML := &libvirtxml.DomainDisk{
		Driver: &libvirtxml.DomainDiskDriver{
			Cache:       "directsync",
			Type:        "qcow2",
			ErrorPolicy: "stop",
			IO:          "native",
		},
		Source: &libvirtxml.DomainDiskSource{
			File: &libvirtxml.DomainDiskSourceFile{
				File:     "/tmp/scratch-"+vpsName+"-backup.qcow2",
				SecLabel: nil,
			},
		},
		BlockIO: &libvirtxml.DomainDiskBlockIO{
			LogicalBlockSize:  512,
			PhysicalBlockSize: 8192,
		},
		Target: &libvirtxml.DomainDiskTarget{
			Dev: "vdb",
			Bus: "virtio",
		},
		IOTune: &libvirtxml.DomainDiskIOTune{
			ReadBytesSec:  146800640,
			WriteBytesSec: 89128960,
		},
		/*Encryption: &libvirtxml.DomainDiskEncryption{
			Format: "luks",
			Secret: &libvirtxml.DomainDiskSecret{
				Type: "passphrase",
				UUID: masterSecret,
			},
		},
		Boot: &libvirtxml.DomainDeviceBoot{
			Order: 3,
		},
		Alias: &libvirtxml.DomainAlias{
			Name: vpsName+"-backup_handler",
		},
	}
	err = dom.AttachDevice(backupHandlerXML.Device)
	if err != nil {
		l.Printf("Error attaching new boot device: %s\n", err.Error())
		return
	}
	err = dom.AttachDevice(NewImageXML.Device)
	if err != nil {
		l.Printf("Error attaching backup device: %s\n", err.Error())
		return
	}




}
*/
func getKeyFile() (key ssh.Signer, err error) {
	//usr, _ := user.Current()
	file := "/root/.ssh/id_rsa"
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}
	key, err = ssh.ParsePrivateKey(buf)
	if err != nil {
		return
	}
	return
}

func Tar(source string, target string) error {
	//filename := filepath.Base(source)
	//target = filepath.Join(target, fmt.Sprintf("%s.tar", filename))
	tarfile, err := os.Create(target + ".tar")
	if err != nil {
		l.Printf("Error creating target: %s\n", err.Error())
		return err
	}
	defer tarfile.Close()

	tarball := tar.NewWriter(tarfile)
	defer tarball.Close()

	info, err := os.Stat(source)
	if err != nil {
		l.Printf("Error statting source: %s\n", err.Error())
		return err
	}

	var baseDir string
	if info.IsDir() {
		baseDir = filepath.Base(source)
	}

	return filepath.Walk(source,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				l.Printf("Error walking filepath: %s\n", err.Error())
				return err
			}
			header, err := tar.FileInfoHeader(info, info.Name())
			if err != nil {
				l.Printf("Error generating info header: %s\n", err.Error())
				return err
			}
			if baseDir != "" {
				header.Name = filepath.Join(baseDir, strings.TrimPrefix(path, source))
				header.Typeflag = tar.TypeGNUSparse
			}

			if err := tarball.WriteHeader(header); err != nil {
				l.Printf("Error writing tarball header: %s\n", err.Error())
				return err
			}

			if info.IsDir() {
				return nil
			}

			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			_, err = io.Copy(tarball, file)
			err = os.Remove(source)
			if err != nil {
				l.Printf("Error removing %s: %s\n", source, err.Error())
			}
			return err
		})
}

func Gzip(source string) []byte {
	reader, err := ioutil.ReadFile(source)
	/*writer, err := os.Create(target)
	if err != nil {
		l.Printf("Error creating target gzip file: %s\n", err.Error())
		return err, nil
	}
	defer func(writer *os.File) error {
		err := writer.Close()
		if err != nil {
			l.Printf("Error creating writer: %s\n", err.Error())
			return err
		}
		return nil
	}(writer)
	*/
	var b bytes.Buffer
	w := gzip.NewWriter(&b)

	err = w.SetConcurrency(400000, runtime.GOMAXPROCS(0))
	if err != nil {
		l.Printf("Error setting PGZip concurrency: %s\n", err.Error())
		return nil
	}
	w.Header.Name = source + ".qcow2"

	_, err = w.Write(reader)
	if err != nil {
		l.Printf("Error writing PGZip bytes: %s\n", err.Error())
		return nil
	}
	err = os.Remove(source)
	if err != nil {
		l.Printf("Error removing %s: %s\n", source, err.Error())
		return nil
	}
	return b.Bytes()
}

func UnGzip(source, target string) error {
	reader, err := os.Open(source)
	if err != nil {
		return err
	}
	defer reader.Close()

	archive, err := gzip.NewReader(reader)
	if err != nil {
		return err
	}
	defer archive.Close()

	target = filepath.Join(target, archive.Name)
	writer, err := os.Create(target)
	if err != nil {
		return err
	}
	defer writer.Close()

	_, err = io.Copy(writer, archive)
	return err
}

type VNCinfo struct {
	VNCPort string `xml:"port,attr"`
}

type MACAttr struct {
	Address string `xml:"address,attr"`
}
type BridgeInterface struct {
	MAC  MACAttr `xml:"mac"`
	Type string  `xml:"type,attr"`
}

type DiskSource struct {
	Path string `xml:"file,attr"`
}
type Disk struct {
	Source DiskSource `xml:"source"`
}

type Devices struct {
	Graphics  VNCinfo           `xml:"graphics"`
	Interface []BridgeInterface `xml:"interface"`
	Disks     []Disk            `xml:"disk"`
}

type xmlParseResult struct {
	Name    string  `xml:"name"`
	UUID    string  `xml:"uuid"`
	Devices Devices `xml:"devices"`
}

func ParseDomainXML(xmlData string) *xmlParseResult {
	var v = xmlParseResult{}
	xml.Unmarshal([]byte(xmlData), &v)
	return &v
}
