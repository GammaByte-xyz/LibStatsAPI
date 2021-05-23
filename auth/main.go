package main

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	uuid "github.com/google/uuid"
	"golang.org/x/net/context"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func handleRequests() {
	http.HandleFunc("/api/auth/user/create", createUser)
	http.HandleFunc("/api/auth/user/vms", getUserDomains)
	http.HandleFunc("/api/auth/vm", authenticateDomain)
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

// This is 1 GiB (gibibyte) in bytes
const (
	GiB = 1073741824 // 1 GiB = 2^30 bytes
)

// Main function that always runs first
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
	dbConnectString := fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/", ConfigFile.SqlUser, ConfigFile.SqlPassword)
	db, err := sql.Open("mysql", dbConnectString)

	createDB := `CREATE DATABASE IF NOT EXISTS lsapi`

	res, err := db.Exec(createDB)
	if err != nil {
		l.Printf("Error %s when creating lsapi DB\n", err)
	}

	db.Close()

	dbConnectString = fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/lsapi", ConfigFile.SqlUser, ConfigFile.SqlPassword)
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

	query = `CREATE TABLE IF NOT EXISTS domaininfo(domain_name text, network text, mac_address text, ram int, vcpus int, storage int, ip_address text, disk_path text, time_created text, user_email text, user_full_name text, username text, user_token text)`

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

	handleRequests()
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

type userCreateStruct struct {
	FullName string `json:"FullName"`
	Email    string `json:"Email"`
	Password string `json:"Password"`
	UserName string `json:"UserName"`
}

type getDomainsStruct struct {
	Token string `json:"Token"`
}

type configFile struct {
	VolumePath      string `yaml:"volume_path"`
	ListenPort      string `yaml:"listen_port"`
	ListenAddress   string `yaml:"listen_address"`
	SqlPassword     string `yaml:"sql_password"`
	Manufacturer    string `yaml:"vm_manufacturer"`
	SqlUser         string `yaml:"sql_user"`
	DomainBandwidth int    `yaml:"domain_bandwidth"`
	Subnet          string `yaml:"virtual_network_subnet"`
}

var l = log.New(os.Stdout, "[LibStatsAPI-Auth] ", 2)

func GenerateSecureToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
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

type domName struct {
	DomainName string
	ID         int
}

func getUserDomains(w http.ResponseWriter, r *http.Request) {
	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config.yml")
	yamlConfig, err := ioutil.ReadFile(filename)

	if err != nil {
		panic(err)
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	// Decode JSON & assign the json value struct to a variable we can use here
	decoder := json.NewDecoder(r.Body)
	var user = &getDomainsStruct{}

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

	query := fmt.Sprintf(`SELECT domain_name FROM domaininfo WHERE user_token='%s'`, user.Token)

	dbVars, err := db.Query(query)
	if err != nil {
		l.Println("Could not get domains from MySQL.")
	}

	l.Printf("All LibStatsAPI Managed VMs:\n")
	//fmt.Fprintf(w, "All LibStatsAPI Managed VMs:\n")

	columns, err := dbVars.Columns()
	if err != nil {
		return
	}

	count := len(columns)
	tableData := make([]map[string]interface{}, 0)
	values := make([]interface{}, count)
	valuePtrs := make([]interface{}, count)
	for dbVars.Next() {
		for i := 0; i < count; i++ {
			valuePtrs[i] = &values[i]
		}
		dbVars.Scan(valuePtrs...)
		entry := make(map[string]interface{})
		for i, col := range columns {
			var v interface{}
			val := values[i]
			b, ok := val.([]byte)
			if ok {
				v = string(b)
			} else {
				v = val
			}
			entry[col] = v
		}
		tableData = append(tableData, entry)
	}
	jsonData, err := json.Marshal(tableData)
	if err != nil {
		return
	}
	fmt.Println(string(jsonData))
	fmt.Fprintf(w, "%s\n", string(jsonData))

}

type authDomainStruct struct {
	DomainName string `json:"DomainName"`
	UserToken  string `json:"Token"`
	UserEmail  string `json:"Email"`
}

func authenticateDomain(w http.ResponseWriter, r *http.Request) {
	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config.yml")
	yamlConfig, err := ioutil.ReadFile(filename)

	if err != nil {
		panic(err)
	}
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	// Decode JSON & assign the json value struct to a variable we can use here
	decoder := json.NewDecoder(r.Body)
	var vps *authDomainStruct = &authDomainStruct{}

	// Decode the struct internally
	err = decoder.Decode(&vps)
	if err != nil {
		l.Println(err.Error())
		return
	}

	if vps.DomainName == "" {
		return
	}
	if vps.UserToken == "" {
		return
	}
	if vps.UserEmail == "" {
		return
	}

	// Set the maximum bytes able to be consumed by the API to prevent denial of service
	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	r.Header.Set("Access-Control-Allow-Origin", "*.repl.co")
	w.Header().Set("Access-Control-Allow-Origin", "*.repl.co")
	r.Header.Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	r.Header.Set("Access-Control-Allow-Headers", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")

	// Connect to MariaDB
	dbConnectString := fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/lsapi", ConfigFile.SqlUser, ConfigFile.SqlPassword)
	db, err := sql.Open("mysql", dbConnectString)
	// if there is an error opening the connection, handle it
	if err != nil {
		l.Println(err)
		return
	}
	// defer the close till after the main function has finished
	// executing
	defer db.Close()

	ownsDomain := verifyOwnership(vps.UserToken, vps.DomainName, vps.UserEmail)
	if ownsDomain == false {
		l.Printf("User with email %s has requested unauthorized access to %s!\n", vps.UserEmail, vps.DomainName)
		UnauthorizedString := fmt.Sprint(`{"Unauthorized": "true"}`)
		fmt.Fprintf(w, "%s\n", UnauthorizedString)
		return
	}

	query := fmt.Sprintf("SELECT domain_name, ram, vcpus, storage FROM domaininfo WHERE user_email = '%s' AND user_token = '%s' AND domain_name = '%s'", vps.UserEmail, vps.UserToken, vps.DomainName)

	rows, err := db.Query(query)
	if err != nil {
		l.Println(err)
		return
	}
	defer rows.Close()

	var domain string
	var domRam int
	var domCpus int
	var domStorage int

	for rows.Next() {
		err := rows.Scan(&domain, &domRam, &domCpus, &domStorage)
		if err != nil {
			l.Println(err)
			return
		}
		l.Printf("VPS Name: %s\n", domain)
		l.Printf("RAM: %d\n", domRam)
		l.Printf("vCPUs: %d\n", domCpus)
		l.Printf("Storage: %d\n", domStorage)
	}
	JsonString := fmt.Sprintf(`{"DomainName": "%s", "DomainRam": "%d", "DomainCpus": "%d", "DomainStorage": "%d"}`, domain, domRam, domCpus, domStorage)
	fmt.Fprintf(w, "%s\n", JsonString)

}

func createUser(w http.ResponseWriter, r *http.Request) {
	// Parse the config file
	filename, _ := filepath.Abs("/etc/gammabyte/lsapi/config.yml")
	yamlConfig, err := ioutil.ReadFile(filename)

	if err != nil {
		panic(err)
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

	l.Println("Request recieved to create user!")
	l.Printf("  Username: %s\n", user.UserName)
	l.Printf("  Full Name: %s\n", user.FullName)
	l.Printf("  Email Adddress: %s\n", user.Email)
	l.Println("  Password: <PRIVATE>")

	if user.UserName == "" {
		return
	}
	if user.FullName == "" {
		return
	}
	if user.Email == "" {
		return
	}
	if user.Password == "" {
		return
	}

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
		exists := fmt.Sprintf(`{"UserExists": "true"}`)
		fmt.Fprintf(w, "%s\n", exists)
		l.Printf("Email %s already exists!", user.Email)
		return
	}

	checkUserNameExists, err := db.Query(checkQueryUserName)
	if checkUserNameExists.Next() {
		exists := fmt.Sprintf(`{"UserExists": "true"}`)
		fmt.Fprintf(w, "%s\n", exists)
		l.Printf("User %s already exists!", user.UserName)
		return
	}

	// Create the users table if it doesn't exist, also add the columns
	query := `CREATE TABLE IF NOT EXISTS users(username text, full_name text, user_token text, email_address text, join_date text, uuid text, password varchar(255) DEFAULT NULL)`

	ctx, cancelfunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelfunc()

	res, err := db.ExecContext(ctx, query)
	if err != nil {
		l.Printf("Error %s when creating users table\n", err)
		return
	}

	rows, err := res.RowsAffected()
	if err != nil {
		l.Printf("Error %s when getting rows affected\n", err)
		return
	}
	l.Printf("Rows affected when creating table: %d\n", rows)

	// Generate arbitrary user binding data
	joinDate := time.Now()
	uuidValue, err := uuid.NewUUID()
	if err != nil {
		l.Printf("Error %s when generating UUID\n", err)
		return
	}
	token := GenerateSecureToken(24)

	// Gather information from JSON input to generate user data, then put it in MariaDB.
	insertQuery := fmt.Sprintf("INSERT INTO users (username, full_name, user_token, email_address, join_date, uuid, password) VALUES ('%s', '%s', '%s', '%s', '%s', '%s', SHA('%s'));", user.UserName, user.FullName, token, user.Email, joinDate.String(), uuidValue.String(), user.Password)

	res, err = db.ExecContext(ctx, insertQuery)
	if err != nil {
		l.Printf("Error %s when inserting user info\n", err)
		return
	}

	rows, err = res.RowsAffected()
	if err != nil {
		l.Printf("Error %s when getting rows affected\n", err)
		return
	}
	l.Printf("Rows affected when creating table: %d\n", rows)

	returnJson := fmt.Sprintf(`{"Token": "%s", "JoinDate": "%s", "UUID": "%s"}`, token, joinDate, uuidValue)
	fmt.Fprintf(w, "%s\n", returnJson)
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
	var ConfigFile configFile
	err = yaml.Unmarshal(yamlConfig, &ConfigFile)

	// Connect to MariaDB
	dbConnectString := fmt.Sprintf("%s:%s@tcp(127.0.0.1:3306)/lsapi", ConfigFile.SqlUser, ConfigFile.SqlPassword)
	db, err := sql.Open("mysql", dbConnectString)
	// if there is an error opening the connection, handle it
	if err != nil {
		l.Println(err)
		return false
	}
	// defer the close till after the main function has finished
	// executing
	defer db.Close()

	// Execute the query checking for the user binding to the VPS
	checkQuery := fmt.Sprintf("select domain_name from domaininfo where user_token = '%s' and domain_name = '%s' and user_email = '%s'", userToken, vpsName, userEmail)
	checkOwnership := db.QueryRow(checkQuery)

	var ownsVps bool

	switch err := checkOwnership.Scan(&vpsName); err {
	case sql.ErrNoRows:
		ownsVps = false
		return ownsVps
	case nil:
		ownsVps = true
	default:
		l.Println(err)
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
