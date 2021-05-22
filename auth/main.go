package main

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
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

type userCreateStruct struct {
	FullName string `json:"FullName"`
	Email    string `json:"Email"`
	Password string `json:"Password"`
	UserName string `json:"UserName"`
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
