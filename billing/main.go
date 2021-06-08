package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"gopkg.in/yaml.v3"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

// Set global variables
var (
	remoteSyslog, _ = syslog.Dial("udp", "localhost:514", syslog.LOG_DEBUG, "[LibStatsAPI-Billing]")
	logFile, _      = os.OpenFile("/var/log/lsapi.log", os.O_APPEND|os.O_RDWR|os.O_CREATE, 0644)
	writeLog        = io.MultiWriter(os.Stdout, logFile, remoteSyslog)
	l               = log.New(writeLog, "[LibStatsAPI-Billing] ", log.Ldate|log.Ltime|log.LUTC|log.Lmsgprefix|log.Lmicroseconds|log.LstdFlags|log.Llongfile|log.Lshortfile)
	db              *sql.DB
	filename        string
	yamlConfig      []byte
	err             error
	ConfigFile      configFile
)

func handleRequests() {
	http.HandleFunc("/api/billing", billingHandler)

	listenAddr := fmt.Sprintf("%s:%s", ConfigFile.ListenAddress, ConfigFile.ListenPort)

	// Listen on specified port
	l.Fatal(http.ListenAndServe(listenAddr, nil))
}

func main() {
	// Parse the config file
	filename, err = filepath.Abs("/etc/gammabyte/lsapi/config-billing.yml")
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

	l.Println("Starting billing server...")
	// Connect to MariaDB
	dbConnectString := fmt.Sprintf("%s:%s@tcp(%s:3306)/lsapi", ConfigFile.SqlUser, ConfigFile.SqlPassword, ConfigFile.SqlAddress)
	db, err = sql.Open("mysql", dbConnectString)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		panic(err.Error())
	}
	handleRequests()
	db.Exec("CREATE TABLE IF NOT EXISTS billing(request text, time_created text, event_type text)")
	db.Exec("CREATE TABLE IF NOT EXISTS plans (firstname text, lastname text, email_address text, plan text, create_time text, address text, city text, state text, zip text, currency_code text, payment_amount text, plan_id text, auto_renewal text, quantity text, request_type text, status text)")
}

func billingHandler(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		return
	}
	var notification PaypalNotification
	err = json.Unmarshal(body, &notification)
	if err != nil {
		l.Printf("Error: %s\n", err.Error())
		return
	}
	_, err = db.Exec("INSERT INTO billing (request, time_created, event_type) VALUES (?, ?, ?)", body, notification.CreateTime, notification.EventType)
	if err != nil {
		l.Printf("Error inserting API request into DB: %s\n", err.Error())
		return
	}
	w.WriteHeader(http.StatusOK)
	l.Println("Paypal:")
	l.Printf("   Body: %s,", body)
	l.Printf("   Parsed: %+v\n", notification)
	if notification.EventType == "BILLING.SUBSCRIPTION.CREATED" {
		createBillingPlan(notification)
	} else if notification.EventType == "BILLING.SUBSCRIPTION.ACTIVATED" {
		activateSubscription(notification)
	} else if contains([]string{"BILLING.SUBSCRIPTION.EXPIRED", "BILLING.SUBSCRIPTION.CANCELLED", "BILLING.SUBSCRIPTION.SUSPENDED"}, notification.EventType) == true {
		killSubscription(notification)
	}
}

func killSubscription(notification PaypalNotification) {
	s := []string{"EXPIRED", "CANCELLED", "SUSPENDED"}
	if contains(s, notification.Resource.Status) == false {
		l.Printf("Error killing subscription: Resource does not have any value containing: %s.\n", s)
		return
	}

	if notification.Resource.PlanID == "1-vcpu" {
		rows, err := db.Query("SELECT max_vcpus FROM users WHERE email_address = ?", notification.Resource.Subscriber.EmailAddress)
		if err != nil {
			l.Printf("Error: %s\n", err.Error())
			return
		}
		var oldMaxVcpus int
		for rows.Next() {
			rows.Scan(&oldMaxVcpus)
		}
		cpusToRemove, err := strconv.Atoi(notification.Resource.Quantity)
		if err != nil {
			l.Printf("Error: %s\n", err.Error())
		}
		newMaxVcpus := oldMaxVcpus - cpusToRemove
		_, err = db.Exec("UPDATE users SET max_vcpus = ? WHERE email_address = ?", newMaxVcpus, notification.Resource.Subscriber.EmailAddress)
		if err != nil {
			l.Printf("Error removing unpaid CPUs: %s\n", err.Error())
		}
	} else if notification.Resource.PlanID == "1gb-ram" {
		rows, err := db.Query("SELECT max_ram FROM users WHERE email_address = ?", notification.Resource.Subscriber.EmailAddress)
		if err != nil {
			l.Printf("Error: %s\n", err.Error())
			return
		}
		var oldMaxRam int
		for rows.Next() {
			rows.Scan(&oldMaxRam)
		}
		ramToRemove, err := strconv.Atoi(notification.Resource.Quantity)
		if err != nil {
			l.Printf("Error: %s\n", err.Error())
			return
		}
		newMaxRam := oldMaxRam - ramToRemove
		_, err = db.Exec("UPDATE users SET max_ram = ? WHERE email_address = ?", newMaxRam, notification.Resource.Subscriber.EmailAddress)
		if err != nil {
			l.Printf("Error removing unpaid RAM: %s\n", err.Error())
		}
	} else if notification.Resource.PlanID == "1gb-storage" {
		rows, err := db.Query("SELECT max_block_storage FROM users WHERE email_address = ?", notification.Resource.Subscriber.EmailAddress)
		if err != nil {
			l.Printf("Error: %s\n", err.Error())
			return
		}
		var oldMaxStorage int
		for rows.Next() {
			rows.Scan(&oldMaxStorage)
		}
		storageToRemove, err := strconv.Atoi(notification.Resource.Quantity)
		if err != nil {
			l.Printf("Error: %s\n", err.Error())
			return
		}
		newMaxStorage := oldMaxStorage - storageToRemove
		_, err = db.Exec("UPDATE users SET max_block_storage = ? WHERE email_address = ?", newMaxStorage, notification.Resource.Subscriber.EmailAddress)
	}
}

func createBillingPlan(notification PaypalNotification) {
	_, err = db.Exec("INSERT INTO plans (firstname, lastname, email_address, plan, create_time, address, city, state, zip, currency_code, payment_amount, plan_id, auto_renewal, quantity, request_type, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", notification.Resource.Subscriber.Name.GivenName, notification.Resource.Subscriber.Name.Surname, notification.Resource.Subscriber.EmailAddress, notification.Resource.PlanID, notification.CreateTime, notification.Resource.Subscriber.ShippingAddress.Address.AddressLine1, notification.Resource.Subscriber.ShippingAddress.Address.AdminArea2, notification.Resource.Subscriber.ShippingAddress.Address.AdminArea1, notification.Resource.Subscriber.ShippingAddress.Address.PostalCode, notification.Resource.ShippingAmount.CurrencyCode, notification.Resource.ShippingAmount.Value, notification.Resource.PlanID, fmt.Sprintf("%t", notification.Resource.AutoRenewal), notification.Resource.Quantity, notification.EventType, notification.Resource.Status)
	if err != nil {
		l.Printf("Error inserting payment info: %s\n", err.Error())
		return
	}
}

func activateSubscription(notification PaypalNotification) {
	_, err = db.Exec("INSERT INTO plans (firstname, lastname, email_address, plan, create_time, address, city, state, zip, currency_code, payment_amount, plan_id, auto_renewal, quantity, request_type, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", notification.Resource.Subscriber.Name.GivenName, notification.Resource.Subscriber.Name.Surname, notification.Resource.Subscriber.EmailAddress, notification.Resource.PlanID, notification.CreateTime, notification.Resource.Subscriber.ShippingAddress.Address.AddressLine1, notification.Resource.Subscriber.ShippingAddress.Address.AdminArea2, notification.Resource.Subscriber.ShippingAddress.Address.AdminArea1, notification.Resource.Subscriber.ShippingAddress.Address.PostalCode, notification.Resource.ShippingAmount.CurrencyCode, notification.Resource.ShippingAmount.Value, notification.Resource.PlanID, fmt.Sprintf("%t", notification.Resource.AutoRenewal), notification.Resource.Quantity, notification.EventType, notification.Resource.Status)
	if err != nil {
		l.Printf("Error inserting payment info: %s\n", err.Error())
		return
	}
	if notification.Resource.Status != "ACTIVE" {
		l.Printf("Invalid status: %s\n", notification.Resource.Status)
		return
	}
	if notification.Resource.PlanID == "1-vcpu" {
		rows, err := db.Query("SELECT max_vcpus FROM users WHERE email_address = ?", notification.Resource.Subscriber.EmailAddress)
		if err != nil {
			l.Printf("Error querying DB for max_vcpus: %s\n", err.Error())
			return
		}
		var oldMaxVcpus int
		for rows.Next() {
			rows.Scan(&oldMaxVcpus)
		}
		newCpuReq, err := strconv.Atoi(notification.Resource.Quantity)
		if err != nil {
			l.Printf("Error adding new max vCPUS to old max vCPUS")
		}
		newMaxVcpus := oldMaxVcpus + newCpuReq
		db.Exec("UPDATE users SET max_vcpus = ? WHERE email_address = ?", newMaxVcpus, notification.Resource.Subscriber.EmailAddress)
	} else if notification.Resource.PlanID == "1gb-ram" {
		rows, err := db.Query("SELECT max_ram FROM users WHERE email_address = ?", notification.Resource.Subscriber.EmailAddress)
		if err != nil {
			l.Printf("Error querying DB for max_ram: %s\n", err.Error())
			return
		}
		var oldMaxRAM int
		for rows.Next() {
			rows.Scan(&oldMaxRAM)
		}
		newRamReq, err := strconv.Atoi(notification.Resource.Quantity)
		if err != nil {
			l.Printf("Error adding new max RAM to old max RAM")
		}
		newMaxRam := oldMaxRAM + newRamReq
		db.Exec("UPDATE users SET max_ram = ? WHERE email_address = ?", newMaxRam, notification.Resource.Subscriber.EmailAddress)
	} else if notification.Resource.PlanID == "1gb-storage" {
		rows, err := db.Query("SELECT max_block_storage FROM users WHERE email_address = ?", notification.Resource.Subscriber.EmailAddress)
		if err != nil {
			l.Printf("Error querying DB for max_block_storage: %s\n", err.Error())
			return
		}
		var oldMaxStorage int
		for rows.Next() {
			rows.Scan(&oldMaxStorage)
		}
		newStorageReq, err := strconv.Atoi(notification.Resource.Quantity)
		if err != nil {
			l.Printf("Error adding new max RAM to old max RAM")
		}
		newMaxStorage := oldMaxStorage + newStorageReq
		db.Exec("UPDATE users SET max_block_storage = ? WHERE email_address = ?", newMaxStorage, notification.Resource.Subscriber.EmailAddress)
	}

}

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}
