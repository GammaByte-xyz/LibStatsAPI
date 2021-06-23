package main

import (
	_ "database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"net/http"
)

func averageEndpoint(w http.ResponseWriter, r *http.Request) {
	avg, err, errCode := getAverage(r.Header.Get("field"), r.Header.Get("domainName"))
	if err != nil {
		l.Printf("Error getting average: %s\n", err.Error())
		switch errCode {
		case 1:
			http.Error(w, "Error: "+r.Header.Get("field")+" is not a valid metric to average", http.StatusInternalServerError)
		case 2:
			http.Error(w, "Error: Could not retrieve metrics from internal database", http.StatusInternalServerError)
		default:
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}
	_, err = fmt.Fprintf(w, `{"Average": "%f"}
`, avg)
	if err != nil {
		l.Printf("Error writing response to client: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func timestampMetricsEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("avgBetween") == "true" {
		metrics, err := getAverageBetweenTimes(r.Header.Get("startStamp"), r.Header.Get("endStamp"), r.Header.Get("domainName"))
		if err != nil {
			l.Printf("Error getting average metrics between timestamps: %s\n", err.Error())
			http.Error(w, "Error: Could not get average metrics between timestamps", http.StatusInternalServerError)
			return
		}
		_, err = fmt.Fprintf(w, `{"CpuUsage": "%.2f", "RamUsage": "%.2f", "DiskUsage": "%.2f", "IoReadBytes": "%.2f", "IoWriteBytes": "%.2f", "NetTxBytes": "%.2f", "NetRxBytes": "%.2f"}
`, metrics.Cpu.Float64, metrics.Ram.Float64, metrics.Disk.Float64, metrics.IoReadBytes.Float64, metrics.IoWriteBytes.Float64, metrics.NetTxBytes.Float64, metrics.NetRxBytes.Float64)
		if err != nil {
			l.Printf("Error returning response to client: %s\n", err.Error())
			return
		}
		return
	}
	metrics, err, _ := getMetricsAtTime(r.Header.Get("startStamp"), r.Header.Get("endStamp"), r.Header.Get("domainName"))
	if err != nil {
		l.Printf("Error getting metrics between timestamps: %s\n", err.Error())
		http.Error(w, "Error: Could not get metrics between provided timestamps", http.StatusInternalServerError)
		return
	}
	jsonBytes, err := json.Marshal(metrics)
	if err != nil {
		l.Printf("Error marshalling JSON values: %s\n", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "%s\n", string(jsonBytes))
}

func getAverage(field string, domainName string) (float64, error, int) {
	var avg float64
	switch field {
	case "cpu":
		err = db.QueryRow("SELECT AVG(cpu)           FROM metrics WHERE domain_name = ?", domainName).Scan(&avg)
	case "ram":
		err = db.QueryRow("SELECT AVG(ram)           FROM metrics WHERE domain_name = ?", domainName).Scan(&avg)
	case "disk":
		err = db.QueryRow("SELECT AVG(disk)          FROM metrics WHERE domain_name = ?", domainName).Scan(&avg)
	case "io_readbytes":
		err = db.QueryRow("SELECT AVG(io_readbytes)  FROM metrics WHERE domain_name = ?", domainName).Scan(&avg)
	case "io_writebytes":
		err = db.QueryRow("SELECT AVG(io_writebytes) FROM metrics WHERE domain_name = ?", domainName).Scan(&avg)
	case "net_txbytes":
		err = db.QueryRow("SELECT AVG(net_txbytes)   FROM metrics WHERE domain_name = ?", domainName).Scan(&avg)
	case "net_rxbytes":
		err = db.QueryRow("SELECT AVG(net_rxbytes)   FROM metrics WHERE domain_name = ?", domainName).Scan(&avg)
	default:
		return -1, fmt.Errorf("%s is not a valid metric to average", field), 1
	}
	if err != nil {
		l.Printf("Error getting metrics from DB: %s\n", err.Error())
		return -1, err, 2
	}
	return avg, nil, 0
}

func getMetricsAtTime(timeStampStart string, timeStampEnd string, domainName string) (dbValuesMetricsArray, error, int) {
	query, err := db.Query("SELECT cpu, ram, disk, io_readbytes, io_writebytes, net_txbytes, net_rxbytes, timestamp FROM metrics WHERE timestamp BETWEEN ? AND ? AND domain_name = ?", timeStampStart, timeStampEnd, domainName)
	if err != nil {
		l.Printf("Error getting metrics between %s and %s for domain %s: %s\n", timeStampStart, timeStampEnd, domainName, err.Error())
		return dbValuesMetricsArray{}, err, 1
	}
	var MetricsValues dbValuesMetrics
	var metricsArray dbValuesMetricsArray
	for query.Next() {
		err = query.Scan(&MetricsValues.Cpu, &MetricsValues.Ram, &MetricsValues.Disk, &MetricsValues.IoReadBytes, &MetricsValues.IoWriteBytes, &MetricsValues.NetTxBytes, &MetricsValues.NetRxBytes, &MetricsValues.TimeStamp)
		if err != nil {
			l.Printf("Error scanning data into metrics array: %s\n", err.Error())
			return dbValuesMetricsArray{}, err, 2
		}
		metricsArray.Cpu = append(metricsArray.Cpu, MetricsValues.Cpu.Int64)
		metricsArray.Ram = append(metricsArray.Ram, MetricsValues.Ram.Int64)
		metricsArray.Disk = append(metricsArray.Disk, MetricsValues.Disk.Int64)
		metricsArray.IoReadBytes = append(metricsArray.IoReadBytes, MetricsValues.IoReadBytes.Float64)
		metricsArray.IoWriteBytes = append(metricsArray.IoWriteBytes, MetricsValues.IoWriteBytes.Float64)
		metricsArray.NetTxBytes = append(metricsArray.NetTxBytes, MetricsValues.NetTxBytes.Float64)
		metricsArray.NetRxBytes = append(metricsArray.NetRxBytes, MetricsValues.NetRxBytes.Float64)
		metricsArray.TimeStamp = append(metricsArray.TimeStamp, MetricsValues.TimeStamp.String)
	}
	return metricsArray, nil, -1
}

func getAverageBetweenTimes(timeStampStart string, timeStampEnd string, domainName string) (dbValuesMetricsStandard, error) {
	var v dbValuesMetricsStandard
	err := db.QueryRow("SELECT AVG(cpu), AVG(ram), AVG(disk), AVG(io_readbytes), AVG(io_writebytes), AVG(net_txbytes), AVG(net_rxbytes) FROM metrics WHERE timestamp BETWEEN ? AND ? AND domain_name = ?", timeStampStart, timeStampEnd, domainName).Scan(&v.Cpu, &v.Ram, &v.Disk, &v.IoReadBytes, &v.IoWriteBytes, &v.NetTxBytes, &v.NetRxBytes)
	if err != nil {
		l.Printf("Error getting average usage between timestamps: %s\n", err.Error())
		return dbValuesMetricsStandard{}, err
	}

	return v, nil
}
