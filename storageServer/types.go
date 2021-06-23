package main

type configFile struct {
	MasterKey   string `yaml:"master_key"`
	SqlAddress  string `yaml:"sql_address"`
	SqlUser     string `yaml:"sql_user"`
	SqlPassword string `yaml:"sql_password"`

	VolumePath    string `yaml:"volume_path"`
	MasterIP      string `yaml:"master_ip"`
	MasterPort    string `yaml:"master_port"`
	SyslogAddress string `yaml:"syslog_server"`
	SyslogPort    string `yaml:"syslog_port"`
	AuthServer    string `yaml:"auth_server"`
}

type sparsecatVolume struct {
	VolumeName string `json:"VolumeName"`
	MasterKey  string `json:"MasterKey"`
}
