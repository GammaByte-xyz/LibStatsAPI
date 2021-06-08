package main

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
	LockNode        string `yaml:"lock_node"`
}

type PaypalNotification struct {
	ID           string `json:"id"`
	CreateTime   string `json:"create_time"`
	ResourceType string `json:"resource_type"`
	EventType    string `json:"event_type"`
	Summary      string `json:"summary"`
	Resource     struct {
		Quantity   string `json:"quantity"`
		Subscriber struct {
			Name struct {
				GivenName string `json:"given_name"`
				Surname   string `json:"surname"`
			} `json:"name"`
			EmailAddress    string `json:"email_address"`
			ShippingAddress struct {
				Name struct {
					FullName string `json:"full_name"`
				} `json:"name"`
				Address struct {
					AddressLine1 string `json:"address_line_1"`
					AddressLine2 string `json:"address_line_2"`
					AdminArea2   string `json:"admin_area_2"`
					AdminArea1   string `json:"admin_area_1"`
					PostalCode   string `json:"postal_code"`
					CountryCode  string `json:"country_code"`
				} `json:"address"`
			} `json:"shipping_address"`
		} `json:"subscriber"`
		CreateTime     string `json:"create_time"`
		ShippingAmount struct {
			CurrencyCode string `json:"currency_code"`
			Value        string `json:"value"`
		} `json:"shipping_amount"`
		StartTime   string `json:"start_time"`
		UpdateTime  string `json:"update_time"`
		BillingInfo struct {
			OutstandingBalance struct {
				CurrencyCode string `json:"currency_code"`
				Value        string `json:"value"`
			} `json:"outstanding_balance"`
			CycleExecutions []struct {
				TenureType                  string `json:"tenure_type"`
				Sequence                    int    `json:"sequence"`
				CyclesCompleted             int    `json:"cycles_completed"`
				CyclesRemaining             int    `json:"cycles_remaining"`
				CurrentPricingSchemeVersion int    `json:"current_pricing_scheme_version"`
			} `json:"cycle_executions"`
			LastPayment struct {
				Amount struct {
					CurrencyCode string `json:"currency_code"`
					Value        string `json:"value"`
				} `json:"amount"`
				Time string `json:"time"`
			} `json:"last_payment"`
			NextBillingTime     string `json:"next_billing_time"`
			FinalPaymentTime    string `json:"final_payment_time"`
			FailedPaymentsCount int    `json:"failed_payments_count"`
		} `json:"billing_info"`
		Links []struct {
			Href   string `json:"href"`
			Rel    string `json:"rel"`
			Method string `json:"method"`
		} `json:"links"`
		ID               string `json:"id"`
		PlanID           string `json:"plan_id"`
		AutoRenewal      bool   `json:"auto_renewal"`
		Status           string `json:"status"`
		StatusUpdateTime string `json:"status_update_time"`
	} `json:"resource"`
	Links []struct {
		Href    string `json:"href"`
		Rel     string `json:"rel"`
		Method  string `json:"method"`
		EncType string `json:"encType"`
	} `json:"links"`
	EventVersion    string `json:"event_version"`
	ResourceVersion string `json:"resource_version"`
	UserToken       string `json:"Token"`
}
