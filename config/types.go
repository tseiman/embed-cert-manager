package config

type EnvVariable struct {
	ShellVariable 	string
	IniSection 		string
	IniVariable 	string

}

type Ca struct {
	Host 			string 			`ini:"host"`
	ClientCert 		string 			`ini:"client_cert"`
	ClientKey 		string 			`ini:"client_key"`
	ServerCertChain string 			`ini:"server_cert_chain"`
	CACert			string 			`ini:"ca_cert"`
	CACertLoaded 	string 			`ini:"ca_cert_loaded"`		
	EJBCAApiUrl     string          `ini:"ejbca_api_url"`
	Password     	string          `ini:"password"`
//	CertProfile     string          `ini:"cert_profile"`
//	CAName 		    string          `ini:"ca_name"`
//	ResponseType    string          `ini:"response_type"`
}

type Target struct {
	SSHUser 		string 			`ini:"ssh_user"`
	SSHKey 			string 			`ini:"ssh_key"`
	SSHPort 		int 			`ini:"ssh_port"`
	CertPath 		string    		`ini:"cert_path"`
	KeyPath 		string    		`ini:"key_path"`
	CSRPath 		string 			`ini:"csr_path"`
	SubjectAltName 	string 			`ini:"subjectAltName"` //delim:","
	ChangeAfterRaw 	string 			`ini:"change_after"`
	ChangeAfter 	uint64 			`ini:"-"`
	CSRCommand 		string 			`ini:"csr_command"`
	CommandEnvList 	[]EnvVariable  	`ini:"-"`
	SetCertCommand 	string 			`ini:"set_cert_command"`
	Certificate		string 			`ini:"certificate"`
}

type Job struct {
	Name 			string			`ini:"host"`
	Enabled 		bool        	`ini:"enabled"`
	Ca 				Ca
	Target 			Target
}


type Config struct {
	Jobs 			[]Job 
	ConfPath 		string
}


