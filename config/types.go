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
}

type Target struct {
	SSHUser 		string 			`ini:"ssh_user"`
	SSHKey 			string 			`ini:"ssh_key"`
	SSHPort 		int 			`ini:"ssh_port"`
	CertPath 		string    		`ini:"cert_path"`
	KeyPath 		string    		`ini:"key_path"`
	CSRPath 		string 			`ini:"csr_path"`
	ReloadCmd 		string 	  		`ini:"reload_cmd"`
	SubjectAltName 	string 			`ini:"subjectAltName"` //delim:","
	Email 			string 		  	`ini:"email"`
	RuntimeRaw 		string 	  		`ini:"runtime"`
	Runtime 		uint64 			`ini:"-"`
	ChangeBeforeRaw string 			`ini:"change_before"`
	ChangeBefore 	uint64 			`ini:"-"`
	CSRCommand 		string 			`ini:"csr_command"`
	CommandEnvList 	[]EnvVariable  	`ini:"-"`
}

type Job struct {
	Name 			string			`ini:"host"`
	Enabled 		bool        	`ini:"enabled"`
	Ca 				Ca
	Target 			Target
}


type Config struct {
	Jobs 			[]Job 
}


