package config

/**
 *  Copyright (c) 2026 Thomas Schmidt
 *  SPDX-License-Identifier: MIT 
 *  home: https://github.com/tseiman/embed-cert-manager/
 * 
 *  Tool to check and eventually renew a certificate on an embedded client
 *  with limited software capabilities.
 * 
 *  Package config defines the core configuration model for embed-cert-manager.
 *  It contains structs that map INI job files into strongly typed Go structures.
 *
 */


/**
 *  EnvVariable describes a shell variable reference found in a script.
 *  It holds the original variable name and, if parseable, the corresponding INI section/key
 *  used to resolve the variable value.
 *
 */
type EnvVariable struct {
	ShellVariable 	string
	IniSection 		string
	IniVariable 	string

}

/**
 *  Ca contains CA/API related configuration for a job.
 *  It defines where the EJBCA SOAP API is located and which TLS material is used to access it.
 *  Fields are populated from the [ca] section in the job INI file via `ini:"..."` tags.
 *
 */
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


/**
 *  Target contains target-host related configuration for a job.
 *  It defines SSH access parameters, certificate/key/CSR paths on the target, renewal timing,
 *  and the shell commands used to create CSRs and install certificates.
 *  Fields are populated from the [target] section in the job INI file via `ini:"..."` tags.
 *
 */
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

/**
 *  Job represents a single certificate update unit ("job") for one target host.
 *  It combines CA configuration and target configuration and is typically loaded from one *.conf file.
 *  Fields are primarily populated from the [job] section (Name, Enabled) plus embedded [ca]/[target].
 *
 */
type Job struct {
	Name 			string			`ini:"host"`
	Enabled 		bool        	`ini:"enabled"`
	Ca 				Ca
	Target 			Target
}

/**
 *  Config is the top-level configuration container.
 *  It holds the list of loaded jobs and the base configuration path used for discovery.
 *
 */
type Config struct {
	Jobs 			[]Job 
	ConfPath 		string
}


