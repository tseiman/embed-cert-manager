package config



type Ca struct {
	Host string
	ClientCert string
	ClientKey string
}

type Target struct {
	CertPath string
	KeyPath string
	ReloadCmd string
	DNS []string
	IP []string
	Email string
	Runtime uint64
	ChangeBefore uint64
}

type Job struct {
	Name string	
	Ca Ca
	Target Target
}


type Config struct {
	Jobs []Job 
}


