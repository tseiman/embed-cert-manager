package config

import (
	"log"
	"fmt"
//	"strings"

//	"gopkg.in/ini.v1"
)


func (c *Config) Load(configPath string) (error) {

	log.Printf("Loading *.conf files from folder: %s\n", configPath)

	var files = c.getFiles(configPath)

	if files == nil {
		return fmt.Errorf("File list was empty")
	}
/*
	job := Job{}
	job.Name = "webserver-cert"
	
	job.Ca = Ca{
		Host:       "https://acme.example",
		ClientCert: "/etc/ca/client.crt",
		ClientKey:  "/etc/ca/client.key",
	}
	job.Target = Target{
		CertPath:  "/etc/nginx/cert.pem",
		KeyPath:   "/etc/nginx/key.pem",
		DNS:       []string{"example.com"},
		Email:     "admin@example.com",
	}

	c.Jobs = append(c.Jobs, job)

*/


	var jobs []Job
	for _, path := range files {
		job := loadOneJobINI(path)
		if job == nil {
			return nil
		}
		jobs = append(jobs, *job)
	}

	c.Jobs = jobs


	return nil
}


