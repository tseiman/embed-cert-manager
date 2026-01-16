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



	var jobs []Job
	for _, path := range files {
		job := loadOneJobINI(path)
		if job != nil {
			jobs = append(jobs, *job)
		}

	}

	c.Jobs = jobs


	return nil
}

func (t *Target) GetCmd(j *Job) (string) { 

	cmd := t.GetShellVariables(j)
	cmd += t.CSRCommand
	return cmd
}

