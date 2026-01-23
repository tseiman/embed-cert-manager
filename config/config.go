package config

/**
 *  Copyright (c) 2026 Thomas Schmidt
 *  SPDX-License-Identifier: MIT 
 *  home: https://github.com/tseiman/embed-cert-manager/
 * 
 *  Tool to check and eventually renew a certificate on an embedded client
 *  with limited software capabilities.
 * 
 * Package config contains configuration types and helpers for loading job INI files
 * and preparing the scripts/commands executed on target hosts.
 * 
 * */


import (
	"fmt"

	"github.com/tseiman/embed-cert-manager/logger"
)


/**
 *  Load reads all job configuration files from the given directory and populates c.Jobs. 
 * Params:
 *   - configPath: directory containing job *.conf files (INI format).
 * Returns:
 *   - error: non-nil if no jobs could be loaded or loading failed.
 * */
func (c *Config) Load(configPath string) (error) {

	logger.Infof("Loading *.conf files from folder: %s\n", configPath)

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


/**
 *  GetCSRCmd builds the shell command used to create a CSR on the target host.
 *  It extracts referenced variables from the configured CSR command and prefixes the script
 *  with the computed environment variable assignments.
 *  Returns:
 *     - string: ready-to-run shell command (env assignments + CSR command).
 * */
func (j *Job) GetCSRCmd() (string) { 

    j.Target.CommandEnvList = extractVars(j.Target.CSRCommand)
	cmd := j.Target.GetShellVariables(j)
	cmd += j.Target.CSRCommand
	return cmd
}

/**
 *  GetCertSetCmd builds the shell command used to install/update certificate material on the target host.
 *  It extracts referenced variables from the configured "set cert" command and prefixes the script
 *  with the computed environment variable assignments.
 *  Returns:
 *   - string: ready-to-run shell command (env assignments + set-cert command).
 * */
func (j *Job) GetCertSetCmd() (string) { 

    j.Target.CommandEnvList = extractVars(j.Target.SetCertCommand)

	cmd := j.Target.GetShellVariables(j)
	cmd += j.Target.SetCertCommand
	return cmd
}

