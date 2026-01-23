package main


/**
 *  Copyright (c) 2026 Thomas Schmidt
 *  SPDX-License-Identifier: MIT 
 *  home: https://github.com/tseiman/embed-cert-manager/
 * 
 *  Tool to check and eventually renew a certificate on an embedded client
 *  with limited software capabilities.
 * 
 * Package main provides the Embedded Certificate Manager CLI.
 * It loads job configurations, checks certificate state via EJBCA, 
 * and updates certificates on targets via SSH.
 * 
 * */


import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"os"
	"log"
	"time"
	"github.com/tseiman/embed-cert-manager/config"
	"github.com/tseiman/embed-cert-manager/ssh"
	"github.com/tseiman/embed-cert-manager/ejbcaHttpsClient"
	"github.com/tseiman/embed-cert-manager/logger"
)


const (
	defaultConfigPath   = "/etc/embed-cert-manager.d"
	defaultForceCert    = false
	defaultLogLevel     = "warn"
	defaultVersionFlag  = false

)

var configPath string
var forcePullCert bool
var logLevel string
var versionFlag bool

var version     = "1.2.3" // per ldflags überschreibbar

/**
 *  initFlags defines and registers command-line flags used by the CLI.
 * */
func initFlags() {
	flag.StringVar(&configPath, 	"c", 		defaultConfigPath, 	"")
	flag.StringVar(&configPath, 	"config", 	defaultConfigPath, 	"")
	flag.BoolVar  (&forcePullCert, 	"f", 		defaultForceCert, 	"")
	flag.BoolVar  (&forcePullCert, 	"force", 	defaultForceCert,	"")
	flag.BoolVar  (&versionFlag, 	"v", 		defaultVersionFlag,	"")
	flag.BoolVar  (&versionFlag, 	"version", 	defaultVersionFlag,	"")
	flag.StringVar(&logLevel, 		"l", 		defaultLogLevel, 	"")
	flag.StringVar(&logLevel, 		"loglevel", defaultLogLevel, 	"")
}


/**
 *  initFlags defines and registers command-line flags used by the CLI.
 * */
func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Options:")
	fmt.Fprintf(os.Stderr,
		"  -c, --config  <path>     Configuration path to read *.conf files from.\n"+
		"                           (default: %s)\n"+
		"\n"+
		"  -f, --force              Force generation and poll of Zertifikate \n"+
		"                           even it is still valid (default: false)\n"+
		"\n"+
		"  -l, --loglevel <level>   Sets a verbosity level. Default is \"warn\". \n"+
		"                           Possible level: error | warn | info | debug\n"+
		"\n"+
		"  -v, --version            Prints the version and exits\n"+
		"\n",
		defaultConfigPath,
	)
}

/*
func version() {
	fmt.Fprintf(os.Stderr, "Version: %s,\n\n", os.Args[0])
	os.Exit(0)
}
*/
/**
 *  main is the CLI entrypoint.
 *  It parses flags and starts the Jobs
 * */
func main() {
//	log.SetFlags(log.LstdFlags | log.Lshortfile)

	initFlags()
	flag.Usage = usage
	flag.Parse()

	if versionFlag {
		fmt.Printf("embed-cert-manager: %s  (c) TS 2026\n", version)
		os.Exit(0)
	}


	switch strings.ToLower(logLevel) {
		case "error":
			logger.SetLevel(logger.LevelError)
		case "warn":
			logger.SetLevel(logger.LevelWarn)
		case "debug":
			logger.SetLevel(logger.LevelDebug)
		default:
			logger.SetLevel(logger.LevelInfo)
	}

	runJobs()

}

/**
 *  runJobs loads configuration/jobs, 
 *  and executes the renewal/update workflow.
 * */
func runJobs() {

	var cfg config.Config

	
	if cfg.Load(configPath + "/jobs.d") != nil { os.Exit(1) }
	if len(cfg.Jobs) == 0 {
		log.Println("No jobs to do - exiting"); 
		os.Exit(0) 
	}
	cfg.ConfPath = configPath



	for _, job := range cfg.Jobs {

		
		log.Printf("[START] main.c ------ starting job <%s> ------\n",job.Name)

		// 1.) create HTTP client with client certificate and server certificate check
		httpClient := ejbcaHttpsClient.NewMTLSClient(&job)
		if httpClient == nil {
			logger.Errorln("newMTLSClient")
			continue
		}
		// 2.) test connectivity to EJBCA
		if !ejbcaHttpsClient.TestConnection(&job,httpClient) {
			logger.Errorln("cant connect to EJBCA %s\n",job.Ca.Host)
			continue
		}

		// 3.) check if the CA has already a certifcate for this host (CN/username)
		//     if so we do not run this job further
		logger.Infoln("Check certificate exists");
		if ! ejbcaHttpsClient.CheckCertState(&job,httpClient) {
			if !forcePullCert {
				logger.Infof("------ skipping job <%s>, certificate exists and is valid. ------\n",job.Name)
				continue
			} else {
				logger.Warnf("NOT skipping job <%s>, certificate exists and is valid but forced by CLI \"-f\" parameter\n",job.Name)
			}
		}
		logger.Infoln("need to request certificate");

		// 4.) need to get e.g. CSR from target host
		logger.Infoln("Runn SSH");
		certCSR, err :=ssh.RunSSHCommand(job.Name +":" +  strconv.Itoa(job.Target.SSHPort) , job.Target.SSHUser, job.Target.SSHKey, job.GetCSRCmd());
		if err != nil {
			logger.Errorf("job <%s> : %v\n",job.Name, err )
			continue
		}

		// 5.) Analize CSR
		logger.Infoln("Parsing CSR");
		if certCSR.ParseCSRFromString() == nil {
			logger.Errorln("Parsing CSR output")
			continue
		}
		
		// 6.) Getting new Ccertificate from CA
		logger.Infoln("Getting new certificate from CA");
		cert := ejbcaHttpsClient.EnrollOrRenewCert(&job, httpClient, []byte(certCSR.CertCSR))
		if cert == nil {
			logger.Errorln("ejbcaHttpsClient")
			continue
		}


		// 7.) Convert the cetificate to PEM
		certBytes, err := ejbcaHttpsClient.CertToPEM(cert)
		if err != nil {
			log.Fatal(err)
		}

		// 7.) assemble ASCII armored (PEM) certificate 
		job.Target.Certificate = (
			"Subject: "  + cert.Subject.String() + "\n" +
			"Issuer: "   + cert.Issuer.String()  + "\n" +
			"NotAfter: " + cert.NotAfter.Format(time.RFC3339) + "\n" +
			string(certBytes) +
			"" )

		// 8.) Connect back to target host to issue cewrtifcate install script from INI file
		logger.Debugln("setting up SSH command:\n",job.GetCertSetCmd())
		_, err2 :=ssh.RunSSHCommand(job.Name +":" +  strconv.Itoa(job.Target.SSHPort) , job.Target.SSHUser, job.Target.SSHKey, job.GetCertSetCmd())
		if err2 != nil {
			log.Printf("job <%s> : %v\n",job.Name, err )
			continue
		}

		logger.Infof("------ finalized certifcate update for job <%s> ------\n",job.Name)

	}

}


