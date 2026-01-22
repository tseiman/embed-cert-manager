package main


/**
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
	"os"
	"log"
	"time"
	"github.com/tseiman/embed-cert-manager/config"
	"github.com/tseiman/embed-cert-manager/ssh"
	"github.com/tseiman/embed-cert-manager/ejbcaHttpsClient"
)


const (
	defaultConfigPath = "/etc/embed-cert-manager.d"
)


var configPath string;
var forcePullCert bool;


/**
 *  initFlags defines and registers command-line flags used by the CLI.
 * */
func initFlags() {
	flag.StringVar(&configPath, "c", defaultConfigPath, "")
	flag.StringVar(&configPath, "config", defaultConfigPath, "")
	flag.BoolVar(&forcePullCert, "f", false, "")
	flag.BoolVar(&forcePullCert, "force", false, "")
}


/**
 *  initFlags defines and registers command-line flags used by the CLI.
 * */
func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Options:")
	fmt.Fprintf(os.Stderr,
		"  -c, --config <path>     Configuration path to read *.conf files from.\n"+
		"                          (default: %s)\n"+
		"\n"+
		"  -f, --force             Force generation and poll of Zertifikate \n"+
		"                          even it is still valid (default: false)\n"+
		"\n",
		defaultConfigPath,
	)
}

/**
 *  main is the CLI entrypoint.
 * It parses flags, loads configuration/jobs, 
 * and executes the renewal/update workflow.
 * */
func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var cfg config.Config
	initFlags()
	flag.Usage = usage
	flag.Parse()

	if cfg.Load(configPath + "/jobs.d") != nil { os.Exit(1) }
	if len(cfg.Jobs) == 0 {
		log.Println("No jobs to do - exiting"); 
		os.Exit(0) 
	}
	cfg.ConfPath = configPath



	for _, job := range cfg.Jobs {


		httpClient := ejbcaHttpsClient.NewMTLSClient(&job)
		if httpClient == nil {
			log.Println("ERROR newMTLSClient")
			continue
		}
		if !ejbcaHttpsClient.TestConnection(&job,httpClient) {
			log.Printf("ERROR cant connect to EJBCA %s\n",job.Ca.Host)
			continue
		}
		log.Println("INFO: Runn SSH");

		certCSR, err :=ssh.RunSSHCommand(job.Name +":" +  strconv.Itoa(job.Target.SSHPort) , job.Target.SSHUser, job.Target.SSHKey, job.GetCSRCmd());

		if err != nil {
			log.Printf("ERROR job <%s> : %v\n",job.Name, err )
			continue
		}

		log.Println("INFO: Parsing CSR");
		if certCSR.ParseCSRFromString() == nil {
			log.Println("ERROR Parsing CSR output")
			continue
		}
		


		log.Println("INFO: Check certificate exists");
		if ! ejbcaHttpsClient.CheckCertState(&job,httpClient) {
			log.Printf("INFO: skipping %s, certificate exists and is valid.\n",job.Name)
			if !forcePullCert {
				continue
			}
		}

		log.Println("INFO: need to request certificate");



//		ejbcaHttpsClient.RequestCertificate(&job,)
		cert := ejbcaHttpsClient.EnrollOrRenewCert(&job, httpClient, []byte(certCSR.CertCSR))

		if cert == nil {
			log.Printf("ERROR ejbcaHttpsClient\n")
			continue
		}

		

		certBytes, err := ejbcaHttpsClient.CertToPEM(cert)
		if err != nil {
			log.Fatal(err)
		}

		job.Target.Certificate = (
			"Subject: "  + cert.Subject.String() + "\n" +
			"Issuer: "   + cert.Issuer.String()  + "\n" +
			"NotAfter: " + cert.NotAfter.Format(time.RFC3339) + "\n" +
			string(certBytes) +
			"" )

		log.Println("INFO: command:\n",job.GetCertSetCmd())

		_, err2 :=ssh.RunSSHCommand(job.Name +":" +  strconv.Itoa(job.Target.SSHPort) , job.Target.SSHUser, job.Target.SSHKey, job.GetCertSetCmd())

		if err2 != nil {
			log.Printf("ERROR job <%s> : %v\n",job.Name, err )
			continue
		}


	}


//	log.Printf("%v\n", uint64(cfg.Jobs[0].Target.Runtime)) 

	
}

