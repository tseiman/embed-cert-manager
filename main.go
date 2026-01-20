package main

import (
	"flag"
	"fmt"
	"strconv"
	"os"
	"log"
	"github.com/tseiman/embed-cert-manager/config"
	"github.com/tseiman/embed-cert-manager/ssh"
	"github.com/tseiman/embed-cert-manager/ejbcaHttpsClient"
)


const (
	defaultConfigPath = "/etc/embed-cert-manager.d"
)


var configPath string;

func initFlags() {
	flag.StringVar(&configPath, "c", defaultConfigPath, "")
	flag.StringVar(&configPath, "config", defaultConfigPath, "")
}



func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Options:")
	fmt.Fprintf(os.Stderr,
		"  -c, --config <path>     Configuration path to read *.conf files from.\n"+
		"                          (default: %s)\n"+
		"\n",
		defaultConfigPath,
	)
}


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

		certCSR, err :=ssh.RunSSHCommand(job.Name +":" +  strconv.Itoa(job.Target.SSHPort) , job.Target.SSHUser, job.Target.SSHKey, job.Target.GetCmd(&job));

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
			log.Printf("INFO: skipping %s\n",job.Name)
			continue
		}


log.Println("INFO: not skipping");
//		ejbcaHttpsClient.RequestCertificate(&job,)



	}



//	log.Printf("%v\n", uint64(cfg.Jobs[0].Target.Runtime)) 

	
}

