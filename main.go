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


		certCSR, err :=ssh.RunSSHCommand(job.Name +":" +  strconv.Itoa(job.Target.SSHPort) , job.Target.SSHUser, job.Target.SSHKey, job.Target.GetCmd(&job));

		if err != nil {
			log.Printf("ERROR job <%s> : %v",job.Name, err )
			continue
		}

		if certCSR.ParseCSRFromString() == nil {
			log.Println("ERROR Parsing CSR output")
			continue
		}
		

/*
		// Erstmal nur “kann ich verbinden?” testen:
		// Nimm irgendeinen Endpoint, der bei dir existiert (später EJBCA REST).
		req, _ := http.NewRequest("GET", baseURL+"/", nil)
		resp, err := c.Do(req)
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		log.Println("HTTP status:", resp.Status)
		log.Println(string(body))

*/

	}



//	log.Printf("%v\n", uint64(cfg.Jobs[0].Target.Runtime)) 

	
}

