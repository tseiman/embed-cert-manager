package main

import (
	"flag"
	"fmt"
	"strconv"
	"os"
	"log"
	"github.com/tseiman/embed-cert-manager/config"
	"github.com/tseiman/embed-cert-manager/ssh"
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

	if cfg.Load(configPath) != nil { os.Exit(1) }
	if len(cfg.Jobs) == 0 {
		log.Println("No jobs to do - exiting"); 
		os.Exit(0) 
	}


	for _, job := range cfg.Jobs {
		out, errOut, err :=ssh.RunSSHCommand(job.Name +":" +  strconv.Itoa(job.Target.SSHPort) , job.Target.SSHUser, job.Target.SSHKey, job.Target.GetCmd(&job));



		log.Printf("========== JOB %s ============\n",job.Name )
		log.Printf("STDOUT\n%s\n\n",out )
		log.Printf("------------------------------\n")
		log.Printf("STFERR\n%s\n\n",errOut )
		log.Printf("========== /JOB ============\n" )
		if err != nil {
			log.Printf("ERROR job <%s> : %v",job.Name, err )
			continue
		}



	}


//	 log.Printf("%v\n", cfg.Jobs)

//	log.Printf("%v\n", uint64(cfg.Jobs[0].Target.Runtime)) 

	
}

