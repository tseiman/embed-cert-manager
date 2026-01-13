package main

import (
	"flag"
	"fmt"
	"os"
	"log"
	"github.com/tseiman/embed-cert-manager/config"
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



	log.Printf("%v\n", cfg.Jobs[0])

	
}

