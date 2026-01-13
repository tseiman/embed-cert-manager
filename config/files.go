package config

import (
//	"fmt"
	"log"
	"os"
	"path/filepath"
//	"sort"
	"strings"

	"gopkg.in/ini.v1"
)


func (c *Config) getFiles(dir string) ([]string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("ERROR: read dir %q: %v", dir, err)
		return nil
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(e.Name()), ".conf") {
			log.Println("Adding .conf file to queue: ",  filepath.Join(dir, e.Name()));
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}

//	sort.Strings(files)

	if len(files) == 0 {
		log.Printf("ERROR: no .conf files found in %q", dir)
		return nil
	}

	return files

}



func loadOneJobINI(path string) (*Job) {
	// Loose: unbekannte Keys sind ok (praktisch für Kommentare/Altlasten)
	// Insensitive: keys case-insensitive
	iniCfg, err := ini.LoadSources(ini.LoadOptions{
		Loose:       true,
		Insensitive: true,
	}, path)
	if err != nil {
		log.Printf("parse ini %q: %v", path, err)
		return nil
	}

	var j Job

	secJob := iniCfg.Section("job")
	j.Name = strings.TrimSpace(secJob.Key("host").String())
	if j.Name == "" {
		// Fallback: Dateiname ohne Endung
		base := filepath.Base(path)
		j.Name = strings.TrimSuffix(base, filepath.Ext(base))
		log.Printf("WARNING: <%s> has no 'host' parameter configured in '[job]' section assuming <%s>\n",path,j.Name)

	}
/*
	if err := iniCfg.Section("ca").MapTo(&j.Ca); err != nil {
		return nil, fmt.Errorf("%q: map [ca]: %w", path, err)
	}
	if err := iniCfg.Section("target").MapTo(&j.Target); err != nil {
		return nil, fmt.Errorf("%q: map [target]: %w", path, err)
	}

	// Trimmen der Listen, weil "a, b" sonst " b" enthält
	j.Target.DNS = trimSlice(j.Target.DNS)
	j.Target.IP = trimSlice(j.Target.IP)
*/
	return &j
}




