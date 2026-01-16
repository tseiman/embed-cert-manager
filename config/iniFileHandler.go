package config

import (
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"reflect"
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

	raw := secJob.Key("enabled").String()
	b, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {	
		log.Printf("ERROR: invalid boolean value for job enable parameter %q: %v, disable DISABLE JOB", raw, err)
		j.Enabled= false
		return nil
	}


	j.Name = strings.TrimSpace(secJob.Key("host").String())
	if j.Name == "" {
		// Fallback: Dateiname ohne Endung
		base := filepath.Base(path)
		j.Name = strings.TrimSuffix(base, filepath.Ext(base))
		log.Printf("WARNING: <%s> has no 'host' parameter configured in '[job]' section assuming <%s>\n",path,j.Name)

	}


	if b == false {
		log.Printf("INFO: Job <%s> not enabled - skipping", j.Name)
		return nil
	}

	j.Enabled=  b

	if err := iniCfg.Section("ca").MapTo(&j.Ca); err != nil {
		log.Printf("ERROR :%q: map [ca]: %v", path, err)
		return nil
	}
	if err := iniCfg.Section("target").MapTo(&j.Target); err != nil {
		log.Printf("ERROR :%q: map [target]: %v", path, err)
		return nil
	}

	// Trimmen der Listen, weil "a, b" sonst " b" enthält
	//j.Target.SubjectAltName = trimSlice(j.Target.SubjectAltName)
	j.Target.Finalize() 


	return &j
}



func trimSlice(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		t := strings.TrimSpace(s)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func (t *Target) Finalize() {
    sec := ParseEJBCAValidity(t.RuntimeRaw)
    t.Runtime = sec

    sec = ParseEJBCAValidity(t.ChangeBeforeRaw)
    t.ChangeBefore = sec

    t.CommandEnvList = extractVars(t.CSRCommand)

}


func (t *Target) GetShellVariables(j *Job) (string) {

	result := ""
    
    for _, envVar := range t.CommandEnvList { 
   	
    	var value reflect.Value

    	switch envVar.IniSection {
			case "job":
				value = FieldByIniTag(j, envVar.IniVariable)
			case "ca":
				value = FieldByIniTag(j.Ca, envVar.IniVariable)
			default:
				value = FieldByIniTag(j.Target, envVar.IniVariable)
		} 	

		line := envVar.IniSection + "_" + envVar.IniVariable + "=\"" + value.String() + "\""
		result += line + "\n"
//		log.Printf("Adding variable %s\n", line)
//log.Printf("Adding variable %s_%s=%s\n", envVar.IniSection, envVar.IniVariable, value)

	}
	

    return result

}




func ParseEJBCAValidity(s string) (uint64) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}

	// Sekunden-Definitionen (wie von dir angenommen)
	const (
		secPerMinute = 60
		secPerHour   = 60 * secPerMinute
		secPerDay    = 24 * secPerHour
		secPerYear   = 31557600             // 365.25d
		secPerMonth  = secPerYear / 12      // 2629800
	)

	var total uint64
	i := 0
	for i < len(s) {
		// whitespace skip
		for i < len(s) && unicode.IsSpace(rune(s[i])) {
			i++
		}
		if i >= len(s) {
			break
		}

		// number lesen
		startNum := i
		for i < len(s) && unicode.IsDigit(rune(s[i])) {
			i++
		}
		if startNum == i {
			log.Printf("expected number at %q", s[startNum:])
			return 0
		}
		n64, err := strconv.ParseUint(s[startNum:i], 10, 64)
		if err != nil {
			log.Printf("invalid number %q: %v", s[startNum:i], err)
			return 0
		}

		// whitespace skip
		for i < len(s) && unicode.IsSpace(rune(s[i])) {
			i++
		}
		if i >= len(s) {
			log.Printf("missing unit after %d", n64)
			return 0
		}

		// unit lesen (wichtig: "mo" vor "m")
		var mul uint64
		switch {
		case strings.HasPrefix(s[i:], "mo"):
			mul = secPerMonth
			i += 2
		case strings.HasPrefix(s[i:], "y"):
			mul = secPerYear
			i += 1
		case strings.HasPrefix(s[i:], "d"):
			mul = secPerDay
			i += 1
		case strings.HasPrefix(s[i:], "h"):
			mul = secPerHour
			i += 1
		case strings.HasPrefix(s[i:], "m"):
			mul = secPerMinute
			i += 1
		case strings.HasPrefix(s[i:], "s"):
			mul = 1
			i += 1
		default:
			log.Printf("unknown unit at %q (allowed: y, mo, d, h, m, s)", s[i:])
			return 0
		}

		// overflow-sicher addieren
		add := n64 * mul
		if mul != 0 && add/mul != n64 {
			log.Printf("overflow computing %d * %d", n64, mul)
			return 0
		}
		if total > ^uint64(0)-add {
			log.Printf("overflow adding %d", add)
			return 0
		}
		total += add
	}

	return total
}



func FieldByIniTag(v any, iniName string) (reflect.Value) {
	rv := reflect.ValueOf(v)

	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}

	rt := rv.Type()

	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		tag := field.Tag.Get("ini")

		if tag == iniName {
			return rv.Field(i)
		}
	}
	log.Printf("ERROR: ini tag %q not found", iniName)
	return reflect.Value{}
}



