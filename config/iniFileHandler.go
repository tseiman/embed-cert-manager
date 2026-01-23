package config

/**
 *  Copyright (c) 2026 Thomas Schmidt
 *  SPDX-License-Identifier: MIT 
 *  home: https://github.com/tseiman/embed-cert-manager/
 * 
 *  Tool to check and eventually renew a certificate on an embedded client
 *  with limited software capabilities.
 * 
 *  Package config implements INI job discovery/loading and variable expansion.
 *  It maps INI keys into strongly-typed structs and prepares environment variables
 *  for shell execution on target systems.
 *
 */

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"reflect"
	"gopkg.in/ini.v1"
	
	"github.com/tseiman/embed-cert-manager/logger"
)

/**
 *  getFiles returns all *.conf files in the given directory (non-recursive).
 *
 *  Params:
 *    - dir: directory to scan.
 *
 *  Returns:
 *    - []string: full paths of discovered *.conf files.
 *
 */
func (c *Config) getFiles(dir string) ([]string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		logger.Errorf("read dir %q: %v", dir, err)
		return nil
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(e.Name()), ".conf") {
			logger.Infoln("Adding .conf file to queue: ",  filepath.Join(dir, e.Name()));
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}

	if len(files) == 0 {
		logger.Errorf("no .conf files found in %q", dir)
		return nil
	}

	return files

}


/**
 *  loadOneJobINI loads and parses a single job INI file.
 *  It maps INI sections and keys into a Job structure.
 *
 *  Params:
 *    - path: filesystem path to the job *.conf file.
 *
 *  Returns:
 *    - *Job: parsed job configuration, or nil if parsing failed.
 *
 */
func loadOneJobINI(path string) (*Job) {
	// Loose: unknown keys are ok (useful for comments and old stuff)
	// Insensitive: keys case-insensitive
	iniCfg, err := ini.LoadSources(ini.LoadOptions{
		Loose:       true,
		Insensitive: true,
	}, path)
	if err != nil {
		logger.Infof("parse ini %q: %v", path, err)
		return nil
	}

	var j Job

	secJob := iniCfg.Section("job")

	raw := secJob.Key("enabled").String()
	b, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {	
		logger.Errorf("invalid boolean value for job enable parameter %q: %v, disable DISABLE JOB", raw, err)
		j.Enabled= false
		return nil
	}


	j.Name = strings.TrimSpace(secJob.Key("host").String())
	if j.Name == "" {
		// Fallback: filename without ending
		base := filepath.Base(path)
		j.Name = strings.TrimSuffix(base, filepath.Ext(base))
		logger.Warnf("<%s> has no 'host' parameter configured in '[job]' section assuming <%s>\n",path,j.Name)

	}


	if b == false {
		logger.Infof("Job <%s> not enabled - skipping", j.Name)
		return nil
	}

	j.Enabled=  b

	if err := iniCfg.Section("ca").MapTo(&j.Ca); err != nil {
		logger.Errorf("%q: map [ca]: %v", path, err)
		return nil
	}
	if err := iniCfg.Section("target").MapTo(&j.Target); err != nil {
		logger.Errorf("%q: map [target]: %v", path, err)
		return nil
	}

	// trim the list becasue "a, b" would contain " b"
	//j.Target.SubjectAltName = trimSlice(j.Target.SubjectAltName)
	j.Finalize() 


	return &j
}


/**
 *  trimSlice trims whitespace from each element and removes empty entries.
 *
 *  Params:
 *    - in: input slice of strings.
 *
 *  Returns:
 *    - []string: cleaned slice.
 *
 */
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

/**
 *  Finalize performs post-processing on a Job after loading.
 *  It normalizes values, derives computed fields, and performs final adjustments.
 *
 */
func (j *Job) Finalize() {

    sec := ParseEJBCAValidity(j.Target.ChangeAfterRaw)
    j.Target.ChangeAfter = sec


    if fileExists(j.Ca.CACert) {
	    data, err := os.ReadFile(j.Ca.CACert)
		if err != nil {
			logger.Errorf("Finalize Load CA Certificate, job: %s, from file %s: %v\n",j.Name, j.Ca.CACert, err)
		} else {
			logger.Infof("Finalize Load CA Certificate, job: %s: %s\n",j.Name, j.Ca.CACert)

			j.Ca.CACertLoaded = string(data)
		}
	
	} else {
		logger.Warnf("Finalize Load CA Certificate, job: %s, not found %s - SKIPPING !\n",j.Name, j.Ca.CACert)
	}
 

}

/**
 *  GetShellVariables renders job, CA, and target values into shell-compatible
 *  environment variable assignments.
 *
 *  Params:
 *    - j: job providing source values.
 *
 *  Returns:
 *    - string: shell variable assignments prefixed by INI section names.
 *
 */
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

	}
    return result
}


/**
 *  ParseEJBCAValidity parses an EJBCA-style validity string into seconds.
 *  Supported units: y, mo, d, h, m, s.
 *
 *  Params:
 *    - s: validity string (e.g. "1y 2mo 4d 1h").
 *
 *  Returns:
 *    - uint64: total duration in seconds.
 *
 */
func ParseEJBCAValidity(s string) (uint64) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	
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

		// number read
		startNum := i
		for i < len(s) && unicode.IsDigit(rune(s[i])) {
			i++
		}
		if startNum == i {
			logger.Errorf("expected number at %q", s[startNum:])
			return 0
		}
		n64, err := strconv.ParseUint(s[startNum:i], 10, 64)
		if err != nil {
			logger.Errorf("invalid number %q: %v", s[startNum:i], err)
			return 0
		}

		// whitespace skip
		for i < len(s) && unicode.IsSpace(rune(s[i])) {
			i++
		}
		if i >= len(s) {
			logger.Errorf("missing unit after %d", n64)
			return 0
		}

		// unit read (important: "mo" comes in front of "m")
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
			logger.Errorf("unknown unit at %q (allowed: y, mo, d, h, m, s)", s[i:])
			return 0
		}

		// overflow-add securely
		add := n64 * mul
		if mul != 0 && add/mul != n64 {
			logger.Errorf("overflow computing %d * %d", n64, mul)
			return 0
		}
		if total > ^uint64(0)-add {
			logger.Errorf("overflow adding %d", add)
			return 0
		}
		total += add
	}

	return total
}


/**
 *  FieldByIniTag finds a struct field by its ini tag using reflection.
 *
 *  Params:
 *    - v: struct or pointer to struct to inspect.
 *    - iniName: INI tag name to search for.
 *
 *  Returns:
 *    - reflect.Value: matching field or invalid value if not found.
 *
 */
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
	logger.Errorf("ini tag %q not found", iniName)
	return reflect.Value{}
}

/**
 *  fileExists reports whether a file exists at the given path.
 *
 *  Params:
 *    - path: filesystem path to test.
 *
 *  Returns:
 *    - bool: true if the file exists.
 *
 */
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil || !os.IsNotExist(err)
}


