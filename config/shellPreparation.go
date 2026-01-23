package config


/**
 *  Copyright (c) 2026 Thomas Schmidt
 *  SPDX-License-Identifier: MIT 
 *  home: https://github.com/tseiman/embed-cert-manager/
 * 
 *  Tool to check and eventually renew a certificate on an embedded client
 *  with limited software capabilities.
 * 
 *  Package config provides helpers for preparing shell scripts from job configuration.
 *  It extracts referenced configuration variables from shell snippets so they can be
 *  exported as environment variables before executing the script on a target host.
 *
 */

import (
	"regexp"

	"github.com/tseiman/embed-cert-manager/logger"
)


/**
 *  extractVars scans a shell snippet and extracts referenced variables of the form ${...}.
 *  It expects variables to follow the convention "<section>_<key>" (e.g. target_key_path),
 *  so they can be mapped back to INI sections and keys.
 *
 *  Params:
 *    - s: shell script/command text to scan for ${...} references.
 *
 *  Returns:
 *    - []EnvVariable: list of extracted variable references (deduplicated). Entries may contain
 *      empty ShellVariable values if a reference cannot be parsed into "<section>_<key>" form.
 *
 */
func extractVars(s string) []EnvVariable {
	reExtracatVar := regexp.MustCompile(`\$\{([^}]+)\}`)
	reGetPrefixAndVar := regexp.MustCompile(`^([-a-zA-Z0-9]+)_([-a-zA-Z0-9_]+)$`)
	matches := reExtracatVar.FindAllStringSubmatch(s, -1)

	seen := make(map[string]struct{})
	var vars []EnvVariable

	for _, m := range matches {
		name := m[1] // Inhalt innerhalb ${...}
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			prefixAndName := reGetPrefixAndVar.FindStringSubmatch(name)
			if len(prefixAndName) == 3 {
				vars = append(vars, EnvVariable{ShellVariable : name, IniSection : prefixAndName[1] , IniVariable : prefixAndName[2] })
			} else {
				logger.Errorf("can't extract variable becasue it seems to have no prefix %s (e.g. target_subjectAltName)", name, prefixAndName)
				vars = append(vars, EnvVariable{ShellVariable : ""})
			}

		}
	}
	return vars
}
