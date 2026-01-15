package config


import (
	"log"
	"regexp"
)

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
				log.Printf("ERROR: can't extract variable becasue it seems to have no prefix %s (e.g. target_subjectAltName)", name, prefixAndName)
				vars = append(vars, EnvVariable{ShellVariable : ""})
			}

		}
	}
	return vars
}
