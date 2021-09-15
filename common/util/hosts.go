package util

import (
	"errors"
	"io/ioutil"
	"os"
	"strings"
)

var hostsFile = "/etc/hosts"

func UpdateHosts(hosts map[string]string) error {
	if os.Getenv("RUNNING_IN_DOCKER") != "true" {
		return errors.New("the application is not running in docker")
	}

	old, err := ioutil.ReadFile(hostsFile)
	if err != nil {
		return err
	}

	var mergedHosts = make(map[string]string)
	for _, line := range strings.Split(strings.Trim(string(old), " \t\r\n"), "\n") {
		line = strings.Replace(strings.Trim(line, " \t"), "\t", " ", -1)
		if len(line) == 0 || line[0] == ';' || line[0] == '#' || line[0] == ':' {
			continue
		}
		pieces := strings.SplitN(line, " ", 2)
		if len(pieces) > 1 && len(pieces[0]) > 0 {
			if names := strings.Fields(pieces[1]); len(names) > 0 {
				for _, name := range names {
					if len(name) > 0 {
						mergedHosts[name] = pieces[0]
					}
				}
			}
		}
	}

	for k, v := range hosts {
		mergedHosts[k] = v
	}

	f, err := os.OpenFile(hostsFile, os.O_WRONLY|os.O_TRUNC, 0644)
	defer f.Close()

	for k, v := range mergedHosts {
		f.WriteString(v + "\t" + k + "\n")
	}
	return nil
}

