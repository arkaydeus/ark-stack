package main

import (
	"fmt"
	"strings"
)

var reservedPorts = map[int]bool{25: true, 80: true, 443: true, 465: true, 587: true, 993: true, 5432: true, 5433: true}

func validateCompose(source string) error {
	if len(source) > 64*1024 {
		return fmt.Errorf("compose document exceeds the 64 KiB input limit")
	}
	lower := strings.ToLower(source)
	for _, needle := range []string{"privileged:", "/var/run/docker.sock", "network_mode: host", "pid: host", "devices:", "cap_add:", "include:", "env_file:", "build:"} {
		if strings.Contains(lower, needle) {
			return fmt.Errorf("unsupported compose construct %q", needle)
		}
	}
	if strings.Contains(lower, "image: ") && strings.Contains(lower, ":latest") && !strings.Contains(lower, "@sha256:") {
		return fmt.Errorf("floating latest tags without a digest are not allowed")
	}
	for port := range reservedPorts {
		needleQuoted := fmt.Sprintf("\"%d:", port)
		needlePlain := fmt.Sprintf("- %d:", port)
		if strings.Contains(source, needleQuoted) || strings.Contains(source, needlePlain) {
			return fmt.Errorf("host port %d is reserved for platform listeners", port)
		}
	}
	return nil
}
