package main

import (
	"fmt"
	"strconv"
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
	if strings.Contains(source, "${") || strings.Contains(source, "$") {
		return fmt.Errorf("compose interpolation is not allowed")
	}
	if strings.Contains(lower, "image: ") && strings.Contains(lower, ":latest") && !strings.Contains(lower, "@sha256:") {
		return fmt.Errorf("floating latest tags without a digest are not allowed")
	}
	for _, line := range strings.Split(source, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "- ") && !strings.Contains(trimmed, ":") {
			continue
		}
		candidate := strings.Trim(strings.TrimPrefix(trimmed, "- "), `"'`)
		if port, ok := publishedPort(candidate); ok && reservedPorts[port] {
			return fmt.Errorf("host port %d is reserved for platform listeners", port)
		}
	}
	return nil
}

func publishedPort(item string) (int, bool) {
	cleaned := strings.TrimSuffix(strings.TrimSuffix(item, "/tcp"), "/udp")
	if strings.HasPrefix(cleaned, "[") {
		close := strings.Index(cleaned, "]:")
		if close > 0 {
			rest := strings.Split(cleaned[close+2:], ":")
			if len(rest) >= 1 {
				port, err := strconv.Atoi(rest[0])
				return port, err == nil
			}
		}
	}
	parts := strings.Split(cleaned, ":")
	if len(parts) == 3 {
		port, err := strconv.Atoi(parts[1])
		return port, err == nil
	}
	if len(parts) == 2 {
		port, err := strconv.Atoi(parts[0])
		return port, err == nil
	}
	return 0, false
}
