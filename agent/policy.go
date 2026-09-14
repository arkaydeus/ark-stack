package main

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxComposeBytes = 64 * 1024
const maxComposeServices = 20

var reservedPorts = map[int]bool{25: true, 80: true, 443: true, 465: true, 587: true, 993: true, 5432: true, 5433: true}
var resourceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)
var allowedTop = set("services", "volumes", "networks")
var allowedService = set("image", "command", "entrypoint", "environment", "ports", "expose", "volumes", "networks", "depends_on", "restart", "healthcheck", "labels", "user", "working_dir", "read_only", "tmpfs", "stop_grace_period", "init", "pids_limit", "mem_limit", "cpus", "cap_drop", "security_opt")

func set(values ...string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

func validateCompose(source string) error {
	if len(source) > maxComposeBytes {
		return fmt.Errorf("compose document exceeds the 64 KiB input limit")
	}
	if strings.Contains(source, "$") {
		return fmt.Errorf("compose interpolation is not allowed")
	}

	decoder := yaml.NewDecoder(bytes.NewBufferString(source))
	var root yaml.Node
	if err := decoder.Decode(&root); err != nil {
		return fmt.Errorf("invalid compose YAML: %w", err)
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("compose must contain exactly one YAML document")
	}
	if err := validateYAMLNode(&root, 0); err != nil {
		return err
	}
	if len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("compose document must be a mapping")
	}
	var doc map[string]any
	if err := root.Content[0].Decode(&doc); err != nil {
		return fmt.Errorf("invalid compose model: %w", err)
	}
	for key := range doc {
		if !allowedTop[key] {
			return fmt.Errorf("unsupported top-level field %q", key)
		}
	}

	services, ok := stringMap(doc["services"])
	if !ok || len(services) == 0 {
		return fmt.Errorf("services must be a non-empty mapping")
	}
	if len(services) > maxComposeServices {
		return fmt.Errorf("at most %d services are allowed", maxComposeServices)
	}
	volumes, err := resources(doc["volumes"], "volume")
	if err != nil {
		return err
	}
	networks, err := resources(doc["networks"], "network")
	if err != nil {
		return err
	}

	for name, raw := range services {
		service, ok := stringMap(raw)
		if !ok {
			return fmt.Errorf("service %q must be a mapping", name)
		}
		for key := range service {
			if !allowedService[key] {
				return fmt.Errorf("unsupported service field %q on %s", key, name)
			}
		}
		image, ok := service["image"].(string)
		if !ok || image == "" {
			return fmt.Errorf("service %q requires a prebuilt image", name)
		}
		if strings.HasSuffix(strings.Split(image, "@")[0], ":latest") && !strings.Contains(image, "@sha256:") {
			return fmt.Errorf("floating latest tags without a digest are not allowed")
		}
		if err := validateSandbox(service); err != nil {
			return fmt.Errorf("service %s: %w", name, err)
		}
		if err := validatePorts(service["ports"]); err != nil {
			return fmt.Errorf("service %s: %w", name, err)
		}
		if err := validateMounts(service["volumes"], volumes); err != nil {
			return fmt.Errorf("service %s: %w", name, err)
		}
		if err := validateNetworks(service["networks"], networks); err != nil {
			return fmt.Errorf("service %s: %w", name, err)
		}
	}
	return nil
}

func validateSandbox(service map[string]any) error {
	if readOnly, ok := service["read_only"].(bool); !ok || !readOnly {
		return fmt.Errorf("canonical read_only=true is required")
	}
	if init, ok := service["init"].(bool); !ok || !init {
		return fmt.Errorf("canonical init=true is required")
	}
	pids, ok := number(service["pids_limit"])
	if !ok || pids != 256 {
		return fmt.Errorf("canonical pids_limit=256 is required")
	}
	if memory, ok := service["mem_limit"].(string); !ok || memory != "512m" {
		return fmt.Errorf("canonical mem_limit=512m is required")
	}
	var cpus float64
	switch value := service["cpus"].(type) {
	case int:
		cpus = float64(value)
	case float64:
		cpus = value
	default:
		return fmt.Errorf("canonical cpus=1 is required")
	}
	if cpus != 1 {
		return fmt.Errorf("canonical cpus=1 is required")
	}
	capDrop, ok := list(service["cap_drop"])
	if !ok || len(capDrop) != 1 || !strings.EqualFold(fmt.Sprint(capDrop[0]), "ALL") {
		return fmt.Errorf("canonical cap_drop=ALL is required")
	}
	securityOpt, ok := list(service["security_opt"])
	if !ok || len(securityOpt) != 1 || strings.ToLower(fmt.Sprint(securityOpt[0])) != "no-new-privileges:true" {
		return fmt.Errorf("canonical no-new-privileges security option is required")
	}
	tmpfs, ok := list(service["tmpfs"])
	if !ok || len(tmpfs) != 1 || fmt.Sprint(tmpfs[0]) != "/tmp:rw,noexec,nosuid,nodev,size=64m" {
		return fmt.Errorf("canonical bounded /tmp mount is required")
	}
	return nil
}

func composeServiceImage(source, serviceName string) (string, error) {
	if err := validateCompose(source); err != nil {
		return "", err
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(source), &doc); err != nil {
		return "", fmt.Errorf("invalid canonical compose model: %w", err)
	}
	services, ok := stringMap(doc["services"])
	if !ok {
		return "", fmt.Errorf("canonical compose services are invalid")
	}
	raw, ok := services[serviceName]
	if !ok {
		return "", fmt.Errorf("adoption service is absent from the canonical compose manifest")
	}
	service, ok := stringMap(raw)
	if !ok {
		return "", fmt.Errorf("adoption service definition is invalid")
	}
	image, ok := service["image"].(string)
	if !ok || image == "" {
		return "", fmt.Errorf("adoption service image is invalid")
	}
	return image, nil
}

func validateYAMLNode(node *yaml.Node, depth int) error {
	if depth > 32 {
		return fmt.Errorf("compose nesting exceeds policy limit")
	}
	if node.Kind == yaml.AliasNode || node.Anchor != "" {
		return fmt.Errorf("YAML anchors and aliases are not allowed")
	}
	if node.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i].Value
			if key == "<<" {
				return fmt.Errorf("YAML merge keys are not allowed")
			}
			if seen[key] {
				return fmt.Errorf("duplicate YAML key %q", key)
			}
			seen[key] = true
		}
	}
	for _, child := range node.Content {
		if err := validateYAMLNode(child, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func stringMap(value any) (map[string]any, bool) {
	if value == nil {
		return map[string]any{}, true
	}
	result, ok := value.(map[string]any)
	return result, ok
}

func reservedResource(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{"ark_", "ark-", "platform", "control", "docker"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func resources(value any, kind string) (map[string]any, error) {
	items, ok := stringMap(value)
	if !ok {
		return nil, fmt.Errorf("%ss must be a mapping", kind)
	}
	for name, raw := range items {
		if !resourceName.MatchString(name) || reservedResource(name) {
			return nil, fmt.Errorf("%s name %q is reserved or invalid", kind, name)
		}
		if raw == nil {
			continue
		}
		config, ok := stringMap(raw)
		if !ok || len(config) != 0 {
			return nil, fmt.Errorf("%s %q options, external resources, drivers, and global names are not allowed", kind, name)
		}
	}
	return items, nil
}

func list(value any) ([]any, bool) {
	if value == nil {
		return nil, true
	}
	items, ok := value.([]any)
	return items, ok
}

func validatePorts(value any) error {
	items, ok := list(value)
	if !ok {
		return fmt.Errorf("ports must be a list")
	}
	for _, item := range items {
		var port int
		var found bool
		switch typed := item.(type) {
		case int:
			port, found = typed, true
		case string:
			if strings.Contains(typed, "-") {
				return fmt.Errorf("port ranges are not allowed")
			}
			port, found = publishedPort(typed)
		case map[string]any:
			if len(typed) > 3 {
				return fmt.Errorf("unsupported long port options")
			}
			for key := range typed {
				if key != "published" && key != "target" && key != "protocol" {
					return fmt.Errorf("unsupported port option %q", key)
				}
			}
			port, found = number(typed["published"])
		default:
			return fmt.Errorf("invalid port entry")
		}
		if !found {
			return fmt.Errorf("ambiguous port entry")
		}
		if reservedPorts[port] {
			return fmt.Errorf("host port %d is reserved for platform listeners", port)
		}
	}
	return nil
}

func number(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case string:
		n, err := strconv.Atoi(typed)
		return n, err == nil
	default:
		return 0, false
	}
}

func validateMounts(value any, declared map[string]any) error {
	items, ok := list(value)
	if !ok {
		return fmt.Errorf("volumes must be a list")
	}
	for _, item := range items {
		var source string
		switch typed := item.(type) {
		case string:
			parts := strings.Split(typed, ":")
			if len(parts) < 2 {
				continue
			}
			source = parts[0]
			if strings.HasPrefix(source, "/") || strings.HasPrefix(source, ".") || strings.Contains(source, "docker.sock") {
				return fmt.Errorf("bind mounts and host paths are not allowed")
			}
		case map[string]any:
			mountType, _ := typed["type"].(string)
			if mountType == "bind" {
				return fmt.Errorf("bind mounts are not allowed")
			}
			for key := range typed {
				if key != "type" && key != "source" && key != "target" && key != "read_only" {
					return fmt.Errorf("unsupported mount option %q", key)
				}
			}
			source, _ = typed["source"].(string)
		default:
			return fmt.Errorf("invalid mount entry")
		}
		if source != "" {
			if _, ok := declared[source]; !ok {
				return fmt.Errorf("named volume %q must be declared and workload-owned", source)
			}
		}
	}
	return nil
}

func validateNetworks(value any, declared map[string]any) error {
	if value == nil {
		return nil
	}
	names := []string{}
	if items, ok := value.([]any); ok {
		for _, item := range items {
			name, ok := item.(string)
			if !ok {
				return fmt.Errorf("network names must be strings")
			}
			names = append(names, name)
		}
	} else if mapping, ok := stringMap(value); ok {
		for name, options := range mapping {
			if options != nil {
				config, ok := stringMap(options)
				if !ok || len(config) != 0 {
					return fmt.Errorf("per-service network options are not allowed")
				}
			}
			names = append(names, name)
		}
	} else {
		return fmt.Errorf("networks must be a list or mapping")
	}
	for _, name := range names {
		if _, ok := declared[name]; !ok {
			return fmt.Errorf("network %q must be declared and workload-owned", name)
		}
	}
	return nil
}

func publishedPort(item string) (int, bool) {
	cleaned := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(item), "/tcp"), "/udp")
	if strings.HasPrefix(cleaned, "[") {
		close := strings.Index(cleaned, "]:")
		if close > 0 {
			parts := strings.Split(cleaned[close+2:], ":")
			if len(parts) == 2 {
				port, err := strconv.Atoi(parts[0])
				return port, err == nil
			}
		}
		return 0, false
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
	if len(parts) == 1 {
		port, err := strconv.Atoi(parts[0])
		return port, err == nil
	}
	return 0, false
}
