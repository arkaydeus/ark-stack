package main

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func safeAdoptionInspection() containerInspection {
	var inspected containerInspection
	inspected.ID = "0123456789abcdef"
	inspected.Name = "/example-web-1"
	inspected.Config.Image = "docker.io/library/nginx:1.29@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	inspected.Config.Labels = map[string]string{
		"com.docker.compose.project": "example",
		"com.docker.compose.service": "web",
	}
	inspected.HostConfig.ReadonlyRootfs = true
	inspected.HostConfig.CapDrop = []string{"ALL"}
	inspected.HostConfig.SecurityOpt = []string{"no-new-privileges:true"}
	inspected.HostConfig.PidsLimit = 256
	inspected.HostConfig.Memory = 512 * 1024 * 1024
	inspected.HostConfig.NanoCPUs = 1_000_000_000
	inspected.NetworkSettings.Networks = map[string]json.RawMessage{"example_default": {}}
	return inspected
}

func TestAdoptionChecksEffectiveContainerIsolation(t *testing.T) {
	image := "docker.io/library/nginx:1.29@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	safe := safeAdoptionInspection()
	if err := validateAdoptableInspection(safe, "web", image); err != nil {
		t.Fatalf("safe container should be adoptable: %v", err)
	}

	tests := map[string]func(*containerInspection){
		"image substitution": func(item *containerInspection) { item.Config.Image = "docker.io/library/nginx:evil" },
		"writable root":      func(item *containerInspection) { item.HostConfig.ReadonlyRootfs = false },
		"capability add":     func(item *containerInspection) { item.HostConfig.CapAdd = []string{"SYS_ADMIN"} },
		"device": func(item *containerInspection) {
			item.HostConfig.Devices = []map[string]any{{"PathOnHost": "/dev/sda"}}
		},
		"host bind":        func(item *containerInspection) { item.HostConfig.Binds = []string{"/:/host"} },
		"unbounded pids":   func(item *containerInspection) { item.HostConfig.PidsLimit = 0 },
		"unbounded memory": func(item *containerInspection) { item.HostConfig.Memory = 0 },
		"unbounded cpu":    func(item *containerInspection) { item.HostConfig.NanoCPUs = 0 },
		"control network": func(item *containerInspection) {
			item.NetworkSettings.Networks = map[string]json.RawMessage{"ark_platform_control": {}}
		},
		"no-new-privileges false colon": func(item *containerInspection) {
			item.HostConfig.SecurityOpt = []string{"no-new-privileges:false"}
		},
		"no-new-privileges false equals": func(item *containerInspection) {
			item.HostConfig.SecurityOpt = []string{"no-new-privileges=false"}
		},
		"shared network namespace": func(item *containerInspection) {
			item.HostConfig.NetworkMode = "container:0123456789ab"
		},
		"shared pid namespace": func(item *containerInspection) {
			item.HostConfig.PidMode = "container:0123456789ab"
		},
		"shared ipc namespace": func(item *containerInspection) {
			item.HostConfig.IpcMode = "service:other"
		},
		"host network": func(item *containerInspection) { item.HostConfig.NetworkMode = "host" },
		"no network attachments": func(item *containerInspection) {
			item.NetworkSettings.Networks = map[string]json.RawMessage{}
		},
		"platform project network": func(item *containerInspection) {
			item.NetworkSettings.Networks = map[string]json.RawMessage{"ark-monitoring_default": {}}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			item := safeAdoptionInspection()
			mutate(&item)
			if err := validateAdoptableInspection(item, "web", image); err == nil {
				t.Fatal("unsafe effective configuration was accepted")
			}
		})
	}
}

func TestAdoptionServiceMustExistInCanonicalManifest(t *testing.T) {
	compose := `services:
  web:
    image: docker.io/library/nginx:1.29@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    read_only: true
    init: true
    pids_limit: 256
    mem_limit: 512m
    cpus: 1
    tmpfs: ["/tmp:rw,noexec,nosuid,nodev,size=64m"]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
`
	image, err := composeServiceImage(compose, "web")
	if err != nil || image != "docker.io/library/nginx:1.29@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("expected image extraction, got %q, %v", image, err)
	}
	if _, err := composeServiceImage(compose, "other"); err == nil {
		t.Fatal("missing adoption service was accepted")
	}
}

func TestAgentLogResultsAreDecodedBoundedAndRedacted(t *testing.T) {
	payload := []byte("password=hunter2\ntoken: abc123\nready\n")
	frame := make([]byte, 8+len(payload))
	frame[0] = 1
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(payload)))
	copy(frame[8:], payload)
	lines := safeLogLines(decodeDockerLogs(frame))
	joined := strings.Join(lines, "\n")
	if strings.Contains(joined, "hunter2") || strings.Contains(joined, "abc123") {
		t.Fatal("sensitive log values were not redacted")
	}
	if !strings.Contains(joined, "ready") || !strings.Contains(joined, "[REDACTED]") {
		t.Fatalf("expected decoded, redacted log output, got %q", joined)
	}

	many := strings.Repeat("line\n", 700)
	if got := len(safeLogLines(many)); got > 500 {
		t.Fatalf("log output was not bounded: %d lines", got)
	}
}
