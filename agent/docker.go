package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func dockerHTTP() *http.Client {
	sock := getenv("DOCKER_SOCKET", "/var/run/docker.sock")
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		},
	}
}

func dockerJSON(method, path string, body any) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, "http://docker"+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := dockerHTTP().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 300 {
		return nil, fmt.Errorf("docker %s %s: %s", method, path, strings.TrimSpace(string(payload)))
	}
	return payload, nil
}

type containerSummary struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Image  string            `json:"Image"`
	State  string            `json:"State"`
	Labels map[string]string `json:"Labels"`
}

type networkSummary struct {
	ID     string            `json:"Id"`
	Name   string            `json:"Name"`
	Labels map[string]string `json:"Labels"`
}

type volumeSummary struct {
	Name   string            `json:"Name"`
	Labels map[string]string `json:"Labels"`
}

type containerInspection struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Image  string `json:"Image"`
	Config struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		Privileged     bool             `json:"Privileged"`
		NetworkMode    string           `json:"NetworkMode"`
		PidMode        string           `json:"PidMode"`
		IpcMode        string           `json:"IpcMode"`
		Binds          []string         `json:"Binds"`
		CapAdd         []string         `json:"CapAdd"`
		CapDrop        []string         `json:"CapDrop"`
		ReadonlyRootfs bool             `json:"ReadonlyRootfs"`
		SecurityOpt    []string         `json:"SecurityOpt"`
		PidsLimit      int64            `json:"PidsLimit"`
		Memory         int64            `json:"Memory"`
		NanoCPUs       int64            `json:"NanoCpus"`
		Devices        []map[string]any `json:"Devices"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]json.RawMessage `json:"Networks"`
	} `json:"NetworkSettings"`
}

func workloadResources(project string) ([]string, []string, error) {
	networkRaw, err := dockerJSON(http.MethodGet, "/networks", nil)
	if err != nil {
		return nil, nil, err
	}
	var networks []networkSummary
	if err := json.Unmarshal(networkRaw, &networks); err != nil {
		return nil, nil, err
	}
	volumeRaw, err := dockerJSON(http.MethodGet, "/volumes", nil)
	if err != nil {
		return nil, nil, err
	}
	var volumeResponse struct {
		Volumes []volumeSummary `json:"Volumes"`
	}
	if err := json.Unmarshal(volumeRaw, &volumeResponse); err != nil {
		return nil, nil, err
	}
	networkIDs := []string{}
	volumeNames := []string{}
	for _, network := range networks {
		if network.Labels["com.docker.compose.project"] == project {
			networkIDs = append(networkIDs, network.ID)
		}
	}
	for _, volume := range volumeResponse.Volumes {
		if volume.Labels["com.docker.compose.project"] == project {
			volumeNames = append(volumeNames, volume.Name)
		}
	}
	return networkIDs, volumeNames, nil
}

func assertAttachedResourcesOwned(inspected containerInspection, project string) ([]string, []string, error) {
	networkIDs, volumeNames, err := workloadResources(project)
	if err != nil {
		return nil, nil, err
	}
	ownedNetworks := map[string]bool{}
	networkRaw, err := dockerJSON(http.MethodGet, "/networks", nil)
	if err != nil {
		return nil, nil, err
	}
	var networks []networkSummary
	if err := json.Unmarshal(networkRaw, &networks); err != nil {
		return nil, nil, err
	}
	for _, network := range networks {
		if network.Labels["com.docker.compose.project"] == project {
			ownedNetworks[network.Name] = true
		}
	}
	for name := range inspected.NetworkSettings.Networks {
		if !ownedNetworks[name] {
			return nil, nil, fmt.Errorf("container is attached to a network not owned by its Compose project")
		}
	}
	ownedVolumes := map[string]bool{}
	for _, name := range volumeNames {
		ownedVolumes[name] = true
	}
	for _, mount := range inspected.Mounts {
		if mount.Type == "volume" && !ownedVolumes[mount.Name] {
			return nil, nil, fmt.Errorf("container uses a volume not owned by its Compose project")
		}
	}
	return networkIDs, volumeNames, nil
}

func validateOwnedContainerResources(id string, binding workloadBinding) error {
	raw, err := dockerJSON(http.MethodGet, "/containers/"+id+"/json", nil)
	if err != nil {
		return err
	}
	var inspected containerInspection
	if err := json.Unmarshal(raw, &inspected); err != nil {
		return err
	}
	if inspected.ID != id || inspected.Config.Labels["com.docker.compose.project"] != binding.Project {
		return fmt.Errorf("container engine identity no longer matches the ownership ledger")
	}
	networkRaw, err := dockerJSON(http.MethodGet, "/networks", nil)
	if err != nil {
		return err
	}
	var networks []networkSummary
	if err := json.Unmarshal(networkRaw, &networks); err != nil {
		return err
	}
	allowedNetworks := map[string]bool{}
	for _, network := range networks {
		if containsExact(binding.Networks, network.ID) && network.Labels["com.docker.compose.project"] == binding.Project {
			allowedNetworks[network.Name] = true
		}
	}
	for name := range inspected.NetworkSettings.Networks {
		if !allowedNetworks[name] {
			return fmt.Errorf("container network identity no longer matches the ownership ledger")
		}
	}
	allowedVolumes := map[string]bool{}
	for _, name := range binding.Volumes {
		allowedVolumes[name] = true
	}
	for _, mount := range inspected.Mounts {
		if mount.Type == "volume" && !allowedVolumes[mount.Name] {
			return fmt.Errorf("container volume identity no longer matches the ownership ledger")
		}
	}
	return nil
}

func containsExact(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func inspectAdoptableContainer(id, expectedService, expectedImage string) (containerInspection, error) {
	var inspected containerInspection
	if matched, _ := regexp.MatchString(`^[a-fA-F0-9]{12,64}$`, id); !matched {
		return inspected, fmt.Errorf("invalid container identifier")
	}
	raw, err := dockerJSON(http.MethodGet, "/containers/"+id+"/json", nil)
	if err != nil {
		return inspected, err
	}
	if err := json.Unmarshal(raw, &inspected); err != nil {
		return inspected, err
	}
	if err := validateAdoptableInspection(inspected, expectedService, expectedImage); err != nil {
		return inspected, err
	}
	return inspected, nil
}

func validateAdoptableInspection(inspected containerInspection, expectedService, expectedImage string) error {
	labels := inspected.Config.Labels
	project := labels["com.docker.compose.project"]
	service := labels["com.docker.compose.service"]
	name := strings.TrimPrefix(inspected.Name, "/")
	if labels["com.ark-stack.protected"] == "true" || strings.HasPrefix(project, "ark-platform") || strings.HasPrefix(project, "ark-mail") || strings.HasPrefix(name, "ark-platform") || strings.HasPrefix(name, "ark-mail") {
		return fmt.Errorf("platform and protected containers cannot be adopted")
	}
	if project == "" || service == "" {
		return fmt.Errorf("only inspected Docker Compose containers with project and service identities may be adopted")
	}
	if expectedService == "" || service != expectedService {
		return fmt.Errorf("inspected Compose service does not match the adoption request")
	}
	if expectedImage == "" || inspected.Config.Image != expectedImage {
		return fmt.Errorf("inspected image does not match the canonical adoption manifest")
	}
	if inspected.HostConfig.Privileged || inspected.HostConfig.NetworkMode == "host" || inspected.HostConfig.PidMode == "host" || inspected.HostConfig.IpcMode == "host" {
		return fmt.Errorf("container uses a forbidden host privilege boundary")
	}
	if len(inspected.HostConfig.Binds) > 0 {
		return fmt.Errorf("containers with host bind mounts cannot be adopted")
	}
	if len(inspected.HostConfig.CapAdd) > 0 || len(inspected.HostConfig.Devices) > 0 {
		return fmt.Errorf("containers with added capabilities or device access cannot be adopted")
	}
	if !inspected.HostConfig.ReadonlyRootfs || !containsFold(inspected.HostConfig.CapDrop, "ALL") || !hasNoNewPrivileges(inspected.HostConfig.SecurityOpt) {
		return fmt.Errorf("container does not enforce the canonical read-only, capability-drop, and no-new-privileges sandbox")
	}
	if inspected.HostConfig.PidsLimit <= 0 || inspected.HostConfig.PidsLimit > 256 {
		return fmt.Errorf("container does not enforce the canonical PID limit")
	}
	if inspected.HostConfig.Memory <= 0 || inspected.HostConfig.Memory > 512*1024*1024 || inspected.HostConfig.NanoCPUs <= 0 || inspected.HostConfig.NanoCPUs > 1_000_000_000 {
		return fmt.Errorf("container does not enforce the canonical memory and CPU limits")
	}
	for _, mount := range inspected.Mounts {
		if mount.Type == "bind" || strings.Contains(mount.Source, "docker.sock") || strings.Contains(mount.Destination, "docker.sock") {
			return fmt.Errorf("container has a forbidden host or Docker socket mount")
		}
	}
	for network := range inspected.NetworkSettings.Networks {
		if protectedNetwork(network) {
			return fmt.Errorf("container is attached to a protected platform network")
		}
	}
	return nil
}

func containsFold(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(value, expected) {
			return true
		}
	}
	return false
}

func hasNoNewPrivileges(values []string) bool {
	for _, value := range values {
		if strings.HasPrefix(strings.ToLower(value), "no-new-privileges") {
			return true
		}
	}
	return false
}

func protectedNetwork(name string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
	for _, fragment := range []string{"ark-platform", "control", "database-management", "mail-management", "monitoring"} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}

func inventory() ([]containerSummary, error) {
	raw, err := dockerJSON(http.MethodGet, "/containers/json?all=true", nil)
	if err != nil {
		return nil, err
	}
	var items []containerSummary
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, err
	}
	for i := range items {
		for key := range items[i].Labels {
			if strings.Contains(strings.ToLower(key), "secret") || strings.Contains(strings.ToLower(key), "token") {
				delete(items[i].Labels, key)
			}
		}
	}
	return items, nil
}

func mutateContainer(id, action string) error {
	_, err := dockerJSON(http.MethodPost, "/containers/"+id+"/"+action, nil)
	return err
}

func containerLogs(id string, tail int) (string, error) {
	if tail <= 0 || tail > 500 {
		tail = 200
	}
	raw, err := dockerJSON(http.MethodGet, fmt.Sprintf("/containers/%s/logs?stdout=1&stderr=1&timestamps=1&tail=%d", id, tail), nil)
	if err != nil {
		return "", err
	}
	return decodeDockerLogs(raw), nil
}

type containerStatsSummary struct {
	ReadAt          string `json:"readAt"`
	Pids            uint64 `json:"pids"`
	MemoryUsage     uint64 `json:"memoryUsage"`
	MemoryLimit     uint64 `json:"memoryLimit"`
	CPUTotalUsage   uint64 `json:"cpuTotalUsage"`
	SystemCPUUsage  uint64 `json:"systemCpuUsage"`
	OnlineCPUs      uint32 `json:"onlineCpus"`
	NetworkRxBytes  uint64 `json:"networkRxBytes"`
	NetworkTxBytes  uint64 `json:"networkTxBytes"`
	BlockReadBytes  uint64 `json:"blockReadBytes"`
	BlockWriteBytes uint64 `json:"blockWriteBytes"`
}

func containerStats(id string) (containerStatsSummary, error) {
	var summary containerStatsSummary
	raw, err := dockerJSON(http.MethodGet, "/containers/"+id+"/stats?stream=false", nil)
	if err != nil {
		return summary, err
	}
	var payload struct {
		Read      string `json:"read"`
		PidsStats struct {
			Current uint64 `json:"current"`
		} `json:"pids_stats"`
		MemoryStats struct {
			Usage uint64 `json:"usage"`
			Limit uint64 `json:"limit"`
		} `json:"memory_stats"`
		CPUStats struct {
			CPUUsage struct {
				TotalUsage uint64 `json:"total_usage"`
			} `json:"cpu_usage"`
			SystemCPUUsage uint64 `json:"system_cpu_usage"`
			OnlineCPUs     uint32 `json:"online_cpus"`
		} `json:"cpu_stats"`
		Networks map[string]struct {
			RxBytes uint64 `json:"rx_bytes"`
			TxBytes uint64 `json:"tx_bytes"`
		} `json:"networks"`
		BlkioStats struct {
			IOServiceBytesRecursive []struct {
				Op    string `json:"op"`
				Value uint64 `json:"value"`
			} `json:"io_service_bytes_recursive"`
		} `json:"blkio_stats"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return summary, fmt.Errorf("invalid Docker stats response: %w", err)
	}
	summary.ReadAt = payload.Read
	summary.Pids = payload.PidsStats.Current
	summary.MemoryUsage = payload.MemoryStats.Usage
	summary.MemoryLimit = payload.MemoryStats.Limit
	summary.CPUTotalUsage = payload.CPUStats.CPUUsage.TotalUsage
	summary.SystemCPUUsage = payload.CPUStats.SystemCPUUsage
	summary.OnlineCPUs = payload.CPUStats.OnlineCPUs
	for _, network := range payload.Networks {
		summary.NetworkRxBytes += network.RxBytes
		summary.NetworkTxBytes += network.TxBytes
	}
	for _, item := range payload.BlkioStats.IOServiceBytesRecursive {
		switch strings.ToLower(item.Op) {
		case "read":
			summary.BlockReadBytes += item.Value
		case "write":
			summary.BlockWriteBytes += item.Value
		}
	}
	return summary, nil
}

var sensitiveLogValue = regexp.MustCompile(`(?i)(password|secret|token|api[_-]?key)(\s*[=:]\s*)[^\s]+`)
var urlCredential = regexp.MustCompile(`(https?://[^:/\s]+:)[^@\s]+@`)

func safeLogLines(value string) []string {
	value = sensitiveLogValue.ReplaceAllString(value, "$1$2[REDACTED]")
	value = urlCredential.ReplaceAllString(value, "$1[REDACTED]@")
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r >= 0x20 {
			return r
		}
		return -1
	}, value)
	lines := strings.Split(clean, "\n")
	if len(lines) > 500 {
		lines = lines[len(lines)-500:]
	}
	for total := 0; len(lines) > 0; {
		total = 0
		for _, line := range lines {
			total += len(line)
		}
		if total <= 64*1024 {
			break
		}
		lines = lines[1:]
	}
	return lines
}

func decodeDockerLogs(raw []byte) string {
	var output bytes.Buffer
	for len(raw) >= 8 && (raw[0] == 1 || raw[0] == 2) && raw[1] == 0 && raw[2] == 0 && raw[3] == 0 {
		length := int(binary.BigEndian.Uint32(raw[4:8]))
		if length < 0 || length > len(raw)-8 {
			return string(raw)
		}
		output.Write(raw[8 : 8+length])
		raw = raw[8+length:]
	}
	if output.Len() == 0 {
		return string(raw)
	}
	return output.String()
}

func composeUp(project, file string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "compose", "-f", file, "-p", project, "up", "-d", "--no-build", "--pull", "never")
	cmd.Env = dockerCommandEnv("COMPOSE_IGNORE_ORPHANS=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(out))
		if len(message) > 4096 {
			message = message[:4096]
		}
		return fmt.Errorf("compose execution failed: %w: %s", err, message)
	}
	return nil
}

func dockerCommandEnv(extra ...string) []string {
	home := "/nonexistent"
	values := []string{"PATH=/usr/local/bin:/usr/bin:/bin"}
	if config := os.Getenv("ARK_DOCKER_CONFIG"); config != "" && filepath.IsAbs(config) {
		home = filepath.Dir(config)
		values = append(values, "DOCKER_CONFIG="+config)
	}
	values = append(values, "HOME="+home)
	return append(values, extra...)
}

func pullImage(image string) error {
	if !strings.Contains(image, "@sha256:") {
		return fmt.Errorf("only immutable image digests may be pulled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "pull", image)
	cmd.Env = dockerCommandEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(out))
		if len(message) > 4096 {
			message = message[:4096]
		}
		return fmt.Errorf("image pull failed: %w: %s", err, message)
	}
	return nil
}

func materializeCompose(workloadID, source, expectedHash string) (string, error) {
	if !resourceName.MatchString(workloadID) {
		return "", fmt.Errorf("invalid workload identifier")
	}
	if err := validateCompose(source); err != nil {
		return "", err
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(source)))
	if digest != expectedHash {
		return "", fmt.Errorf("compose hash does not match the approved workload")
	}
	root := getenv("ARK_AGENT_STATE_DIR", "/var/lib/ark-agent")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", err
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("agent state root is not a real path: %w", err)
	}
	dir := filepath.Join(resolvedRoot, "workloads", workloadID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if info, err := os.Lstat(dir); err != nil || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("workload state directory is not agent-owned")
	}
	if resolved, err := filepath.EvalSymlinks(dir); err != nil || resolved != dir {
		return "", fmt.Errorf("workload state directory is not an owned real path")
	}
	file := filepath.Join(dir, "compose.yml")
	temporary := file + ".next"
	if err := os.WriteFile(temporary, []byte(source), 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(temporary, file); err != nil {
		return "", err
	}
	return file, nil
}
