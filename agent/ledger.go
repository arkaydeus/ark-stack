package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type workloadBinding struct {
	Project     string   `json:"project"`
	ComposeHash string   `json:"composeHash"`
	Containers  []string `json:"containers"`
	Networks    []string `json:"networks"`
	Volumes     []string `json:"volumes"`
}

type resourceLedger struct {
	Version   int                        `json:"version"`
	Workloads map[string]workloadBinding `json:"workloads"`
}

func ledgerPath() string {
	return filepath.Join(getenv("ARK_AGENT_STATE_DIR", "/var/lib/ark-agent"), "resource-ledger.json")
}

func loadLedger() (resourceLedger, error) {
	ledger := resourceLedger{Version: 1, Workloads: map[string]workloadBinding{}}
	raw, err := os.ReadFile(ledgerPath())
	if os.IsNotExist(err) {
		return ledger, nil
	}
	if err != nil {
		return ledger, err
	}
	if err := json.Unmarshal(raw, &ledger); err != nil || ledger.Version != 1 || ledger.Workloads == nil {
		// A torn write leaves a truncated or empty file. Fall back to the previous copy rather
		// than failing every owned-container operation until someone intervenes by hand.
		backup, backupErr := os.ReadFile(ledgerPath() + ".bak")
		if backupErr != nil {
			if err != nil {
				return ledger, err
			}
			return ledger, fmt.Errorf("unsupported resource ledger")
		}
		recovered := resourceLedger{Version: 1, Workloads: map[string]workloadBinding{}}
		if err := json.Unmarshal(backup, &recovered); err != nil {
			return ledger, fmt.Errorf("resource ledger and its backup are both unreadable: %w", err)
		}
		if recovered.Version != 1 || recovered.Workloads == nil {
			return ledger, fmt.Errorf("unsupported resource ledger")
		}
		return recovered, nil
	}
	return ledger, nil
}

func saveLedger(ledger resourceLedger) error {
	path := ledgerPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(ledger, "", "  ")
	if err != nil {
		return err
	}
	// Keep the previous ledger so a torn write is recoverable; without it a truncated file
	// makes every owned-container operation fail permanently.
	if previous, err := os.ReadFile(path); err == nil {
		if err := writeFileSynced(path+".bak", previous); err != nil {
			return err
		}
	}
	next := path + ".next"
	if err := writeFileSynced(next, raw); err != nil {
		return err
	}
	if err := os.Rename(next, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// Durability for a rename-based atomic replace needs the file contents on disk before the
// rename and the directory entry on disk after it.
func writeFileSynced(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func syncDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.Sync()
}

func recordWorkload(id, project, composeHash, compose string) error {
	items, err := inventory()
	if err != nil {
		return err
	}
	// The control plane shares one Compose project across every service in a platform project,
	// and `COMPOSE_IGNORE_ORPHANS` keeps containers from removed services running. So the scan
	// is scoped to the services this manifest actually declares: anything else under the same
	// project belongs to a sibling workload and is none of this deploy's business.
	declared, err := composeServiceNames(compose)
	if err != nil {
		return err
	}
	containers := []string{}
	for _, item := range items {
		if item.Labels["com.docker.compose.project"] != project {
			continue
		}
		serviceName := item.Labels["com.docker.compose.service"]
		if !declared[serviceName] {
			continue
		}
		expectedImage, err := composeServiceImage(compose, serviceName)
		if err != nil {
			return err
		}
		if _, err := inspectAdoptableContainer(item.ID, serviceName, expectedImage); err != nil {
			// `compose up` has already run, so a container that fails inspection is live and
			// about to be left out of the ledger. Stop what this deploy created rather than
			// leaving unmanaged containers behind.
			stopUnledgered(append(containers, item.ID))
			return fmt.Errorf("deployed container failed effective-policy inspection: %w", err)
		}
		containers = append(containers, item.ID)
	}
	if len(containers) == 0 {
		return fmt.Errorf("compose completed without observable owned containers")
	}
	networks, volumes, err := workloadResources(project)
	if err != nil {
		return err
	}
	ledger, err := loadLedger()
	if err != nil {
		return err
	}
	ledger.Workloads[id] = workloadBinding{
		Project: project, ComposeHash: composeHash, Containers: containers, Networks: networks, Volumes: volumes,
	}
	return saveLedger(ledger)
}

func adoptWorkload(id, containerID, expectedService, composeHash, compose string) error {
	expectedImage, err := composeServiceImage(compose, expectedService)
	if err != nil {
		return err
	}
	inspected, err := inspectAdoptableContainer(containerID, expectedService, expectedImage)
	if err != nil {
		return err
	}
	ledger, err := loadLedger()
	if err != nil {
		return err
	}
	for workloadID, binding := range ledger.Workloads {
		for _, existingID := range binding.Containers {
			if existingID == inspected.ID && workloadID != id {
				return fmt.Errorf("container is already owned by another workload")
			}
		}
	}
	project := inspected.Config.Labels["com.docker.compose.project"]
	networks, volumes, err := assertAttachedResourcesOwned(inspected, project)
	if err != nil {
		return err
	}
	ledger.Workloads[id] = workloadBinding{
		Project:     project,
		ComposeHash: composeHash,
		Containers:  []string{inspected.ID},
		Networks:    networks,
		Volumes:     volumes,
	}
	return saveLedger(ledger)
}

func ownedContainer(workloadID, serviceName string) (string, error) {
	ledger, err := loadLedger()
	if err != nil {
		return "", err
	}
	binding, ok := ledger.Workloads[workloadID]
	if !ok {
		return "", fmt.Errorf("workload has no agent-owned resource binding")
	}
	items, err := inventory()
	if err != nil {
		return "", err
	}
	for _, item := range items {
		owned := false
		for _, id := range binding.Containers {
			if item.ID == id {
				owned = true
				break
			}
		}
		if !owned || item.Labels["com.docker.compose.project"] != binding.Project {
			continue
		}
		containerName := ""
		if len(item.Names) > 0 {
			containerName = strings.TrimPrefix(item.Names[0], "/")
		}
		if serviceName == "" || item.Labels["com.docker.compose.service"] == serviceName || containerName == serviceName {
			if err := validateOwnedContainerResources(item.ID, binding); err != nil {
				return "", err
			}
			return item.ID, nil
		}
	}
	return "", fmt.Errorf("no currently owned container matches this workload")
}

// Best effort: the caller is already returning an error, and a container that cannot be stopped
// is reported through that error rather than masking it.
func stopUnledgered(containers []string) {
	for _, id := range containers {
		_ = mutateContainer(id, "stop")
	}
}
