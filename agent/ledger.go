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
	if err := json.Unmarshal(raw, &ledger); err != nil {
		return ledger, err
	}
	if ledger.Version != 1 || ledger.Workloads == nil {
		return ledger, fmt.Errorf("unsupported resource ledger")
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
	next := path + ".next"
	if err := os.WriteFile(next, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(next, path)
}

func recordWorkload(id, project, composeHash, compose string) error {
	items, err := inventory()
	if err != nil {
		return err
	}
	containers := []string{}
	for _, item := range items {
		if item.Labels["com.docker.compose.project"] == project {
			serviceName := item.Labels["com.docker.compose.service"]
			expectedImage, err := composeServiceImage(compose, serviceName)
			if err != nil {
				return err
			}
			if _, err := inspectAdoptableContainer(item.ID, serviceName, expectedImage); err != nil {
				return fmt.Errorf("deployed container failed effective-policy inspection: %w", err)
			}
			containers = append(containers, item.ID)
		}
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
