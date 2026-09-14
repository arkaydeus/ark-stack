package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type job struct {
	ID         string         `json:"id"`
	Kind       string         `json:"kind"`
	Payload    map[string]any `json:"payload"`
	ClaimToken string         `json:"claimToken"`
	TargetIDs  []string       `json:"targetIds"`
}

func main() {
	apiURL := getenv("ARK_API_URL", "http://127.0.0.1:3000")
	token := os.Getenv("ARK_AGENT_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "ARK_AGENT_TOKEN is required")
		os.Exit(1)
	}
	log := journal{path: getenv("ARK_AGENT_JOURNAL", "journal.jsonl")}
	client := &http.Client{Timeout: 20 * time.Second}
	for {
		if err := tick(client, apiURL, token, &log); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		time.Sleep(3 * time.Second)
	}
}

func tick(client *http.Client, apiURL, token string, log *journal) error {
	if err := workerHeartbeat(client, apiURL, token); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, apiURL+"/api/internal/jobs", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("job poll failed: %s", res.Status)
	}
	var payload struct {
		Jobs []job `json:"jobs"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return err
	}
	for _, item := range payload.Jobs {
		status := "succeeded"
		note := ""
		evidence := map[string]any{"worker": "agent"}
		if compose, ok := item.Payload["compose"].(string); ok {
			if err := validateCompose(compose); err != nil {
				status = "failed"
				note = err.Error()
				_ = log.append(journalEntry{ID: item.ID, Action: item.Kind, Target: item.ID, Status: "rejected", Note: note})
				_ = complete(client, apiURL, token, item.ID, item.ClaimToken, status, note, evidence)
				continue
			}
		}
		result, err := executeWithHeartbeat(client, apiURL, token, item)
		for key, value := range result {
			evidence[key] = value
		}
		if err != nil {
			status = "failed"
			note = err.Error()
		}
		_ = log.append(journalEntry{ID: item.ID, Action: item.Kind, Target: item.ID, Status: status, Note: note})
		_ = complete(client, apiURL, token, item.ID, item.ClaimToken, status, note, evidence)
	}
	return nil
}

func workerHeartbeat(client *http.Client, apiURL, token string) error {
	body, _ := json.Marshal(map[string]string{"version": "go-agent-v1"})
	req, err := http.NewRequest(http.MethodPost, apiURL+"/api/internal/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("agent heartbeat rejected: %s", res.Status)
	}
	return nil
}

func executeWithHeartbeat(client *http.Client, apiURL, token string, item job) (map[string]any, error) {
	done := make(chan struct{})
	heartbeatErr := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if err := heartbeat(client, apiURL, token, item.ID, item.ClaimToken); err != nil {
					select {
					case heartbeatErr <- err:
					default:
					}
					return
				}
			}
		}
	}()
	result, err := execute(item)
	close(done)
	select {
	case leaseErr := <-heartbeatErr:
		return nil, fmt.Errorf("operation lease heartbeat failed: %w", leaseErr)
	default:
		return result, err
	}
}

func heartbeat(client *http.Client, apiURL, token, id, claimToken string) error {
	body, _ := json.Marshal(map[string]string{"claimToken": claimToken})
	req, err := http.NewRequest(http.MethodPost, apiURL+"/api/internal/jobs/"+id+"/heartbeat", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat rejected: %s", res.Status)
	}
	return nil
}

func execute(item job) (map[string]any, error) {
	switch item.Kind {
	case "service.deploy", "update.apply":
		compose, _ := item.Payload["compose"].(string)
		if compose == "" {
			return nil, fmt.Errorf("compose payload required")
		}
		if err := validateCompose(compose); err != nil {
			return nil, err
		}
		project, _ := item.Payload["project"].(string)
		expectedHash, _ := item.Payload["composeHash"].(string)
		if len(item.TargetIDs) != 1 || project == "" || expectedHash == "" {
			return nil, fmt.Errorf("one workload target, project, and composeHash are required for deploy")
		}
		file, err := materializeCompose(item.TargetIDs[0], compose, expectedHash)
		if err != nil {
			return nil, err
		}
		images, _ := item.Payload["images"].([]any)
		for _, raw := range images {
			image, ok := raw.(string)
			if !ok {
				return nil, fmt.Errorf("invalid approved image list")
			}
			if err := pullImage(image); err != nil {
				return nil, err
			}
		}
		if err := composeUp(project, file); err != nil {
			return nil, err
		}
		return nil, recordWorkload(item.TargetIDs[0], project, expectedHash, compose)
	case "service.adopt":
		compose, _ := item.Payload["compose"].(string)
		expectedHash, _ := item.Payload["composeHash"].(string)
		containerID, _ := item.Payload["containerId"].(string)
		serviceName, _ := item.Payload["name"].(string)
		if len(item.TargetIDs) != 1 || compose == "" || expectedHash == "" || containerID == "" {
			return nil, fmt.Errorf("adoption requires one workload, canonical compose, composeHash, and container ID")
		}
		if _, err := materializeCompose(item.TargetIDs[0], compose, expectedHash); err != nil {
			return nil, err
		}
		return nil, adoptWorkload(item.TargetIDs[0], containerID, serviceName, expectedHash, compose)
	case "service.start", "service.stop", "service.restart":
		if len(item.TargetIDs) != 1 {
			return nil, fmt.Errorf("one workload target is required")
		}
		name, _ := item.Payload["name"].(string)
		id, err := ownedContainer(item.TargetIDs[0], name)
		if err != nil {
			return nil, err
		}
		action := strings.TrimPrefix(item.Kind, "service.")
		return nil, mutateContainer(id, action)
	case "service.logs":
		if len(item.TargetIDs) != 1 {
			return nil, fmt.Errorf("one workload target is required")
		}
		name, _ := item.Payload["name"].(string)
		if name == "" {
			return nil, fmt.Errorf("service name is required for scoped logs")
		}
		id, err := ownedContainer(item.TargetIDs[0], name)
		if err != nil {
			return nil, err
		}
		logs, err := containerLogs(id, 200)
		if err != nil {
			return nil, err
		}
		return map[string]any{"lines": safeLogLines(logs)}, nil
	case "service.stats":
		if len(item.TargetIDs) != 1 {
			return nil, fmt.Errorf("one workload target is required")
		}
		name, _ := item.Payload["name"].(string)
		if name == "" {
			return nil, fmt.Errorf("service name is required for scoped stats")
		}
		id, err := ownedContainer(item.TargetIDs[0], name)
		if err != nil {
			return nil, err
		}
		stats, err := containerStats(id)
		if err != nil {
			return nil, err
		}
		return map[string]any{"stats": stats}, nil
	case "service.discover":
		if len(item.TargetIDs) != 1 || item.TargetIDs[0] != "platform" || item.Payload["request"] != "redacted-inventory-v1" {
			return nil, fmt.Errorf("inventory requires the prepared platform-scoped contract")
		}
		items, err := inventory()
		if err != nil {
			return nil, err
		}
		if len(items) > 100 {
			items = items[:100]
		}
		for index := range items {
			items[index].Labels = map[string]string{
				"com.docker.compose.project": items[index].Labels["com.docker.compose.project"],
				"com.docker.compose.service": items[index].Labels["com.docker.compose.service"],
			}
		}
		return map[string]any{"inventory": items}, nil
	default:
		return nil, fmt.Errorf("unsupported agent operation kind: %s", item.Kind)
	}
}

func complete(client *http.Client, apiURL, token, id, claimToken, status, errText string, evidence map[string]any) error {
	body, _ := json.Marshal(map[string]any{"status": status, "error": errText, "claimToken": claimToken, "evidence": evidence})
	req, err := http.NewRequest(http.MethodPost, apiURL+"/api/internal/jobs/"+id+"/complete", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("job completion rejected: %s", res.Status)
	}
	return nil
}

func getenv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
