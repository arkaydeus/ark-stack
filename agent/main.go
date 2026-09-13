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
		if compose, ok := item.Payload["compose"].(string); ok {
			if err := validateCompose(compose); err != nil {
				status = "failed"
				note = err.Error()
				_ = log.append(journalEntry{ID: item.ID, Action: item.Kind, Target: item.ID, Status: "rejected", Note: note})
				_ = complete(client, apiURL, token, item.ID, item.ClaimToken, status, note)
				continue
			}
		}
		if err := execute(item); err != nil {
			status = "failed"
			note = err.Error()
		}
		_ = log.append(journalEntry{ID: item.ID, Action: item.Kind, Target: item.ID, Status: status, Note: note})
		_ = complete(client, apiURL, token, item.ID, item.ClaimToken, status, note)
	}
	return nil
}

func execute(item job) error {
	switch item.Kind {
	case "service.deploy", "update.apply":
		compose, _ := item.Payload["compose"].(string)
		if compose == "" {
			return fmt.Errorf("compose payload required")
		}
		if err := validateCompose(compose); err != nil {
			return err
		}
		file, _ := item.Payload["file"].(string)
		project, _ := item.Payload["project"].(string)
		if file == "" || project == "" {
			return fmt.Errorf("host compose file and project are required for deploy")
		}
		return composeUp(project, file)
	case "service.start", "service.stop", "service.restart":
		id, _ := item.Payload["containerId"].(string)
		if id == "" {
			return fmt.Errorf("containerId required")
		}
		action := strings.TrimPrefix(item.Kind, "service.")
		return mutateContainer(id, action)
	case "service.logs":
		id, _ := item.Payload["containerId"].(string)
		_, err := containerLogs(id, 200)
		return err
	case "service.stats":
		id, _ := item.Payload["containerId"].(string)
		_, err := containerStats(id)
		return err
	default:
		_, err := inventory()
		return err
	}
}

func complete(client *http.Client, apiURL, token, id, claimToken, status, errText string) error {
	body, _ := json.Marshal(map[string]any{"status": status, "error": errText, "claimToken": claimToken, "evidence": map[string]any{"worker": "agent"}})
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
	res.Body.Close()
	return nil
}

func getenv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
