package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
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
	return string(raw), nil
}

func containerStats(id string) ([]byte, error) {
	return dockerJSON(http.MethodGet, "/containers/"+id+"/stats?stream=false", nil)
}

func composeUp(project, file string) error {
	cmd := exec.Command("docker", "compose", "-f", file, "-p", project, "up", "-d", "--no-build", "--pull", "never", "--no-interpolate")
	cmd.Env = append(os.Environ(), "COMPOSE_IGNORE_ORPHANS=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
