package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestDisposableDockerDeploymentAndDurableLedger(t *testing.T) {
	if os.Getenv("ARK_DOCKER_INTEGRATION") != "1" {
		t.Skip("set ARK_DOCKER_INTEGRATION=1 on a disposable Docker daemon")
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	project := "ark-fix1-test-" + suffix
	workload := "fix1-" + suffix
	image := "docker.io/library/busybox:1.37.0@sha256:9db7b59979c38555a39def84a31fb98b5296952f9e3afd4f6f11f05b07adfab0"
	compose := fmt.Sprintf(`services:
  probe:
    image: %s
    command: ["sh", "-c", "while true; do echo ready; sleep 5; done"]
    read_only: true
    init: true
    pids_limit: 256
    mem_limit: 512m
    cpus: 1
    tmpfs: ["/tmp:rw,noexec,nosuid,nodev,size=64m"]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
`, image)
	state := t.TempDir()
	t.Setenv("ARK_AGENT_STATE_DIR", state)
	if home := os.Getenv("HOME"); home != "" {
		t.Setenv("ARK_DOCKER_CONFIG", filepath.Join(home, ".docker"))
	}
	if err := pullImage(image); err != nil {
		t.Fatal(err)
	}
	file, err := materializeCompose(workload, compose, fmt.Sprintf("%x", sha256Bytes(compose)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "docker", "compose", "-f", file, "-p", project, "down", "--volumes", "--remove-orphans")
		command.Env = dockerCommandEnv()
		_ = command.Run()
	})
	if err := composeUp(context.Background(), project, file); err != nil {
		t.Fatal(err)
	}
	if err := recordWorkload(workload, project, fmt.Sprintf("%x", sha256Bytes(compose)), compose); err != nil {
		t.Fatal(err)
	}
	first, err := loadLedger()
	if err != nil {
		t.Fatal(err)
	}
	binding := first.Workloads[workload]
	if len(binding.Containers) != 1 || len(binding.Networks) == 0 {
		t.Fatalf("expected exact container and network identities in ledger: %+v", binding)
	}
	if _, err := os.Stat(filepath.Join(state, "resource-ledger.json")); err != nil {
		t.Fatal(err)
	}
	second, err := loadLedger()
	if err != nil || second.Workloads[workload].ComposeHash != binding.ComposeHash {
		t.Fatalf("ownership ledger did not survive reload: %v", err)
	}
	containerID, err := ownedContainer(workload, "probe")
	if err != nil || containerID != binding.Containers[0] {
		t.Fatalf("owned container identity did not revalidate: %q, %v", containerID, err)
	}
	if err := mutateContainer(containerID, "restart"); err != nil {
		t.Fatalf("ledger-scoped restart failed: %v", err)
	}
}

func sha256Bytes(value string) [32]byte {
	return sha256.Sum256([]byte(value))
}
