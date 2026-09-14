package main

import "testing"

func TestRejectsDockerSocketAndPrivileged(t *testing.T) {
	err := validateCompose(`
services:
  evil:
    image: alpine:latest
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`)
	if err == nil {
		t.Fatal("expected policy rejection")
	}
}

func TestRejectsReservedPort(t *testing.T) {
	err := validateCompose(`
services:
  mail:
    image: nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    ports:
      - "25:25"
`)
	if err == nil {
		t.Fatal("expected reserved port rejection")
	}
}

func TestRejectsHostIPReservedPortAndInterpolation(t *testing.T) {
	if err := validateCompose(`
services:
  mail:
    image: nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    ports:
      - "0.0.0.0:25:8080"
`); err == nil {
		t.Fatal("expected reserved host-ip port rejection")
	}
	if err := validateCompose(`
services:
  x:
    image: nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    volumes:
      - "${X:-/var/run}/docker.sock:/sock"
`); err == nil {
		t.Fatal("expected interpolation rejection")
	}
	if err := validateCompose(`
services:
  x:
    image: nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    command: ["sh","-c","echo $HOME"]
`); err == nil {
		t.Fatal("expected command interpolation rejection")
	}
}

func TestAcceptsPinnedImage(t *testing.T) {
	err := validateCompose(`
services:
  web:
    image: docker.io/library/nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    ports:
      - "8080:80"
    read_only: true
    init: true
    pids_limit: 256
    mem_limit: 512m
    cpus: 1
    tmpfs: ["/tmp:rw,noexec,nosuid,nodev,size=64m"]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
`)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRejectsManifestWithoutCanonicalSandbox(t *testing.T) {
	if err := validateCompose(`
services:
  web:
    image: docker.io/library/nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`); err == nil {
		t.Fatal("expected missing canonical sandbox rejection")
	}
}

func TestRejectsNamedHostBindAndExternalControlResources(t *testing.T) {
	fixtures := []string{
		`{"services":{"app":{"image":"nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","volumes":["data:/data"]}},"volumes":{"data":{"driver":"local","driver_opts":{"type":"none","o":"bind","device":"/"}}}}`,
		`services:
  app:
    image: nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    networks: [control]
networks:
  control: { external: true, name: ark_platform }
`,
		`services:
  app:
    image: nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    volumes: [control:/data]
volumes:
  control: { external: true }
`,
	}
	for _, fixture := range fixtures {
		if err := validateCompose(fixture); err == nil {
			t.Fatal("expected protected resource rejection")
		}
	}
}

func TestRejectsAliasesDuplicateKeysAndUnsupportedFields(t *testing.T) {
	fixtures := []string{
		"services:\n  app: &app\n    image: nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n  copy: *app\n",
		"services:\n  app:\n    image: nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    image: nginx:1.27.3@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
		"services:\n  app:\n    image: nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n    logging: {driver: syslog}\n",
	}
	for _, fixture := range fixtures {
		if err := validateCompose(fixture); err == nil {
			t.Fatal("expected parser policy rejection")
		}
	}
}
