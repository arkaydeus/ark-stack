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
}

func TestAcceptsPinnedImage(t *testing.T) {
	err := validateCompose(`
services:
  web:
    image: docker.io/library/nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    ports:
      - "8080:80"
`)
	if err != nil {
		t.Fatal(err)
	}
}
