package main

import (
	"strings"
	"testing"
)

const pinnedImage = "docker.io/library/nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// validateSandbox runs before the port, mount, and network rules, so a fixture that omits the
// canonical block is rejected before the rule under test is ever reached. Every fixture here is
// built on top of the canonical block so each test exercises the rule it names.
func sandboxed(service string, fields ...string) string {
	body := []string{
		"services:",
		"  " + service + ":",
		"    image: " + pinnedImage,
	}
	body = append(body, fields...)
	body = append(body,
		"    read_only: true",
		"    init: true",
		"    pids_limit: 256",
		"    mem_limit: 512m",
		"    cpus: 1",
		`    tmpfs: ["/tmp:rw,noexec,nosuid,nodev,size=64m"]`,
		"    cap_drop: [ALL]",
		`    security_opt: ["no-new-privileges:true"]`,
	)
	return strings.Join(body, "\n") + "\n"
}

func expectRejection(t *testing.T, source, contains string) {
	t.Helper()
	err := validateCompose(source)
	if err == nil {
		t.Fatalf("expected rejection containing %q, got none", contains)
	}
	if !strings.Contains(err.Error(), contains) {
		t.Fatalf("expected rejection containing %q, got %q", contains, err.Error())
	}
}

func TestRejectsDockerSocketAndPrivileged(t *testing.T) {
	expectRejection(t, sandboxed("evil", "    privileged: true"), "unsupported service field")
	expectRejection(t,
		sandboxed("evil", "    volumes:", "      - /var/run/docker.sock:/var/run/docker.sock"),
		"bind",
	)
}

func TestRejectsReservedPort(t *testing.T) {
	expectRejection(t, sandboxed("mail", "    ports:", `      - "25:25"`), "reserved")
	expectRejection(t, sandboxed("mail", "    ports:", `      - "0.0.0.0:25:8080"`), "reserved")
	expectRejection(t, sandboxed("db", "    ports:", `      - "5432:5432"`), "reserved")
}

func TestRejectsLongFormReservedAndAmbiguousPorts(t *testing.T) {
	expectRejection(t,
		sandboxed("mail", "    ports:", "      - target: 80", "        published: 25"),
		"reserved",
	)
	// The long form reports the range through the "ambiguous" path because a range never
	// parses as a single published port; the short form has its own explicit range check.
	expectRejection(t,
		sandboxed("mail", "    ports:", "      - target: 80", `        published: "80-81"`),
		"ambiguous port entry",
	)
	expectRejection(t, sandboxed("mail", "    ports:", `      - "80-81:80"`), "port ranges are not allowed")
}

func TestRejectsInterpolation(t *testing.T) {
	expectRejection(t,
		sandboxed("x", "    volumes:", `      - "${X:-/var/run}/docker.sock:/sock"`),
		"interpolation",
	)
	expectRejection(t, sandboxed("x", `    command: ["sh","-c","echo $HOME"]`), "interpolation")
}

func TestRequiresDigestPinnedImages(t *testing.T) {
	expectRejection(t,
		strings.Replace(sandboxed("web"), pinnedImage, "docker.io/library/nginx:1.27.3", 1),
		"immutable sha256 digest",
	)
	expectRejection(t,
		strings.Replace(sandboxed("web"), pinnedImage, "docker.io/library/alpine:latest", 1),
		"immutable sha256 digest",
	)
}

func TestAcceptsPinnedImage(t *testing.T) {
	if err := validateCompose(sandboxed("web", "    ports:", `      - "8080:80"`)); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsManifestWithoutCanonicalSandbox(t *testing.T) {
	if err := validateCompose("services:\n  web:\n    image: " + pinnedImage + "\n"); err == nil {
		t.Fatal("expected missing canonical sandbox rejection")
	}
}

func TestRejectsNamedHostBindAndExternalControlResources(t *testing.T) {
	fixtures := []string{
		sandboxed("app", "    volumes:", "      - data:/data") +
			"volumes:\n  data:\n    driver: local\n    driver_opts: { type: none, o: bind, device: / }\n",
		sandboxed("app", "    networks:", "      - control") +
			"networks:\n  control: { external: true, name: ark_platform }\n",
		sandboxed("app", "    volumes:", "      - control:/data") +
			"volumes:\n  control: { external: true }\n",
	}
	for _, fixture := range fixtures {
		if err := validateCompose(fixture); err == nil {
			t.Fatal("expected protected resource rejection")
		}
	}
}

func TestRejectsAliasesDuplicateKeysAndUnsupportedFields(t *testing.T) {
	fixtures := []string{
		"services:\n  app: &app\n    image: " + pinnedImage + "\n  copy: *app\n",
		"services:\n  app:\n    image: " + pinnedImage + "\n    image: " + pinnedImage + "\n",
		sandboxed("app", "    logging: {driver: syslog}"),
	}
	for _, fixture := range fixtures {
		if err := validateCompose(fixture); err == nil {
			t.Fatal("expected parser policy rejection")
		}
	}
}

func TestRejectsReservedAndMalformedWorkloadProjects(t *testing.T) {
	for _, project := range []string{
		"ark-platform",
		"ark-mail",
		"ark-monitoring",
		"ark-restore",
		"ark-platform-extra",
		"ARK-PLATFORM",
		"platform",
		"",
		"ark-",
		"ark-web/../platform",
		"ark-web;rm",
	} {
		if err := validateWorkloadProject(project); err == nil {
			t.Fatalf("workload project %q was accepted", project)
		}
	}
	for _, project := range []string{"ark-web", "ark-shop-2", "ark-controls"} {
		if err := validateWorkloadProject(project); err != nil {
			t.Fatalf("workload project %q should be accepted: %v", project, err)
		}
	}
}

func TestComposeServiceNamesReturnsDeclaredServicesOnly(t *testing.T) {
	names, err := composeServiceNames(sandboxed("web"))
	if err != nil {
		t.Fatal(err)
	}
	if !names["web"] || len(names) != 1 {
		t.Fatalf("expected only the declared service, got %v", names)
	}
}
