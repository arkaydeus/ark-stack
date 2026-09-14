import { describe, expect, test } from "bun:test";

import { canonicalizeComposeSource, validateComposeSource } from "./compose-policy.ts";

describe("compose policy", () => {
  test("accepts a pinned stateless image", () => {
    const result = validateComposeSource(`
services:
  web:
    image: docker.io/library/nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    ports:
      - "8080:80"
    volumes:
      - app_data:/data
volumes:
  app_data:
`);
    expect(result.ok).toBe(true);
    const canonical = canonicalizeComposeSource(`
services:
  web:
    image: docker.io/library/nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
`);
    expect(canonical).toContain("read_only: true");
    expect(canonical).toContain("pids_limit: 256");
    expect(canonical).toContain("mem_limit: 512m");
    expect(canonical).toContain("cpus: 1");
    expect(canonical).toContain("cap_drop:");
    expect(canonical).toContain("no-new-privileges:true");
  });

  test("rejects caller attempts to weaken injected sandbox limits", () => {
    for (const setting of [
      "read_only: false",
      "pids_limit: 999999",
      "mem_limit: 64g",
      "cpus: 16",
      "tmpfs: [/etc]",
      "cap_drop: []",
      "security_opt: []",
    ]) {
      expect(
        validateComposeSource(`
services:
  app:
    image: docker.io/library/nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    ${setting}
`).ok,
      ).toBe(false);
    }
  });

  test("rejects docker socket, privileged mode, and latest tags", () => {
    const result = validateComposeSource(`
services:
  evil:
    image: docker.io/library/alpine:latest
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      const messages = result.violations.map((item) => item.message).join(" ");
      expect(messages).toContain("Privileged");
      expect(messages).toContain("Bind mounts");
      expect(messages).toContain("allowed registry");
    }
  });

  test("rejects includes and reserved platform ports", () => {
    const result = validateComposeSource(`
include:
  - https://evil.example/compose.yaml
services:
  mail:
    image: docker.io/library/nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    ports:
      - "25:25"
`);
    expect(result.ok).toBe(false);
  });

  test("rejects interpolation in command, entrypoint, labels, and working_dir", () => {
    const image =
      "docker.io/library/nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    for (const field of [
      `command: ["sh","-c","echo $HOME"]`,
      "entrypoint: [echo, ${ARK_ROOT_KEY}]",
      "labels: { owner: ${USER} }",
      "working_dir: ${PWD}",
    ]) {
      const result = validateComposeSource(`
services:
  app:
    image: ${image}
    ${field}
`);
      expect(result.ok).toBe(false);
    }
  });

  test("rejects interpolation that would expand into a host bind mount", () => {
    const result = validateComposeSource(`
services:
  x:
    image: docker.io/library/nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    volumes:
      - "\${X:-/var/run}/docker.sock:/sock"
`);
    expect(result.ok).toBe(false);
  });

  test("rejects host-IP publish forms of reserved ports", () => {
    const hostIp = validateComposeSource(`
services:
  mail:
    image: docker.io/library/nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    ports:
      - "0.0.0.0:25:8080"
`);
    const loopback = validateComposeSource(`
services:
  db:
    image: docker.io/library/nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    ports:
      - "127.0.0.1:5432:5432"
`);
    expect(hostIp.ok).toBe(false);
    expect(loopback.ok).toBe(false);
  });

  test("rejects implicit localhost registries", () => {
    const result = validateComposeSource(`
services:
  x:
    image: localhost:5000/app:1.0.0
`);
    expect(result.ok).toBe(false);
  });

  test("rejects host binds hidden in named volumes and external platform resources", () => {
    const image =
      "docker.io/library/nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    for (const source of [
      `services:\n  app:\n    image: ${image}\n    volumes: [data:/data]\nvolumes:\n  data:\n    driver: local\n    driver_opts: { type: none, o: bind, device: / }\n`,
      `services:\n  app:\n    image: ${image}\n    networks: [control]\nnetworks:\n  control: { external: true, name: ark_platform }\n`,
      `services:\n  app:\n    image: ${image}\n    volumes: [control:/data]\nvolumes:\n  control: { external: true }\n`,
    ]) {
      expect(validateComposeSource(source).ok).toBe(false);
    }
  });

  test("rejects unknown lifecycle, logging and namespace escape fields", () => {
    const result = validateComposeSource(`
services:
  app:
    image: docker.io/library/nginx:1.27.3@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    post_start: [{ command: id }]
    logging: { driver: syslog }
    volumes_from: [other]
`);
    expect(result.ok).toBe(false);
  });
});
