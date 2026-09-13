import { describe, expect, test } from "bun:test";

import { validateComposeSource } from "./compose-policy.ts";

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
});
