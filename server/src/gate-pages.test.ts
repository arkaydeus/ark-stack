// Gate page security headers and the icon they load (FD-11; docs/design/front-door.md §3.9.2).
// The DB-backed suites check the same headers on live responses; this pins the exact policy.
import { describe, expect, test } from "bun:test";

import {
  GATE_BRAND_ASSETS,
  enrollPage,
  gateBrandAsset,
  gateMessagePage,
  gateNonce,
  gatePageHeaders,
  loginPage,
} from "./gate-pages.ts";

const nonce = "AAAAAAAAAAAAAAAAAAAAAA";

describe("gate page headers", () => {
  test("the CSP is nonce-bound for script and style and allows images from the login origin only", () => {
    expect(gatePageHeaders(nonce)).toEqual({
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
      "X-Frame-Options": "DENY",
      "X-Content-Type-Options": "nosniff",
      "Content-Security-Policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`,
    });
  });

  test("nonces are fresh 128-bit base64url values", () => {
    const first = gateNonce();
    expect(first).toMatch(/^[\w-]{22}$/);
    expect(gateNonce()).not.toBe(first);
  });
});

describe("gate pages", () => {
  const pages = [
    loginPage({ nonce, next: "/gate/authorize?route=r" }),
    loginPage({ nonce, next: null, signedInAs: "a@example.com" }),
    enrollPage({ nonce, next: null, email: "a@example.com" }),
    gateMessagePage({ nonce, title: "Access denied", message: "No.", signOut: true }),
  ];

  test("every page links the favicon and shows the mark, both from /gate/brand/", () => {
    for (const html of pages) {
      expect(html).toContain(
        '<link rel="icon" href="/gate/brand/icon-32.png" type="image/png" sizes="32x32">',
      );
      expect(html).toContain(
        '<img class="mark" src="/gate/brand/icon-96.png" alt="Ark Stack" width="40" height="40">',
      );
      for (const [, src] of html.matchAll(/(?:src|href)="(\/gate\/brand\/[^"]+)"/g))
        expect(Object.keys(GATE_BRAND_ASSETS)).toContain(src!);
    }
  });

  test("every script and style element carries the nonce, and nothing loads from elsewhere", () => {
    for (const html of pages) {
      for (const [tag] of html.matchAll(/<(?:script|style)\b[^>]*>/g))
        expect(tag).toContain(`nonce="${nonce}"`);
      expect(html).not.toMatch(/(?:src|href)="(?:https?:)?\/\//);
      expect(html).not.toMatch(/\sstyle="/);
    }
  });
});

describe("gate icon files", () => {
  test("each icon path is a PNG with long-lived public caching", () => {
    for (const path of Object.keys(GATE_BRAND_ASSETS)) {
      const asset = gateBrandAsset(path)!;
      expect(asset.headers).toEqual({
        "Content-Type": "image/png",
        "Cache-Control": "public, max-age=604800",
        "X-Content-Type-Options": "nosniff",
        "Cross-Origin-Resource-Policy": "same-origin",
      });
      expect([...asset.body.subarray(0, 8)]).toEqual([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
      expect(asset.body.length).toBeLessThan(8 * 1024);
    }
  });

  test("any other path is not an icon", () => {
    for (const path of [
      "/gate/brand/",
      "/gate/brand/icon-512.png",
      "/gate/brand/../brand/icon-32.png",
      "/gate/brand/constructor",
      "/gate/brand/ICON-32.PNG",
    ])
      expect(gateBrandAsset(path)).toBeNull();
  });
});
