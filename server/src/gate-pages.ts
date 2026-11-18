// Minimal server-rendered pages for the gate login origin (docs/design/front-door.md §3.9.2, FD-11;
// forced first TOTP enrollment, §3.9.6, FD-12).
//
// `/gate/login` signs in with Better Auth's email/password and TOTP endpoints (the only API paths
// the login origin forwards, `GATE_LOGIN_AUTH_PATHS`) from a small nonce-bound script, then follows
// `next`, which must be a relative `/gate/authorize?…` path. Pages send a strict CSP, no referrer
// and no caching, and cannot be framed. `/gate/enroll` makes a signed-in user without TOTP enroll an
// authenticator before any route is reachable.

import { randomBytes } from "node:crypto";

const escapeHtml = (value: string) =>
  value.replace(
    /[&<>"']/g,
    (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]!,
  );

const STYLE = `
  body { font: 16px/1.5 system-ui, sans-serif; margin: 0; background: #f6f6f7; color: #18181b; }
  main { max-width: 22rem; margin: 12vh auto; padding: 2rem; background: #fff; border: 1px solid #e4e4e7; border-radius: 0.5rem; }
  h1 { font-size: 1.25rem; margin: 0 0 1rem; }
  label { display: block; margin: 0.75rem 0 0.25rem; font-size: 0.875rem; }
  input { width: 100%; box-sizing: border-box; padding: 0.5rem; font: inherit; border: 1px solid #a1a1aa; border-radius: 0.25rem; }
  button { margin-top: 1rem; width: 100%; padding: 0.5rem; font: inherit; border: 0; border-radius: 0.25rem; background: #18181b; color: #fff; cursor: pointer; }
  p.message { color: #b91c1c; min-height: 1.5em; margin: 0.75rem 0 0; }
`;

/** Security headers for every gate page; the nonce authorises this response's script and style. */
export function gatePageHeaders(nonce: string): Record<string, string> {
  return {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`,
  };
}

export function gateNonce() {
  return randomBytes(16).toString("base64url");
}

function page(nonce: string, title: string, body: string, script = "") {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${escapeHtml(title)}</title>
<style nonce="${nonce}">${STYLE}</style>
</head>
<body>
<main>
${body}
</main>
${script || body.includes(SIGN_OUT_FORM) ? `<script nonce="${nonce}">${body.includes(SIGN_OUT_FORM) ? SIGN_OUT_SCRIPT : ""}${script}</script>` : ""}
</body>
</html>
`;
}

const SIGN_OUT_FORM = `<form id="signout" method="post" action="/gate/logout"><button type="submit">Sign out everywhere</button></form>`;

const SIGN_OUT_SCRIPT = `
document.getElementById("signout").addEventListener("submit", async (event) => {
  event.preventDefault();
  const response = await fetch("/gate/logout", { method: "POST", credentials: "same-origin" });
  if (response.ok) location.assign("/gate/login");
});
`;

const LOGIN_SCRIPT = `
const next = document.body.dataset.next || "";
const signin = document.getElementById("signin");
const totp = document.getElementById("totp");
const message = document.getElementById("message");
async function post(path, body) {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  let data = null;
  try { data = await response.json(); } catch {}
  return { ok: response.ok, data };
}
function failed(result, fallback) {
  message.textContent = (result.data && (result.data.message || result.data.error)) || fallback;
}
function done() { location.assign(next || "/gate/login"); }
signin.addEventListener("submit", async (event) => {
  event.preventDefault();
  message.textContent = "";
  const result = await post("/api/auth/sign-in/email", {
    email: signin.elements.email.value,
    password: signin.elements.password.value,
  });
  if (!result.ok) return failed(result, "Sign-in failed.");
  if (result.data && result.data.twoFactorRedirect) {
    signin.hidden = true;
    totp.hidden = false;
    totp.elements.code.focus();
    return;
  }
  done();
});
totp.addEventListener("submit", async (event) => {
  event.preventDefault();
  message.textContent = "";
  const result = await post("/api/auth/two-factor/verify-totp", { code: totp.elements.code.value.trim() });
  if (!result.ok) return failed(result, "The code was not accepted.");
  done();
});
`;

/** The sign-in page. `next` was validated by `checkLoginNext`; `email` is a signed-in session's. */
export function loginPage(input: { nonce: string; next: string | null; signedInAs?: string | null }) {
  if (input.signedInAs) {
    return page(
      input.nonce,
      "Signed in",
      `<h1>Signed in</h1>
<p>You are signed in as ${escapeHtml(input.signedInAs)}.</p>
${SIGN_OUT_FORM}`,
    );
  }
  return page(
    input.nonce,
    "Sign in",
    `<h1>Sign in</h1>
<form id="signin" data-testid="signin">
<label for="email">Email</label>
<input id="email" name="email" type="email" autocomplete="username" required>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Continue</button>
</form>
<form id="totp" hidden>
<label for="code">Authenticator code</label>
<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required>
<button type="submit">Verify</button>
</form>
<p class="message" id="message" role="alert"></p>`,
    LOGIN_SCRIPT,
  ).replace("<body>", `<body data-next="${escapeHtml(input.next ?? "")}">`);
}

const ENROLL_SCRIPT = `
const next = document.body.dataset.next || "";
const enable = document.getElementById("enable");
const setup = document.getElementById("setup");
const verify = document.getElementById("verify");
const message = document.getElementById("message");
async function post(path, body) {
  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  let data = null;
  try { data = await response.json(); } catch {}
  return { ok: response.ok, data };
}
function failed(result, fallback) {
  message.textContent = (result.data && (result.data.message || result.data.error)) || fallback;
}
enable.addEventListener("submit", async (event) => {
  event.preventDefault();
  message.textContent = "";
  const result = await post("/api/auth/two-factor/enable", { password: enable.elements.password.value });
  if (!result.ok || !result.data || !result.data.totpURI) return failed(result, "Could not start enrollment.");
  const uri = new URL(result.data.totpURI);
  document.getElementById("secret").textContent = uri.searchParams.get("secret") || result.data.totpURI;
  const link = document.getElementById("uri");
  link.href = result.data.totpURI;
  const codes = document.getElementById("backup");
  codes.replaceChildren(...(result.data.backupCodes || []).map((code) => {
    const item = document.createElement("li");
    item.textContent = code;
    return item;
  }));
  enable.hidden = true;
  setup.hidden = false;
  verify.elements.code.focus();
});
verify.addEventListener("submit", async (event) => {
  event.preventDefault();
  message.textContent = "";
  const result = await post("/api/auth/two-factor/verify-totp", { code: verify.elements.code.value.trim() });
  if (!result.ok) return failed(result, "The code was not accepted.");
  location.assign(next || "/gate/login");
});
`;

/**
 * Forced first TOTP enrollment for a signed-in login-origin session whose user has none (FD-12).
 * Uses only the enrollment-only Better Auth endpoints the login origin forwards for such a session
 * (`GATE_ENROLLMENT_AUTH_PATHS`) and `verify-totp`, which turns TOTP on and rotates the session to
 * one with MFA assurance. `next` was validated by `checkLoginNext`.
 */
export function enrollPage(input: { nonce: string; next: string | null; email: string }) {
  return page(
    input.nonce,
    "Set up two-factor authentication",
    `<h1>Set up two-factor authentication</h1>
<p>Signed in as ${escapeHtml(input.email)}. An authenticator app is required before you can open any site.</p>
<form id="enable">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Set up authenticator</button>
</form>
<div id="setup" hidden>
<p>Add this key to your authenticator app, or <a id="uri" href="#">open it in the app</a>:</p>
<p><code id="secret" data-testid="totp-secret"></code></p>
<p>Recovery codes (store them safely; each works once):</p>
<ul id="backup"></ul>
<form id="verify">
<label for="code">Authenticator code</label>
<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" required>
<button type="submit">Verify and continue</button>
</form>
</div>
<p class="message" id="message" role="alert"></p>
${SIGN_OUT_FORM}`,
    ENROLL_SCRIPT,
  ).replace("<body>", `<body data-next="${escapeHtml(input.next ?? "")}">`);
}

export function gateMessagePage(input: { nonce: string; title: string; message: string; signOut?: boolean }) {
  return page(
    input.nonce,
    input.title,
    `<h1>${escapeHtml(input.title)}</h1>
<p>${escapeHtml(input.message)}</p>
${input.signOut ? SIGN_OUT_FORM : ""}`,
  );
}
