// Test-only independent verifier. Never silently skip signature checks on macOS LibreSSL.
export function testOpenSsl() {
  for (const candidate of [
    process.env.ARK_OPENSSL_BIN,
    Bun.which("openssl"),
    "/opt/homebrew/opt/openssl@3/bin/openssl",
    "/usr/local/opt/openssl@3/bin/openssl",
  ]) {
    if (!candidate || !Bun.file(candidate).size) continue;
    const result = Bun.spawnSync([candidate, "version"]);
    if (result.exitCode === 0 && /^OpenSSL [3-9]\./.test(result.stdout.toString())) return candidate;
  }
  throw new Error("Tests require OpenSSL 3 or newer. Set ARK_OPENSSL_BIN to its executable.");
}
