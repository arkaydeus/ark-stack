/** A failed command is not evidence that a TLS listener refused a protocol. */
export function assertTls12Rejected(result: { status: number; stdout: string; stderr: string }) {
  const output = result.stdout + result.stderr;
  if (result.status === 0 || /(?:Cipher is|Cipher\s*:)\s*(?!0000|\(NONE\))\S+/.test(output)) {
    throw new Error("TLS 1.2 handshake succeeded.");
  }
  if (!/CONNECTED\(/.test(output) || !/alert protocol version|unsupported protocol/i.test(output)) {
    throw new Error(
      `OpenSSL did not demonstrate a TLS protocol rejection; PostgreSQL STARTTLS support is required: ${output}`,
    );
  }
}
