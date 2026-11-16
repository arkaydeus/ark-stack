import { describe, expect, test } from "bun:test";
import { assertTls12Rejected } from "../../scripts/pgbouncer-smoke-checks.ts";

describe("TLS 1.2 rejection evidence", () => {
  test("usage errors, connection failures and missing client certificates cannot pass", () => {
    for (const output of [
      "s_client: unknown option -starttls\nusage: s_client",
      "connect: Connection refused",
      "CONNECTED(00000003)\ntlsv13 alert certificate required",
    ]) {
      expect(() => assertTls12Rejected({ status: 1, stdout: output, stderr: "" })).toThrow(
        /did not demonstrate/,
      );
    }
  });
  test("a TLS 1.2 capable listener fails the assertion even if the CLI exits nonzero", () => {
    for (const status of [0, 1]) {
      expect(() =>
        assertTls12Rejected({
          status,
          stdout: "CONNECTED(00000003)\nProtocol  : TLSv1.2\nCipher : ECDHE-ECDSA-AES256-GCM-SHA384",
          stderr: "",
        }),
      ).toThrow(/succeeded/);
    }
  });
  test("requires a connection and a protocol-version alert", () => {
    expect(() =>
      assertTls12Rejected({
        status: 1,
        stdout: "CONNECTED(00000003)\nProtocol : TLSv1.2\nCipher : 0000",
        stderr: "SSL routines:ssl3_read_bytes:tlsv1 alert protocol version",
      }),
    ).not.toThrow();
  });
});
