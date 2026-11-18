// RFC 4648 Base32 decoding and RFC 6238 SHA-1 TOTP (6 digits, 30 s), independent of Better Auth's
// generator. Shared by the gate browser harness and e2e/gate.spec.ts.
import { createHmac } from "node:crypto";

export function totpCode(secret: string, at = Date.now()) {
  const bits = [...secret.toUpperCase().replace(/=+$/, "")]
    .map((char) => "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(char).toString(2).padStart(5, "0"))
    .join("");
  const key = Buffer.from(bits.match(/.{8}/g)!.map((byte) => Number.parseInt(byte, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30_000)));
  const digest = createHmac("sha1", key).update(counter).digest();
  const offset = digest[digest.length - 1]! & 15;
  return ((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).toString().padStart(6, "0");
}
