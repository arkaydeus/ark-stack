import { createHash } from "node:crypto";

import { stableStringify } from "./id.ts";

export function sha256Hex(value: string | Uint8Array) {
  return createHash("sha256").update(value).digest("hex");
}

export function planHash(value: unknown) {
  return sha256Hex(stableStringify(value));
}
