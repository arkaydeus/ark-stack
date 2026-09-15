/**
 * Raised by input validators for a caller mistake — a malformed hostname, an alias loop, a bad
 * CIDR. The API maps it to 422 so the caller sees the reason instead of a generic 500.
 */
export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}
