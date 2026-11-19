/** Request and window bounds shared by the route editor and the edge renderer. */
export const HTTP_RATE_LIMIT_BOUNDS = {
  requests: { min: 1, max: 1_000 },
  /** Window bounds in milliseconds: 1 s to 1 h. */
  windowMs: { min: 1_000, max: 3_600_000 },
} as const;
