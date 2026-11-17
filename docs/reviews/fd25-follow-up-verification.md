# FD-25 follow-up: review gap verification

Recorded 17 November 2026, following reviewed commit `2a7cac000a3a7e945890af24ecdb36b847879978`.

## Test repair

The no-watchdog HAProxy launch-guard test now requires a real HTTP 200 through
public port 443, together with refusal of the tailnet route. An HAProxy log line
for an unsuccessful connection to Caddy cannot satisfy the assertion.

After verifying that watchdog loss closes established tailnet sessions and
restarts HAProxy, the fixture starts Caddy with its existing HTTP-only closed
configuration. HAProxy's full and closed configuration files are untouched.
This gives the HAProxy assertion a stable HTTP backend without relying on the
overlap of two independent guard restart windows. Caddy's own launch guard,
listener closure and session shutdown are exercised by the observer suite.
The fixture copies the worker-owned private files as uid 1000 in the pinned Bun
container, avoiding dependence on the host user's filesystem permissions.

## Database and evidence isolation

The original validation package and output artifacts remain unchanged in
`.orkestrator/review-artifacts/review-validation-349b00ce-bfbd-4dd9-bbe9-23b210404257/`.
Its broad unit command and observer command both failed with `DATABASE_URL`
missing; the observer exited before executing any phase.

Reruns use a disposable `postgres:17.6` container, database owner `ark_migration`,
and an ephemeral port published on `127.0.0.1` only. Migrations run before the
unit suite. The test environment uses the repository CI values, with
`DATABASE_URL` and `DATABASE_APP_URL` pointing at this isolated database. The
observer creates and drops its own database. No `db:up` or shared-resource prune
is used; cleanup removes only this run's database container and harness resources.

New stdout, stderr and command records are kept separately under
`.orkestrator/address-findings/`. This directory is local pipeline evidence;
the results below are the durable repository record.

## Validation results

- The exact previously failed broad command passed: 842 tests, zero failures,
  one snapshot, 670149 assertions, across 71 files (71.7 seconds):
  `bun --env-file=.env test shared server workers tests scripts/publish-images.test.ts scripts/install-edge-auth.test.ts scripts/install-edge-l4.test.ts scripts/edge-namespace.test.ts`.
- Focused formatting, lint and TypeScript checks passed for
  `scripts/test-edge-l4.ts`. Previously passing repository-wide checks were not
  repeated.
- The exact previously failed observer command, `bun scripts/test-edge-observer.ts`,
  passed all nine phases in 64.8 seconds. Its stderr was empty.
- `bun scripts/test-edge-l4.ts` passed the full runtime suite, including the
  restored public HTTP 200 assertion, the 630-second WebSocket idle check,
  PROXY trust, SNI/Host checks, reload continuity and tailnet withdrawal. With
  Caddy's listener down, all six requests reset in 1–2 ms with `SC` and zero
  retries. All 20 requests during Caddy reloads returned 200.
- After the final worker-UID file-copy adjustment, a focused runner generated
  from the final script executed the unchanged production setup, lease-expiry
  test and launch-guard test. It verified HTTP 200 through public 443 after the
  no-watchdog restart while the tailnet connection was refused. The launch-guard
  phase passed in 28.9 seconds. The generated source and output are archived in
  `.orkestrator/address-findings/`; the temporary script was removed afterward.
  The first focused attempt omitted the HAProxy generation setup and failed
  before the repaired assertion. Including the unchanged lease-expiry test
  restored that prerequisite and the same focused command passed.

| Observer phase                                            | Result | Duration |
| --------------------------------------------------------- | ------ | -------- |
| LocalAPI read-only deployment                             | Passed | 3.9 s    |
| Identity withdrawal within detection + 5 s                | Passed | 1.7 s    |
| Shared backend per-route withdrawal and restart           | Passed | 4.1 s    |
| Disable with a WebSocket has no critical withdrawal alert | Passed | 4.1 s    |
| Watchdog loss while Caddy is serving                      | Passed | 11.3 s   |
| Lease expiry with observation stopped                     | Passed | 10.6 s   |
| Start with an expired lease                               | Passed | 6.0 s    |
| Withdrawal failure stops the proxy                        | Passed | 9.2 s    |
| Unreadable admin config stops the proxy                   | Passed | 8.2 s    |

The new direct-listener path ran for each of the four safety-stop scenarios:

| Trigger                       | Caddy listener closed (8443) | Route stopped through public 443 | Existing session  |
| ----------------------------- | ---------------------------- | -------------------------------- | ----------------- |
| Watchdog pause                | 1989 ms                      | 2031 ms                          | Closed at 1943 ms |
| Watchdog stop                 | 664 ms                       | 1006 ms                          | Closed at 620 ms  |
| Withdrawal POST /load failure | 587 ms                       | 624 ms                           | Closed within 5 s |
| Unreadable admin config       | 521 ms                       | 521 ms                           | Closed within 5 s |

All values are relative to the trigger or detection; every five-second assertion
passed. The listener helper timestamps transitions on host receipt. Additional
observations: identity withdrawal removed the config in 728 ms and closed the
session in 709 ms; shared-backend revocation withdrew the handler in 105 ms,
closed its session in 27 ms, and restored the other hostname in 1129 ms. Disabling
a route closed its WebSocket in 207 ms without a critical alert. With observation
stopped, withdrawal occurred at last completion + 8082 ms and session closure at
last completion + 8010 ms, against the eight-second lease plus five-second bound
of 13000 ms.
