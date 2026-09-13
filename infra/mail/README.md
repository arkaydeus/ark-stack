Stalwart templates live here. Incoming mail can start without SES. Outbound sending stays paused until relay credentials are verified. Native administrative routes are never published on the public edge.

`mise run mail:up` starts the pinned Stalwart engine. Reconcile through the API after MFA; the public container does not receive AWS, DNS, or root keys.
