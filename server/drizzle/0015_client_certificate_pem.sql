-- Private CA module (docs/design/front-door.md §3.10.1, ticket FD-13).
-- An issued client certificate is public data that must outlive issuance: the one-time bundle
-- reveal (FD-17), the Vercel push (FD-29) and rollover delivery (FD-28) all happen after the
-- issuing transaction. server/src/modules/pki.ts always writes it; the column stays nullable so
-- the migration cannot fail on a hand-inserted row.
ALTER TABLE client_certificates ADD COLUMN cert_pem text;
