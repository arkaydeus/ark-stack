-- Platform region setting (docs/design/front-door.md §3.15, ticket FD-03).
-- These are the two platform_settings lines that 0013_front_door.sql left out of the §3.1 SQL.
-- `region` is a preset from shared/src/region.ts that drives the suggested Vercel function region,
-- the backup bucket region hint and the docs wording; it never changes AWS_REGION or SES.
-- `vps_region_label` is display-only free text: Ark records the VPS region but does not choose it.

ALTER TABLE platform_settings
  ADD COLUMN region text NOT NULL DEFAULT 'us-east',
  ADD COLUMN vps_region_label text,               -- free text: "Hetzner ash", "DO nyc3"; recorded only
  ADD CONSTRAINT platform_settings_region_check
    CHECK (region IN ('us-east', 'us-west', 'eu-west', 'eu-central')),
  ADD CONSTRAINT platform_settings_vps_region_label_check
    CHECK (vps_region_label IS NULL OR char_length(vps_region_label) BETWEEN 1 AND 64);
