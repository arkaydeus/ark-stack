// Platform region presets (docs/design/front-door.md §3.15, ticket FD-03).
//
// The preset only drives *suggestions*: the Vercel function region Ark puts in the generated
// `vercel.json` snippet, the S3-compatible backup bucket region hint, and the wording the docs
// use. Ark does not choose or provision the VPS; `vps_region_label` merely records where the
// operator put it. The preset never feeds `AWS_REGION`, which SES uses
// (infra/platform/docker-compose.yml mail-worker, server/src/modules/providers.ts); SES region
// selection stays an explicit, separate choice.
//
// Vercel region codes verified on 2026-11-16 against the "Region list" table at
// https://vercel.com/docs/regions (page last updated 2026-08-11):
//   iad1  us-east-1     Washington, D.C., USA   (also Vercel's default function region,
//                                                 "Compute defaults" on the same page)
//   sfo1  us-west-1     San Francisco, USA
//   dub1  eu-west-1     Dublin, Ireland
//   fra1  eu-central-1  Frankfurt, Germany
// Each preset's backup region hint is the AWS region Vercel lists for that code, so a bucket
// created with the hint sits next to the suggested function region.

import { z } from "zod";

export const platformRegions = ["us-east", "us-west", "eu-west", "eu-central"] as const;
export type PlatformRegion = (typeof platformRegions)[number];

export const DEFAULT_PLATFORM_REGION: PlatformRegion = "us-east";

/** Vercel compute region codes Ark can suggest. Each one is in the vercel.com/docs/regions list. */
export const vercelRegionCodes = ["iad1", "sfo1", "dub1", "fra1"] as const;
export type VercelRegionCode = (typeof vercelRegionCodes)[number];

export type RegionProfile = {
  region: PlatformRegion;
  /** Short name for selectors, e.g. "US East". */
  label: string;
  /** Vercel function region code for `vercel.json` `regions`. */
  vercelRegion: VercelRegionCode;
  /** Vercel's reference location for that code. */
  vercelLocation: string;
  /** Suggested S3-compatible bucket region (AWS naming; other providers pick their nearest). */
  backupRegionHint: string;
  /** How the docs name the area the VPS should be in. */
  docsLabel: string;
};

export const regionProfiles: Readonly<Record<PlatformRegion, RegionProfile>> = Object.freeze({
  "us-east": {
    region: "us-east",
    label: "US East",
    vercelRegion: "iad1",
    vercelLocation: "Washington, D.C., USA",
    backupRegionHint: "us-east-1",
    docsLabel: "US East (Virginia/New York)",
  },
  "us-west": {
    region: "us-west",
    label: "US West",
    vercelRegion: "sfo1",
    vercelLocation: "San Francisco, USA",
    backupRegionHint: "us-west-1",
    docsLabel: "US West (California)",
  },
  "eu-west": {
    region: "eu-west",
    label: "EU West",
    vercelRegion: "dub1",
    vercelLocation: "Dublin, Ireland",
    backupRegionHint: "eu-west-1",
    docsLabel: "EU West (Ireland)",
  },
  "eu-central": {
    region: "eu-central",
    label: "EU Central",
    vercelRegion: "fra1",
    vercelLocation: "Frankfurt, Germany",
    backupRegionHint: "eu-central-1",
    docsLabel: "EU Central (Frankfurt)",
  },
});

export function isPlatformRegion(value: unknown): value is PlatformRegion {
  return typeof value === "string" && (platformRegions as readonly string[]).includes(value);
}

/** The profile for a stored region; anything unknown or missing falls back to the default. */
export function regionProfile(region: string | null | undefined): RegionProfile {
  return regionProfiles[isPlatformRegion(region) ? region : DEFAULT_PLATFORM_REGION];
}

/** The `vercel.json` fragment that pins functions next to the VPS. */
export function vercelRegionsConfig(region: string | null | undefined) {
  return { regions: [regionProfile(region).vercelRegion] };
}

/** The same fragment as the one-line JSON the Vercel guide shows. */
export function vercelRegionsSnippet(region: string | null | undefined) {
  return JSON.stringify(vercelRegionsConfig(region));
}

export const VPS_REGION_LABEL_MAX = 64;
// Letters (any script), digits, spaces and a few separators: enough for "Hetzner ash",
// "DO nyc3" or "OVH Gravelines (GRA-1)", and nothing that could be markup or a control character.
const VPS_REGION_LABEL_PATTERN = /^[\p{L}\p{N}][\p{L}\p{N} .,()/_:#+'-]*$/u;

export const vpsRegionLabelInput = z
  .string()
  .trim()
  .max(VPS_REGION_LABEL_MAX, `The VPS region label is at most ${VPS_REGION_LABEL_MAX} characters.`)
  .refine(
    (value) => value === "" || VPS_REGION_LABEL_PATTERN.test(value),
    "The VPS region label may contain letters, digits, spaces and . , ( ) / _ : # + ' - only, and must start with a letter or digit.",
  )
  .transform((value) => (value === "" ? null : value));

export const regionSettingsInput = z
  .object({
    region: z.enum(platformRegions),
    vpsRegionLabel: vpsRegionLabelInput.nullable().default(null),
  })
  .strict()
  .transform(({ region, vpsRegionLabel }) => ({ region, vpsRegionLabel: vpsRegionLabel ?? null }));

export type RegionSettingsInput = z.output<typeof regionSettingsInput>;

/** What the API reports for the region setting: the stored values plus every derived suggestion. */
export function regionSummary(settings: { region?: string | null; vpsRegionLabel?: string | null } | null) {
  const profile = regionProfile(settings?.region);
  return {
    ...profile,
    vpsRegionLabel: settings?.vpsRegionLabel ?? null,
    vercelConfig: vercelRegionsConfig(profile.region),
    vercelSnippet: vercelRegionsSnippet(profile.region),
    latencyHint: `Keep the VPS in ${profile.docsLabel} and Vercel functions in ${profile.vercelRegion} (${profile.vercelLocation}). Each cross-region database round trip adds tens of milliseconds, and an ORM issues several per request.`,
    options: platformRegions.map((region) => ({
      region,
      label: regionProfiles[region].label,
      vercelRegion: regionProfiles[region].vercelRegion,
    })),
  };
}

export type RegionSummary = ReturnType<typeof regionSummary>;
