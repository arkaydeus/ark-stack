import { describe, expect, test } from "bun:test";

import {
  DEFAULT_PLATFORM_REGION,
  isPlatformRegion,
  platformRegions,
  regionProfile,
  regionProfiles,
  regionSettingsInput,
  regionSummary,
  vercelRegionCodes,
  vercelRegionsConfig,
  vercelRegionsSnippet,
} from "./region.ts";

// The "Region list" table at https://vercel.com/docs/regions (page last updated 2026-08-11,
// checked 2026-11-16): Vercel code -> [AWS region name, reference location].
const VERCEL_REGION_LIST: Record<string, [string, string]> = {
  arn1: ["eu-north-1", "Stockholm, Sweden"],
  bom1: ["ap-south-1", "Mumbai, India"],
  cdg1: ["eu-west-3", "Paris, France"],
  cle1: ["us-east-2", "Cleveland, USA"],
  cpt1: ["af-south-1", "Cape Town, South Africa"],
  dub1: ["eu-west-1", "Dublin, Ireland"],
  fra1: ["eu-central-1", "Frankfurt, Germany"],
  gru1: ["sa-east-1", "São Paulo, Brazil"],
  hkg1: ["ap-east-1", "Hong Kong"],
  hnd1: ["ap-northeast-1", "Tokyo, Japan"],
  iad1: ["us-east-1", "Washington, D.C., USA"],
  icn1: ["ap-northeast-2", "Seoul, South Korea"],
  kix1: ["ap-northeast-3", "Osaka, Japan"],
  lhr1: ["eu-west-2", "London, United Kingdom"],
  pdx1: ["us-west-2", "Portland, USA"],
  sfo1: ["us-west-1", "San Francisco, USA"],
  sin1: ["ap-southeast-1", "Singapore"],
  syd1: ["ap-southeast-2", "Sydney, Australia"],
  yul1: ["ca-central-1", "Montréal, Canada"],
};

describe("region mapping", () => {
  test("defaults to us-east, which suggests Vercel iad1", () => {
    expect(DEFAULT_PLATFORM_REGION).toBe("us-east");
    expect(regionProfile(undefined).vercelRegion).toBe("iad1");
    expect(regionProfile(null).region).toBe("us-east");
    expect(vercelRegionsConfig(null)).toEqual({ regions: ["iad1"] });
    expect(vercelRegionsSnippet(undefined)).toBe('{"regions":["iad1"]}');
  });

  test("maps every preset as designed (front door §3.15)", () => {
    expect(
      platformRegions.map((region) => [
        region,
        regionProfiles[region].vercelRegion,
        regionProfiles[region].backupRegionHint,
      ]),
    ).toEqual([
      ["us-east", "iad1", "us-east-1"],
      ["us-west", "sfo1", "us-west-1"],
      ["eu-west", "dub1", "eu-west-1"],
      ["eu-central", "fra1", "eu-central-1"],
    ]);
    for (const region of platformRegions) {
      const profile = regionProfiles[region];
      expect(profile.region).toBe(region);
      expect(profile.docsLabel.length).toBeGreaterThan(0);
      expect(vercelRegionsConfig(region)).toEqual({ regions: [profile.vercelRegion] });
    }
  });

  test("every Vercel code is in vercel.com/docs/regions with the stated location", () => {
    for (const code of vercelRegionCodes) expect(VERCEL_REGION_LIST).toHaveProperty(code);
    for (const region of platformRegions) {
      const profile = regionProfiles[region];
      const listed = VERCEL_REGION_LIST[profile.vercelRegion];
      expect(listed, region).toBeDefined();
      expect(profile.vercelLocation).toBe(listed![1]);
      // The bucket hint is the AWS region Vercel runs that code in, so they stay co-located.
      expect(profile.backupRegionHint).toBe(listed![0]);
    }
    expect(new Set(platformRegions.map((region) => regionProfiles[region].vercelRegion))).toEqual(
      new Set(vercelRegionCodes),
    );
  });

  test("unknown stored values fall back to the default rather than throwing", () => {
    expect(isPlatformRegion("eu-west")).toBe(true);
    expect(isPlatformRegion("us-east-1")).toBe(false);
    expect(isPlatformRegion(42)).toBe(false);
    expect(regionProfile("ap-south").region).toBe("us-east");
  });

  test("changing the region changes the Vercel and backup suggestions but names no SES setting", () => {
    const east = regionSummary({ region: "us-east", vpsRegionLabel: null });
    const central = regionSummary({ region: "eu-central", vpsRegionLabel: "Hetzner fsn1" });
    expect(east.vercelSnippet).toBe('{"regions":["iad1"]}');
    expect(central.vercelSnippet).toBe('{"regions":["fra1"]}');
    expect(central.backupRegionHint).toBe("eu-central-1");
    expect(central.vpsRegionLabel).toBe("Hetzner fsn1");
    expect(central.options.map((option) => option.region)).toEqual([...platformRegions]);
    expect(JSON.stringify(central)).not.toMatch(/AWS_REGION|\bSES\b/);
    expect(regionSummary(null).region).toBe("us-east");
  });
});

describe("region settings input", () => {
  test("accepts presets and normalises the VPS label", () => {
    expect(regionSettingsInput.parse({ region: "eu-west", vpsRegionLabel: "  DO lon1 " })).toEqual({
      region: "eu-west",
      vpsRegionLabel: "DO lon1",
    });
    expect(regionSettingsInput.parse({ region: "us-west" })).toEqual({
      region: "us-west",
      vpsRegionLabel: null,
    });
    expect(regionSettingsInput.parse({ region: "us-east", vpsRegionLabel: "   " }).vpsRegionLabel).toBe(null);
    expect(
      regionSettingsInput.parse({ region: "eu-central", vpsRegionLabel: "Nürnberg (NBG-1), Hetzner" })
        .vpsRegionLabel,
    ).toBe("Nürnberg (NBG-1), Hetzner");
    expect(
      regionSettingsInput.parse({ region: "us-east", vpsRegionLabel: "x".repeat(64) }).vpsRegionLabel,
    ).toHaveLength(64);
  });

  test("rejects unknown regions, oversized or unsafe labels and extra keys", () => {
    for (const region of ["us-east-1", "iad1", "", "US-EAST", null]) {
      expect(regionSettingsInput.safeParse({ region }).success, String(region)).toBe(false);
    }
    for (const label of ["x".repeat(65), "<script>", "Hetzner\nash", "-leading", "a;b", "a\u0000b"]) {
      expect(regionSettingsInput.safeParse({ region: "us-east", vpsRegionLabel: label }).success, label).toBe(
        false,
      );
    }
    expect(
      regionSettingsInput.safeParse({ region: "us-east", vpsRegionLabel: null, awsRegion: "us-east-1" })
        .success,
    ).toBe(false);
  });
});
