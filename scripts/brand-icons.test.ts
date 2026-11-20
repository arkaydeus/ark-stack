// The committed Ark Stack icons: derived from the one master, right sizes and shapes, small files.
import { describe, expect, test } from "bun:test";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  FAVICON_ICO,
  MASTER,
  OUTPUTS,
  SAFE_ZONE,
  artworkExtent,
  decodePng,
  encodeIco,
  encodeIndexedPng,
  encodePng,
  generate,
  navy,
  optimisedPng,
  quantize,
  resize,
  shapeCorners,
  type Image,
} from "./brand-icons.ts";

const root = join(import.meta.dir, "..");
const read = (path: string) => new Uint8Array(readFileSync(join(root, path)));
const master = decodePng(read(MASTER));
const alpha = (image: Image, x: number, y: number) => image.data[(y * image.width + x) * 4 + 3]!;
const brightness = (image: Image, x: number, y: number) => {
  const p = (y * image.width + x) * 4;
  return image.data[p]! + image.data[p + 1]! + image.data[p + 2]!;
};

/** The `.ico` directory: each entry's size and embedded PNG. */
function icoEntries(bytes: Uint8Array) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  expect(view.getUint16(0, true)).toBe(0);
  expect(view.getUint16(2, true)).toBe(1);
  return Array.from({ length: view.getUint16(4, true) }, (_, index) => {
    const entry = 6 + index * 16;
    const offset = view.getUint32(entry + 12, true);
    return {
      size: bytes[entry]! || 256,
      png: bytes.subarray(offset, offset + view.getUint32(entry + 8, true)),
    };
  });
}

describe("PNG and ICO codec", () => {
  const image: Image = {
    width: 3,
    height: 2,
    // Two rows of three RGBA pixels: opaque, translucent and transparent, then three opaque.
    data: Uint8Array.from([
      255, 0, 0, 255, 0, 255, 0, 128, 0, 0, 255, 0, 10, 20, 30, 255, 40, 50, 60, 255, 70, 80, 90, 255,
    ]),
  };

  test("truecolour and indexed encodings round-trip", () => {
    expect(decodePng(encodePng(image))).toEqual(image);
    const { palette, indices, psnr } = quantize(image);
    expect(psnr).toBe(Infinity);
    expect(decodePng(encodeIndexedPng(3, 2, palette, indices))).toEqual(image);
    expect(decodePng(optimisedPng(image))).toEqual(image);
  });

  test("an opaque image is stored as RGB", () => {
    const opaque = { ...image, data: image.data.map((value, index) => (index % 4 === 3 ? 255 : value)) };
    expect(encodePng(opaque)[25]).toBe(2);
    expect(decodePng(encodePng(opaque))).toEqual(opaque);
  });

  test.each([
    [
      "RGB",
      "iVBORw0KGgoAAAANSUhEUgAAAAIAAAABCAIAAAB7QOjdAAAABnRSTlMABwAKABYlxesGAAAAD0lEQVR4nGNg5xITEBEDAAEpAGIMZux8AAAAAElFTkSuQmCC",
      [7, 10, 22, 0, 16, 20, 22, 255],
    ],
    [
      "greyscale",
      "iVBORw0KGgoAAAANSUhEUgAAAAIAAAABCAAAAADRSSBWAAAAAnRSTlMAFoJHeGkAAAALSURBVHicYxATBwAARgAuCfgjjwAAAABJRU5ErkJggg==",
      [22, 22, 22, 0, 23, 23, 23, 255],
    ],
  ] as const)("decodes an 8-bit %s PNG with a colour key", (_format, png, rgba) => {
    expect(decodePng(Buffer.from(png, "base64")).data).toEqual(Uint8Array.from(rgba));
  });

  test.each([
    [7, 3],
    [1014, 180],
  ])("resamples uniform %ipx to %ipx through the edges", (from, to) => {
    const flat: Image = { width: from, height: from, data: new Uint8Array(from * from * 4).fill(200) };
    expect(resize(flat, to).data.every((value) => value === 200)).toBe(true);
  });

  test("reports a missing navy field", () => {
    const white = decodePng(encodePng({ width: 2, height: 2, data: new Uint8Array(16).fill(255) }));
    expect(() => navy(white, 0)).toThrow("The master has no navy pixels");
  });

  test("an ICO wraps each PNG with its size", () => {
    const png = encodePng(image);
    expect(icoEntries(encodeIco([{ size: 16, png }]))).toEqual([{ size: 16, png }]);
  });
});

test("regenerating from a shifted master updates both admin theme files", () => {
  const fixture = mkdtempSync(join(tmpdir(), "ark-brand-"));
  try {
    mkdirSync(join(fixture, "assets/brand"), { recursive: true });
    mkdirSync(join(fixture, "web/public"), { recursive: true });
    for (const path of ["web/index.html", "web/public/manifest.webmanifest"])
      copyFileSync(join(root, path), join(fixture, path));
    const shifted = {
      ...master,
      data: master.data.map((value, i) => (i % 4 === 2 && value < 40 && value > 4 ? value + 8 : value)),
    };
    const colour = navy(shifted);
    expect(colour).not.toBe(navy(master));
    writeFileSync(join(fixture, MASTER), encodePng(shifted));
    generate(fixture);
    expect(readFileSync(join(fixture, "web/index.html"), "utf8")).toContain(
      `<meta name="theme-color" content="${colour}" />`,
    );
    const manifest = JSON.parse(readFileSync(join(fixture, "web/public/manifest.webmanifest"), "utf8"));
    expect(manifest.theme_color).toBe(colour);
    expect(manifest.background_color).toBe(colour);
    expect(manifest.icons).toEqual(
      JSON.parse(readFileSync(join(root, "web/public/manifest.webmanifest"), "utf8")).icons,
    );
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

describe("committed icons", () => {
  test("the master is the supplied 1254px artwork with near-black square corners", () => {
    expect([master.width, master.height]).toEqual([1254, 1254]);
    expect(brightness(master, 0, 0)).toBeLessThan(6);
    expect(brightness(master, 627, 0)).toBeGreaterThan(30);
  });

  test("the artwork sits inside the maskable safe zone", () => {
    expect(artworkExtent(master)).toBeLessThanOrEqual(SAFE_ZONE);
    const maskable = decodePng(read(OUTPUTS.maskable512.path));
    expect(artworkExtent(maskable)).toBeLessThanOrEqual(SAFE_ZONE);
  });

  for (const [name, output] of Object.entries(OUTPUTS)) {
    test(`${name}: ${output.size}px ${output.mode}, faithful to the master`, () => {
      const image = decodePng(read(output.path));
      expect([image.width, image.height]).toEqual([output.size, output.size]);
      const last = output.size - 1;
      const middle = output.size >> 1;
      for (const [x, y] of [
        [0, 0],
        [last, 0],
        [0, last],
        [last, last],
      ] as const) {
        if (output.mode === "rounded") expect(alpha(image, x, y)).toBe(0);
        else {
          expect(alpha(image, x, y)).toBe(255);
          // Filled with the icon's navy, not the master's near-black corners.
          expect(brightness(image, x, y)).toBeGreaterThan(15);
        }
      }
      expect(alpha(image, middle, 0)).toBe(255);
      if (output.mode === "full-bleed")
        expect(image.data.every((v, i) => i % 4 !== 3 || v === 255)).toBe(true);
      // Pixel-for-pixel close to a fresh derivation from the master (quantisation only).
      const fresh = resize(shapeCorners(master, output.mode), output.size);
      let squared = 0;
      fresh.data.forEach((value, index) => (squared += (value - image.data[index]!) ** 2));
      expect(10 * Math.log10((255 * 255) / (squared / fresh.data.length || 1e-9))).toBeGreaterThan(45);
    });
  }

  test("favicon.ico holds the 16, 32 and 48px rounded icons", () => {
    const entries = icoEntries(read(FAVICON_ICO.path));
    expect(entries.map((entry) => entry.size)).toEqual([...FAVICON_ICO.sizes]);
    for (const entry of entries) {
      const image = decodePng(entry.png);
      expect([image.width, image.height]).toEqual([entry.size, entry.size]);
      // At 16px one pixel covers 78 source pixels, so the corner is a few percent covered.
      expect(alpha(image, 0, 0)).toBeLessThan(16);
      expect(alpha(image, entry.size >> 1, entry.size >> 1)).toBe(255);
    }
  });

  test("files are small, and the master never ships with the web UI", () => {
    const limits: Record<string, number> = { 32: 4_000, 96: 8_000, 180: 16_000, 192: 24_000, 256: 40_000 };
    for (const output of Object.values(OUTPUTS))
      expect(statSync(join(root, output.path)).size).toBeLessThan(limits[output.size] ?? 120_000);
    expect(statSync(join(root, FAVICON_ICO.path)).size).toBeLessThan(8_000);
    const publicFiles = (dir: string): string[] =>
      readdirSync(join(root, dir), { withFileTypes: true }).flatMap((entry) =>
        entry.isDirectory() ? publicFiles(`${dir}/${entry.name}`) : [`${dir}/${entry.name}`],
      );
    for (const file of publicFiles("web/public"))
      expect(statSync(join(root, file)).size).toBeLessThan(200_000);
  });

  test("the theme colour in the page head and manifest is the icon's navy", () => {
    const colour = navy(master);
    expect(readFileSync(join(root, "web/index.html"), "utf8")).toContain(
      `<meta name="theme-color" content="${colour}" />`,
    );
    const manifest = JSON.parse(readFileSync(join(root, "web/public/manifest.webmanifest"), "utf8"));
    expect(manifest.theme_color).toBe(colour);
    expect(manifest.background_color).toBe(colour);
    expect(manifest.icons).toEqual([
      { src: "/brand/icon-192.png", sizes: "192x192", type: "image/png", purpose: "any" },
      { src: "/brand/icon-512.png", sizes: "512x512", type: "image/png", purpose: "any" },
      { src: "/brand/icon-maskable-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
    ]);
    for (const icon of manifest.icons)
      expect(statSync(join(root, "web/public", icon.src)).isFile()).toBe(true);
  });
});
