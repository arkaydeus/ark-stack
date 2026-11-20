// Ark Stack icon generator (dev only): derives every committed icon size from the supplied master.
//
//   bun scripts/brand-icons.ts            (also: mise run brand:icons)
//
// The master, assets/brand/ark-stack-icon.png, is the user-supplied 1254×1254 artwork: a white "A" on
// a stack of layers on a navy rounded square whose corners are opaque near-black. Nothing is redrawn;
// every output is the master resampled (exact area average), with only the corners changed:
//
//   - "rounded" outputs (favicons, in-app and README logos, manifest `any` icons) make the corners
//     outside the rounded square transparent, with an anti-aliased edge;
//   - "full-bleed" outputs (apple-touch-icon, the maskable manifest icon) fill the corners with the
//     icon's own navy so iOS and Android can apply their own mask. The artwork already sits inside
//     the maskable safe zone (the centre circle of 80% diameter); the script fails if it ever does not.
//
// It uses only Bun and node:zlib (no image dependency). Outputs are palette-quantised when that
// keeps the error tiny, and the generated files are committed; rerun this only when the master changes.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { deflateSync, inflateSync } from "node:zlib";

export type Image = { width: number; height: number; data: Uint8Array };

const SIGNATURE = Uint8Array.of(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a);

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(bytes: Uint8Array) {
  let c = 0xffffffff;
  for (const byte of bytes) c = CRC_TABLE[(c ^ byte) & 0xff]! ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function paeth(a: number, b: number, c: number) {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
}

/** Decodes an 8-bit, non-interlaced PNG (greyscale, RGB, palette, grey+alpha or RGBA) to RGBA. */
export function decodePng(bytes: Uint8Array): Image {
  if (!SIGNATURE.every((value, index) => bytes[index] === value)) throw new Error("Not a PNG file.");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let width = 0;
  let height = 0;
  let colorType = 0;
  let palette: Uint8Array = new Uint8Array(0);
  let transparency: Uint8Array = new Uint8Array(0);
  const idat: Uint8Array[] = [];
  for (let offset = 8; offset < bytes.length;) {
    const length = view.getUint32(offset);
    const type = String.fromCharCode(...bytes.subarray(offset + 4, offset + 8));
    const body = bytes.subarray(offset + 8, offset + 8 + length);
    if (type === "IHDR") {
      width = view.getUint32(offset + 8);
      height = view.getUint32(offset + 12);
      colorType = body[9]!;
      if (body[8] !== 8 || body[12] !== 0) throw new Error("Only 8-bit, non-interlaced PNGs are supported.");
    } else if (type === "PLTE") palette = body;
    else if (type === "tRNS") transparency = body;
    else if (type === "IDAT") idat.push(body);
    else if (type === "IEND") break;
    offset += 12 + length;
  }
  const channels = ({ 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 } as Record<number, number>)[colorType];
  if (!channels) throw new Error(`Unsupported PNG colour type ${colorType}.`);
  // PNG stores colour-key samples as big-endian 16-bit values, even for 8-bit pixels.
  const key = new DataView(transparency.buffer, transparency.byteOffset, transparency.byteLength);
  const transparentGrey = colorType === 0 && key.byteLength === 2 ? key.getUint16(0) : -1;
  const transparentRgb =
    colorType === 2 && key.byteLength === 6 ? [key.getUint16(0), key.getUint16(2), key.getUint16(4)] : [];
  const raw = inflateSync(Buffer.concat(idat));
  const stride = width * channels;
  const pixels = new Uint8Array(stride * height);
  for (let y = 0; y < height; y++) {
    const filter = raw[y * (stride + 1)]!;
    const source = y * (stride + 1) + 1;
    const row = y * stride;
    for (let x = 0; x < stride; x++) {
      const a = x >= channels ? pixels[row + x - channels]! : 0;
      const b = y > 0 ? pixels[row - stride + x]! : 0;
      const c = x >= channels && y > 0 ? pixels[row - stride + x - channels]! : 0;
      const predictor = [0, a, b, (a + b) >> 1, paeth(a, b, c)][filter];
      if (predictor === undefined) throw new Error(`Invalid PNG filter ${filter}.`);
      pixels[row + x] = (raw[source + x]! + predictor) & 0xff;
    }
  }
  const data = new Uint8Array(width * height * 4);
  for (let i = 0; i < width * height; i++) {
    const p = i * channels;
    let rgba: number[];
    if (colorType === 6) rgba = [pixels[p]!, pixels[p + 1]!, pixels[p + 2]!, pixels[p + 3]!];
    else if (colorType === 2) {
      const r = pixels[p]!;
      const g = pixels[p + 1]!;
      const b = pixels[p + 2]!;
      const alpha = r === transparentRgb[0] && g === transparentRgb[1] && b === transparentRgb[2] ? 0 : 255;
      rgba = [r, g, b, alpha];
    } else if (colorType === 4) rgba = [pixels[p]!, pixels[p]!, pixels[p]!, pixels[p + 1]!];
    else if (colorType === 0) {
      const grey = pixels[p]!;
      rgba = [grey, grey, grey, grey === transparentGrey ? 0 : 255];
    } else {
      const index = pixels[p]!;
      rgba = [...palette.subarray(index * 3, index * 3 + 3), transparency[index] ?? 255];
    }
    data.set(rgba, i * 4);
  }
  return { width, height, data };
}

function chunk(type: string, body: Uint8Array) {
  const out = new Uint8Array(12 + body.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, body.length);
  out.set(new TextEncoder().encode(type), 4);
  out.set(body, 8);
  view.setUint32(8 + body.length, crc32(out.subarray(4, 8 + body.length)));
  return out;
}

/**
 * Filters scanlines and deflates them: adaptive (minimum sum of absolute differences) for truecolour,
 * none for palette indices, where prediction only adds entropy.
 */
function compress(pixels: Uint8Array, stride: number, height: number, bpp: number, adaptive: boolean) {
  const out = new Uint8Array((stride + 1) * height);
  const candidate = new Uint8Array(stride);
  for (let y = 0; y < height; y++) {
    const row = pixels.subarray(y * stride, (y + 1) * stride);
    const above = y > 0 ? pixels.subarray((y - 1) * stride, y * stride) : new Uint8Array(stride);
    let bestScore = Infinity;
    for (const filter of adaptive ? [0, 1, 2, 3, 4] : [0]) {
      let score = 0;
      for (let x = 0; x < stride; x++) {
        const a = x >= bpp ? row[x - bpp]! : 0;
        const b = above[x]!;
        const c = x >= bpp ? above[x - bpp]! : 0;
        const value = (row[x]! - [0, a, b, (a + b) >> 1, paeth(a, b, c)][filter]!) & 0xff;
        candidate[x] = value;
        score += value < 128 ? value : 256 - value;
      }
      if (score < bestScore) {
        bestScore = score;
        out[y * (stride + 1)] = filter;
        out.set(candidate, y * (stride + 1) + 1);
      }
    }
  }
  return deflateSync(out, { level: 9, memLevel: 9 });
}

function header(width: number, height: number, colorType: number) {
  const body = new Uint8Array(13);
  const view = new DataView(body.buffer);
  view.setUint32(0, width);
  view.setUint32(4, height);
  body.set([8, colorType, 0, 0, 0], 8);
  return chunk("IHDR", body);
}

function assemble(chunks: Uint8Array[]) {
  return new Uint8Array(Buffer.concat([SIGNATURE, ...chunks]));
}

/** Truecolour PNG: RGB when every pixel is opaque, RGBA otherwise. */
export function encodePng(image: Image) {
  const opaque = image.data.every((value, index) => index % 4 !== 3 || value === 255);
  const bpp = opaque ? 3 : 4;
  const pixels = opaque ? image.data.filter((_, index) => index % 4 !== 3) : image.data.slice();
  return assemble([
    header(image.width, image.height, opaque ? 2 : 6),
    chunk("IDAT", compress(pixels, image.width * bpp, image.height, bpp, true)),
    chunk("IEND", new Uint8Array(0)),
  ]);
}

/** Indexed PNG with a tRNS chunk for translucent palette entries. */
export function encodeIndexedPng(width: number, height: number, palette: number[][], indices: Uint8Array) {
  const alphas = palette.map((color) => color[3]!);
  const lastTranslucent = alphas.findLastIndex((alpha) => alpha < 255);
  return assemble([
    header(width, height, 3),
    chunk("PLTE", Uint8Array.from(palette.flatMap((color) => color.slice(0, 3)))),
    ...(lastTranslucent >= 0 ? [chunk("tRNS", Uint8Array.from(alphas.slice(0, lastTranslucent + 1)))] : []),
    chunk("IDAT", compress(indices, width, height, 1, false)),
    chunk("IEND", new Uint8Array(0)),
  ]);
}

/**
 * Median-cut palette (at most `maxColors` entries, 256 or fewer) over the image's colours, weighted
 * by pixel count, then nearest-colour mapping without dithering. Returns the palette, the indices
 * and the peak signal-to-noise ratio against the input, in dB.
 */
export function quantize(image: Image, maxColors = 256) {
  const counts = new Map<number, number>();
  const view = new DataView(image.data.buffer, image.data.byteOffset, image.data.byteLength);
  for (let i = 0; i < image.data.length; i += 4) {
    const key = view.getUint32(i);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const colors = [...counts].map(([key, count]) => ({
    rgba: [key >>> 24, (key >>> 16) & 0xff, (key >>> 8) & 0xff, key & 0xff],
    count,
  }));
  type Color = (typeof colors)[number];
  let boxes: Color[][] = [colors];
  const spread = (box: Color[], channel: number) => {
    let min = 255;
    let max = 0;
    for (const color of box) {
      min = Math.min(min, color.rgba[channel]!);
      max = Math.max(max, color.rgba[channel]!);
    }
    return max - min;
  };
  while (boxes.length < maxColors) {
    let target = -1;
    let targetScore = 0;
    let targetChannel = 0;
    boxes.forEach((box, index) => {
      if (box.length < 2) return;
      const weight = Math.sqrt(box.reduce((sum, color) => sum + color.count, 0));
      for (let channel = 0; channel < 4; channel++) {
        const score = spread(box, channel) * weight;
        if (score > targetScore) {
          targetScore = score;
          target = index;
          targetChannel = channel;
        }
      }
    });
    if (target < 0) break;
    const box = boxes[target]!.toSorted((a, b) => a.rgba[targetChannel]! - b.rgba[targetChannel]!);
    const total = box.reduce((sum, color) => sum + color.count, 0);
    let split = 0;
    for (let seen = 0; split < box.length - 1 && seen + box[split]!.count <= total / 2; split++)
      seen += box[split]!.count;
    split = Math.min(Math.max(split, 1), box.length - 1);
    boxes = [...boxes.slice(0, target), box.slice(0, split), box.slice(split), ...boxes.slice(target + 1)];
  }
  const palette = boxes.map((box) => {
    const total = box.reduce((sum, color) => sum + color.count, 0);
    return [0, 1, 2, 3].map((channel) =>
      Math.round(box.reduce((sum, color) => sum + color.rgba[channel]! * color.count, 0) / total),
    );
  });
  // Opaque entries last keeps the tRNS chunk short.
  palette.sort((a, b) => a[3]! - b[3]!);
  const nearest = new Map<number, number>();
  let squaredError = 0;
  for (const { rgba, count } of colors) {
    let best = 0;
    let bestDistance = Infinity;
    palette.forEach((entry, index) => {
      const distance = entry.reduce((sum, value, channel) => sum + (value - rgba[channel]!) ** 2, 0);
      if (distance < bestDistance) {
        bestDistance = distance;
        best = index;
      }
    });
    squaredError += bestDistance * count;
    nearest.set(((rgba[0]! << 24) | (rgba[1]! << 16) | (rgba[2]! << 8) | rgba[3]!) >>> 0, best);
  }
  const indices = new Uint8Array(image.width * image.height);
  for (let i = 0; i < indices.length; i++) indices[i] = nearest.get(view.getUint32(i * 4))!;
  const meanSquaredError = squaredError / (image.width * image.height * 4);
  const psnr = meanSquaredError === 0 ? Infinity : 10 * Math.log10((255 * 255) / meanSquaredError);
  return { palette, indices, psnr };
}

/** Palette sizes tried, smallest first. */
const PALETTE_SIZES = [32, 48, 64, 96, 128, 192, 256];

/**
 * The smallest faithful PNG: the smallest palette whose quantisation keeps the PSNR at or above
 * `minPsnr` dB (50 dB is visually lossless), or truecolour when that is smaller or none qualifies.
 */
export function optimisedPng(image: Image, minPsnr = 50) {
  let best = encodePng(image);
  for (const size of PALETTE_SIZES) {
    const { palette, indices, psnr } = quantize(image, size);
    if (psnr < minPsnr) continue;
    const indexed = encodeIndexedPng(image.width, image.height, palette, indices);
    if (indexed.length < best.length) best = indexed;
    break;
  }
  return best;
}

/** Exact area-average resample in premultiplied alpha (a box filter of the source footprint). */
export function resize(image: Image, size: number): Image {
  const weights = (from: number, to: number) => {
    const scale = from / to;
    return Array.from({ length: to }, (_, target) => {
      const start = target * scale;
      const end = Math.min(from, start + scale);
      const taps: Array<[number, number]> = [];
      for (let source = Math.floor(start); source < Math.ceil(end); source++) {
        const weight = Math.min(end, source + 1) - Math.max(start, source);
        if (weight > 0) taps.push([source, weight / scale]);
      }
      return taps;
    });
  };
  const columns = weights(image.width, size);
  const rows = weights(image.height, size);
  const { width, data } = image;
  // Premultiply, then filter horizontally into a float buffer, then vertically.
  const horizontal = new Float64Array(size * image.height * 4);
  for (let y = 0; y < image.height; y++) {
    for (let x = 0; x < size; x++) {
      const out = (y * size + x) * 4;
      for (const [source, weight] of columns[x]!) {
        const p = (y * width + source) * 4;
        const alpha = data[p + 3]! / 255;
        horizontal[out] += data[p]! * alpha * weight;
        horizontal[out + 1] += data[p + 1]! * alpha * weight;
        horizontal[out + 2] += data[p + 2]! * alpha * weight;
        horizontal[out + 3] += alpha * weight;
      }
    }
  }
  const result = new Uint8Array(size * size * 4);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const sum = [0, 0, 0, 0];
      for (const [source, weight] of rows[y]!) {
        const p = (source * size + x) * 4;
        for (let channel = 0; channel < 4; channel++) sum[channel]! += horizontal[p + channel]! * weight;
      }
      const alpha = sum[3]!;
      const out = (y * size + x) * 4;
      for (let channel = 0; channel < 3; channel++)
        result[out + channel] = alpha > 0 ? Math.round(Math.min(255, sum[channel]! / alpha)) : 0;
      result[out + 3] = Math.round(Math.min(1, alpha) * 255);
    }
  }
  return { width: size, height: size, data: result };
}

/** Measured corner radius of the master's rounded square (circular corners, ±1px on all four). */
export const MASTER_CORNER_RADIUS = 240;
/** How far inside the rounded edge the master's pixels are replaced, past its dark anti-aliasing. */
const EDGE_BAND = 8;

/**
 * Replaces the master's corners. `rounded`: transparent outside the rounded square, anti-aliased on
 * its edge. `full-bleed`: opaque everywhere. Pixels near or beyond the edge take the colour found on
 * the same ray from the corner's centre, `EDGE_BAND` px inside the edge, so the navy (and its
 * gradient) continues without the master's near-black fringe.
 */
export function shapeCorners(image: Image, mode: "rounded" | "full-bleed", radius = MASTER_CORNER_RADIUS) {
  const { width, height, data } = image;
  const out = data.slice();
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const px = x + 0.5;
      const py = y + 0.5;
      const cx = px < radius ? radius : px > width - radius ? width - radius : null;
      const cy = py < radius ? radius : py > height - radius ? height - radius : null;
      if (cx === null || cy === null) continue;
      const dx = px - cx;
      const dy = py - cy;
      const distance = Math.hypot(dx, dy);
      if (distance < radius - EDGE_BAND - 1) continue;
      const inner = radius - EDGE_BAND;
      const sx = Math.min(width - 1, Math.max(0, Math.floor(cx + (dx / distance) * inner)));
      const sy = Math.min(height - 1, Math.max(0, Math.floor(cy + (dy / distance) * inner)));
      const target = (y * width + x) * 4;
      out.set(data.subarray((sy * width + sx) * 4, (sy * width + sx) * 4 + 3), target);
      out[target + 3] =
        mode === "full-bleed" ? 255 : Math.round(Math.min(1, Math.max(0, radius - distance + 0.5)) * 255);
    }
  }
  return { width, height, data: out };
}

/** Bright artwork pixels' farthest distance from the centre, as a fraction of the half-width. */
export function artworkExtent(image: Image) {
  const centre = image.width / 2;
  let extent = 0;
  for (let y = 0; y < image.height; y++) {
    for (let x = 0; x < image.width; x++) {
      const p = (y * image.width + x) * 4;
      if (image.data[p]! + image.data[p + 1]! + image.data[p + 2]! < 3 * 128) continue;
      extent = Math.max(extent, Math.hypot(x + 0.5 - centre, y + 0.5 - centre));
    }
  }
  return extent / centre;
}

/** The mean colour of the navy field (dark pixels inside the rounded square), as `#rrggbb`. */
export function navy(image: Image, radius = MASTER_CORNER_RADIUS) {
  const sum = [0, 0, 0];
  let count = 0;
  for (let y = radius; y < image.height - radius; y++) {
    for (let x = 0; x < image.width; x++) {
      const p = (y * image.width + x) * 4;
      const brightness = image.data[p]! + image.data[p + 1]! + image.data[p + 2]!;
      if (brightness < 15 || brightness > 120) continue;
      for (let channel = 0; channel < 3; channel++) sum[channel]! += image.data[p + channel]!;
      count++;
    }
  }
  if (count === 0) throw new Error("The master has no navy pixels from which to derive the theme colour.");
  return `#${sum
    .map((value) =>
      Math.round(value / count)
        .toString(16)
        .padStart(2, "0"),
    )
    .join("")}`;
}

/** A PNG-compressed `.ico` (Windows Vista and every current browser read PNG entries). */
export function encodeIco(images: Array<{ size: number; png: Uint8Array }>) {
  const headerSize = 6 + images.length * 16;
  const out = new Uint8Array(headerSize + images.reduce((sum, image) => sum + image.png.length, 0));
  const view = new DataView(out.buffer);
  view.setUint16(2, 1, true);
  view.setUint16(4, images.length, true);
  let offset = headerSize;
  images.forEach(({ size, png }, index) => {
    const entry = 6 + index * 16;
    out[entry] = size >= 256 ? 0 : size;
    out[entry + 1] = size >= 256 ? 0 : size;
    view.setUint16(entry + 4, 1, true);
    view.setUint16(entry + 6, 32, true);
    view.setUint32(entry + 8, png.length, true);
    view.setUint32(entry + 12, offset, true);
    out.set(png, offset);
    offset += png.length;
  });
  return out;
}

const ROOT = join(import.meta.dir, "..");
export const MASTER = "assets/brand/ark-stack-icon.png";

/** Every derived file, relative to the repository root. */
export const OUTPUTS = {
  readme: { path: "assets/brand/ark-stack-icon-256.png", size: 256, mode: "rounded" },
  favicon32: { path: "web/public/brand/icon-32.png", size: 32, mode: "rounded" },
  logo: { path: "web/public/brand/icon-96.png", size: 96, mode: "rounded" },
  appleTouch: { path: "web/public/brand/apple-touch-icon.png", size: 180, mode: "full-bleed" },
  any192: { path: "web/public/brand/icon-192.png", size: 192, mode: "rounded" },
  any512: { path: "web/public/brand/icon-512.png", size: 512, mode: "rounded" },
  maskable512: { path: "web/public/brand/icon-maskable-512.png", size: 512, mode: "full-bleed" },
} as const;
export const FAVICON_ICO = { path: "web/public/favicon.ico", sizes: [16, 32, 48] } as const;
/** The maskable safe zone: a centred circle whose diameter is 80% of the icon. */
export const SAFE_ZONE = 0.8;

export function generate(root = ROOT) {
  const master = decodePng(readFileSync(join(root, MASTER)));
  const extent = artworkExtent(master);
  if (extent > SAFE_ZONE)
    throw new Error(`Artwork reaches ${extent.toFixed(3)} of the half-width (> ${SAFE_ZONE}).`);
  const colour = navy(master);
  const themeFiles = [
    { path: "web/index.html", patterns: [/(<meta name="theme-color" content=")[^"]+(")/] },
    {
      path: "web/public/manifest.webmanifest",
      patterns: [/("theme_color"\s*:\s*")[^"]+(")/, /("background_color"\s*:\s*")[^"]+(")/],
    },
  ].map(({ path, patterns }) => {
    const file = join(root, path);
    const original = readFileSync(file, "utf8");
    let updated = original;
    for (const pattern of patterns) {
      if (!pattern.test(updated)) throw new Error(`Missing generated colour field in ${path}.`);
      updated = updated.replace(
        pattern,
        (_match, prefix: string, suffix: string) => prefix + colour + suffix,
      );
    }
    return { file, original, updated };
  });
  const shaped = {
    rounded: shapeCorners(master, "rounded"),
    "full-bleed": shapeCorners(master, "full-bleed"),
  };
  const write = (path: string, bytes: Uint8Array) => {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), bytes);
    console.log(`${path.padEnd(42)} ${bytes.length.toLocaleString("en").padStart(7)} bytes`);
  };
  for (const output of Object.values(OUTPUTS))
    write(output.path, optimisedPng(resize(shaped[output.mode], output.size)));
  write(
    FAVICON_ICO.path,
    encodeIco(FAVICON_ICO.sizes.map((size) => ({ size, png: optimisedPng(resize(shaped.rounded, size)) }))),
  );
  for (const { file, original, updated } of themeFiles) {
    if (original !== updated) writeFileSync(file, updated);
  }
  console.log(`artwork extent ${extent.toFixed(3)} of the half-width (safe zone ${SAFE_ZONE})`);
  console.log(`navy ${colour} (web/index.html and web/public/manifest.webmanifest)`);
  console.log(`from ${relative(process.cwd(), join(root, MASTER))}`);
}

if (import.meta.main) generate();
