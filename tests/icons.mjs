/**
 * Render `src-tauri/icons/icon.svg` to the PNG sizes `tauri.conf.json` bundles.
 *
 * Rendered with the same headless Chrome `screens.mjs` already drives, for the
 * same reason: the icon is the mark, and the mark is drawn by a browser
 * everywhere else in the product. A second rasteriser would be a second
 * opinion about the geometry.
 *
 * Only the four files that already existed are written. `tauri icon` would
 * emit a further twenty — .icns, .ico, Windows Square*Logo tiles — none of
 * which `tauri.conf.json` references, and unreferenced binaries in the tree
 * are debt nobody reads.
 *
 * Android launcher icons are not written here: `tauri android init` derives
 * `res/mipmap-*` from these on every CI run, and `gen/android` stays generated
 * (SPEC-003 ADR-204).
 *
 *   node tests/icons.mjs
 */

import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import puppeteer from "puppeteer";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const source = join(root, "src-tauri", "icons", "icon.svg");

/** Name → edge length. Matches the files already in `src-tauri/icons`. */
const SIZES = {
  "32x32.png": 32,
  "128x128.png": 128,
  "128x128@2x.png": 256,
  "icon.png": 512,
};

const svg = await readFile(source, "utf8");

const browser = await puppeteer.launch({
  args: process.env.CI ? ["--no-sandbox", "--disable-setuid-sandbox"] : [],
});

try {
  for (const [name, size] of Object.entries(SIZES)) {
    const page = await browser.newPage();
    await page.setViewport({ width: size, height: size, deviceScaleFactor: 1 });
    await page.setContent("<!doctype html><body>", { waitUntil: "load" });

    // Drawn into a canvas rather than screenshotted.
    //
    // `page.screenshot` encodes a fully-opaque capture as a 3-channel PNG —
    // Chrome drops the alpha channel when nothing uses it — and
    // `tauri::generate_context!` refuses those outright with `icon ... is not
    // RGBA`. A canvas is backed by RGBA regardless of what is painted on it, so
    // `toDataURL` always emits colour type 6. Same pixels, four channels.
    const dataUrl = await page.evaluate(
      async (svgSource, edge) => {
        const image = new Image();
        image.src =
          "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svgSource);
        await image.decode();

        const canvas = document.createElement("canvas");
        canvas.width = edge;
        canvas.height = edge;
        canvas.getContext("2d").drawImage(image, 0, 0, edge, edge);
        return canvas.toDataURL("image/png");
      },
      svg,
      size,
    );
    const png = Buffer.from(dataUrl.split(",")[1], "base64");

    // IHDR colour type, byte 25: 6 is RGBA, 2 is RGB. Checked here because the
    // alternative place to find out is a proc-macro panic in an unrelated
    // crate, twenty minutes into a build.
    const colourType = png[25];
    if (colourType !== 6) {
      throw new Error(
        `${name}: PNG colour type ${colourType}, expected 6 (RGBA). ` +
          `tauri::generate_context! will refuse this file.`,
      );
    }

    await writeFile(join(root, "src-tauri", "icons", name), png);
    console.log(`${name.padEnd(16)} ${size}×${size}  RGBA`);
    await page.close();
  }
} finally {
  await browser.close();
}
