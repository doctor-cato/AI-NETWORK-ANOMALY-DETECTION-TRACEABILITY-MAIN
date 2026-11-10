import { readFile, readdir, stat } from "node:fs/promises";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const dist = fileURLToPath(new URL("../dist/", import.meta.url));
const base = (
  process.env.SITE_BASE ?? "/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN"
).replace(/\/$/, "");
const files = [];
async function walk(dir) {
  for (const name of await readdir(dir)) {
    const path = join(dir, name);
    if ((await stat(path)).isDirectory()) await walk(path);
    else files.push(path);
  }
}
await walk(dist);
const publicPaths = new Set(
  files.map((file) => "/" + relative(dist, file).replaceAll("\\", "/")),
);
const htmlFiles = files.filter((file) => file.endsWith(".html"));
const errors = [];
for (const file of htmlFiles) {
  const html = await readFile(file, "utf8");
  const route =
    "/" +
    relative(dist, file)
      .replaceAll("\\", "/")
      .replace(/index\.html$/, "");
  for (const match of html.matchAll(/(?:href|src)="([^"]+)"/g)) {
    const raw = match[1];
    if (/^(https?:|mailto:|data:|javascript:)/.test(raw)) continue;
    const url = new URL(raw, `https://example.invalid${base}${route}`);
    if (!url.pathname.startsWith(`${base}/`)) {
      errors.push(`${route}: outside base: ${raw}`);
      continue;
    }
    const target = url.pathname.slice(base.length) || "/";
    const targetFile = target.endsWith("/") ? `${target}index.html` : target;
    if (!publicPaths.has(targetFile)) {
      errors.push(`${route}: missing ${raw}`);
      continue;
    }
    if (url.hash && targetFile.endsWith(".html")) {
      const targetHtml = await readFile(
        join(dist, targetFile.slice(1)),
        "utf8",
      );
      const id = decodeURIComponent(url.hash.slice(1));
      if (!targetHtml.includes(`id="${id}"`))
        errors.push(`${route}: missing fragment ${raw}`);
    }
  }
}
if (errors.length) {
  console.error(errors.join("\n"));
  process.exitCode = 1;
} else
  console.log(
    `PASS: ${htmlFiles.length} pages, all internal assets and links resolve under ${base || "/"} .`,
  );
