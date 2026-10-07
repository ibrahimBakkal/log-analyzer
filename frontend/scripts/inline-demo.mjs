// Folds the demo build into one file: dist-demo/index.html with its script and
// stylesheet inside. A single file can be opened from disk, mailed, or put on any
// static host, and nothing in it depends on where it is served from.
//
// Run by `npm run build:demo`, after `vite build --mode demo`.

import { readFileSync, rmSync, statSync, writeFileSync } from "node:fs";

const dist = new URL("../dist-demo/", import.meta.url);
const read = (file) => readFileSync(new URL(file, dist), "utf8");

// Inside an inline <script>, these two sequences would end or derail the element.
const inlineScript = (code) => code.replaceAll("</script", "<\\/script").replaceAll("<!--", "<\\!--");

let html = read("index.html");
let inlined = 0;
html = html.replace(/<link rel="stylesheet"[^>]*href="\.\/([^"]+)"[^>]*>/g, (_, file) => {
  inlined += 1;
  return `<style>${read(file)}</style>`;
});
html = html.replace(/<script type="module"[^>]*src="\.\/([^"]+)"[^>]*><\/script>/g, (_, file) => {
  inlined += 1;
  return `<script type="module">${inlineScript(read(file))}</script>`;
});

const left = html.match(/(?:src|href)="\.\/assets\/[^"]+"/g);
if (inlined < 2 || left) {
  console.error(`inline-demo: expected one stylesheet and one script, and nothing else to load. Left: ${left ?? "none"}`);
  process.exit(1);
}

writeFileSync(new URL("index.html", dist), html);
rmSync(new URL("assets/", dist), { recursive: true, force: true });
const kilobytes = Math.round(statSync(new URL("index.html", dist)).size / 1024);
console.log(`dist-demo/index.html is self-contained (${kilobytes} kB)`);
