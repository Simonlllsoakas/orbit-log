// Build script for Cloudflare Pages.
// Reads every posts/*.json, sorts by date (newest first),
// and writes dist/posts-index.json that the website loads at runtime.
// Also copies index.html and admin/ into dist/.
// No dependencies — plain Node.js (ES module).
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(import.meta.url));
const dist = path.join(root, "dist");

fs.rmSync(dist, { recursive: true, force: true });
fs.mkdirSync(dist, { recursive: true });

// Static files
fs.copyFileSync(path.join(root, "index.html"), path.join(dist, "index.html"));
fs.cpSync(path.join(root, "admin"), path.join(dist, "admin"), { recursive: true });

// Posts index
const postsDir = path.join(root, "posts");
const posts = fs.readdirSync(postsDir)
  .filter((f) => f.endsWith(".json"))
  .map((f) => {
    const data = JSON.parse(fs.readFileSync(path.join(postsDir, f), "utf8"));
    data.id = data.id || f.replace(/\.json$/, "");
    return data;
  })
  .sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : 0));

fs.writeFileSync(path.join(dist, "posts-index.json"), JSON.stringify(posts));
console.log("Built posts-index.json with", posts.length, "posts");
