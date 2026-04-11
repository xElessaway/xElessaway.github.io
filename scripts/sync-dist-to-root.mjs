import { cp, mkdir, readdir, rm } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const distDir = path.join(rootDir, "dist");

const preservedEntries = new Set([
  ".astro",
  ".git",
  ".github",
  ".gitignore",
  "README.md",
  "astro.config.mjs",
  "dist",
  "node_modules",
  "package-lock.json",
  "package.json",
  "public",
  "scripts",
  "src",
  "tsconfig.json"
]);

async function sync() {
  const rootEntries = await readdir(rootDir, { withFileTypes: true });

  for (const entry of rootEntries) {
    if (preservedEntries.has(entry.name)) {
      continue;
    }

    await rm(path.join(rootDir, entry.name), { recursive: true, force: true });
  }

  await mkdir(rootDir, { recursive: true });
  await cp(distDir, rootDir, { recursive: true, force: true });
}

sync().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
