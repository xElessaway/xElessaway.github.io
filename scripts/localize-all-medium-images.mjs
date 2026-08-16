import { readdir, readFile, writeFile, mkdir } from "node:fs/promises";
import { join, extname } from "node:path";
import { existsSync } from "node:fs";

const BLOG_DIR = "./src/content/blog";
const PUBLIC_DIR = "./public/images/posts";

async function downloadImage(url, destPath) {
  try {
    const res = await fetch(url, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
      }
    });

    if (!res.ok) {
      console.warn(`[FAILED] ${res.status} ${url}`);
      return false;
    }

    const buffer = Buffer.from(await res.arrayBuffer());
    await writeFile(destPath, buffer);
    return true;
  } catch (err) {
    console.error(`[ERROR] downloading ${url}:`, err.message);
    return false;
  }
}

async function main() {
  const files = await readdir(BLOG_DIR);
  const mdFiles = files.filter((f) => f.endsWith(".md"));

  console.log(`Found ${mdFiles.length} markdown articles.`);

  for (const file of mdFiles) {
    const slug = file.replace(/\.md$/, "");
    const filePath = join(BLOG_DIR, file);
    let content = await readFile(filePath, "utf-8");

    // Match all medium images: https://cdn-images-1.medium.com/... or https://miro.medium.com/...
    const imageRegex = /https:\/\/(?:cdn-images-\d+\.medium\.com|miro\.medium\.com)\/[^\s"'\)>]+/g;
    const matches = [...new Set(content.match(imageRegex) || [])];

    if (matches.length === 0) {
      console.log(`[OK] No external medium images in ${file}`);
      continue;
    }

    console.log(`\n[PROCESSING] ${file}: Found ${matches.length} external images.`);
    const targetDir = join(PUBLIC_DIR, slug);
    await mkdir(targetDir, { recursive: true });

    let index = 1;
    for (const imgUrl of matches) {
      // Determine file extension
      let ext = extname(imgUrl.split("?")[0]) || ".png";
      if (![".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg"].includes(ext.toLowerCase())) {
        ext = ".png";
      }

      const fileName = `img-${String(index).padStart(2, "0")}${ext}`;
      const destPath = join(targetDir, fileName);
      const publicPath = `/images/posts/${slug}/${fileName}`;

      console.log(`  Downloading (${index}/${matches.length}): ${imgUrl.slice(0, 60)}... -> ${publicPath}`);
      const success = await downloadImage(imgUrl, destPath);

      if (success) {
        // Replace all occurrences of this image URL in the content
        content = content.replaceAll(imgUrl, publicPath);
      }
      index++;
    }

    await writeFile(filePath, content, "utf-8");
    console.log(`[DONE] Updated ${file} with localized image paths.`);
  }

  console.log("\n All blog images successfully localized to public/images/posts/!");
}

main().catch(console.error);
