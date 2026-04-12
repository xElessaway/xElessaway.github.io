import { createHash } from "node:crypto";
import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const FEED_URL = process.env.MEDIUM_FEED_URL || "https://xelessaway.medium.com/feed";
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const blogDir = path.join(rootDir, "src", "content", "blog");
const EXCLUDED_SLUGS = new Set([
  "0xl4ugh-ctf-2023",
  "auc-hotaru-games-writeups",
  "jordan-infosec-ctf-2022-qualifications"
]);
const FEATURED_SLUGS = new Set([
  "how-a-phone-number-can-reveal-your-entire-identity-real-osint-cases",
  "how-a-malicious-application-used-a-game-demo-to-deliver-an-infostealer",
  "egctf25-digital-forensics-writeup"
]);
const MOJIBAKE_MARKERS = ["â€™", "â€œ", "â€", "â€“", "â€”", "â€¦", "Ã", "Â"];

function normalizeEncoding(value) {
  if (!value) {
    return value;
  }

  if (!MOJIBAKE_MARKERS.some((marker) => value.includes(marker))) {
    return value;
  }

  return Buffer.from(value, "latin1").toString("utf8");
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function extractTag(block, tag) {
  const safeTag = escapeRegex(tag);
  const cdataMatch = block.match(new RegExp(`<${safeTag}(?:\\s[^>]*)?><!\\[CDATA\\[([\\s\\S]*?)\\]\\]><\\/${safeTag}>`, "i"));

  if (cdataMatch) {
    return normalizeEncoding(cdataMatch[1].trim());
  }

  const plainMatch = block.match(new RegExp(`<${safeTag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${safeTag}>`, "i"));
  return plainMatch ? normalizeEncoding(plainMatch[1].trim()) : "";
}

function extractTags(block, tag) {
  const safeTag = escapeRegex(tag);
  const matches = [...block.matchAll(new RegExp(`<${safeTag}(?:\\s[^>]*)?><!\\[CDATA\\[([\\s\\S]*?)\\]\\]><\\/${safeTag}>`, "gi"))];
  return matches.map((match) => normalizeEncoding(match[1].trim())).filter(Boolean);
}

function decodeEntities(value) {
  return normalizeEncoding(
    value
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
  );
}

function stripHtml(value) {
  return decodeEntities(value.replace(/<[^>]+>/g, " ").replace(/\u00a0/g, " ")).replace(/\s+/g, " ").trim();
}

function slugify(value) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-{2,}/g, "-");
}

function toYamlString(value) {
  return JSON.stringify(value);
}

function trimDescription(value) {
  if (value.length <= 180) {
    return value;
  }

  const shortened = value.slice(0, 177).replace(/\s+\S*$/, "").trim();
  return `${shortened}...`;
}

function deriveSlug(title, link, seenSlugs) {
  const url = new URL(link);
  const lastSegment = url.pathname.split("/").filter(Boolean).at(-1) || "";
  const mediumSlug = lastSegment.replace(/-[0-9a-f]{12}$/i, "");
  const baseSlug = slugify(mediumSlug || title) || `post-${createHash("sha1").update(link).digest("hex").slice(0, 8)}`;

  if (!seenSlugs.has(baseSlug)) {
    seenSlugs.add(baseSlug);
    return baseSlug;
  }

  const uniqueSlug = `${baseSlug}-${createHash("sha1").update(link).digest("hex").slice(0, 6)}`;
  seenSlugs.add(uniqueSlug);
  return uniqueSlug;
}

function cleanBody(html) {
  let body = normalizeEncoding(html)
    .replace(/\u00a0/g, " ")
    .replace(/<img[^>]+src="https:\/\/medium\.com\/_\/stat[^"]*"[^>]*>/gi, "")
    .replace(/<img\b/gi, '<img loading="lazy" referrerpolicy="no-referrer"')
    .trim();

  const closingPatterns = [
    /<p><em>Share this with someone[\s\S]*?<\/em><\/p>\s*$/i,
    /<p><em>Follow for more[\s\S]*?<\/em><\/p>\s*$/i,
    /<p><em>#[\s\S]*?<\/em><\/p>\s*$/i
  ];

  let changed = true;
  while (changed) {
    changed = false;

    for (const pattern of closingPatterns) {
      if (pattern.test(body)) {
        body = body.replace(pattern, "").trim();
        changed = true;
      }
    }
  }

  return body;
}

function buildFrontmatter(post, featured) {
  const lines = [
    "---",
    `title: ${toYamlString(post.title)}`,
    `description: ${toYamlString(post.description)}`,
    `publishedAt: ${post.publishedAt}`
  ];

  if (post.tags.length === 0) {
    lines.push("tags: []");
  } else {
    lines.push("tags:");
    for (const tag of post.tags) {
      lines.push(`  - ${toYamlString(tag)}`);
    }
  }

  if (post.cover) {
    lines.push(`cover: ${toYamlString(post.cover)}`);
  }

  lines.push(`featured: ${featured}`);
  lines.push("draft: false");
  lines.push('sourceLabel: "Medium"');
  lines.push(`sourceUrl: ${toYamlString(post.link)}`);
  lines.push("---", "", post.body, "");

  return lines.join("\n");
}

async function removeExistingMediumPosts() {
  const entries = await readdir(blogDir, { withFileTypes: true });

  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith(".md")) {
      continue;
    }

    const filePath = path.join(blogDir, entry.name);
    const contents = await readFile(filePath, "utf8");

    if (contents.includes('sourceLabel: "Medium"')) {
      await rm(filePath, { force: true });
    }
  }
}

async function fetchFeed() {
  const response = await fetch(FEED_URL, {
    headers: {
      "user-agent": "xelessaway-site-sync/1.0"
    }
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch Medium feed: ${response.status} ${response.statusText}`);
  }

  return response.text();
}

async function sync() {
  await mkdir(blogDir, { recursive: true });
  await removeExistingMediumPosts();

  const xml = await fetchFeed();
  const itemMatches = [...xml.matchAll(/<item>([\s\S]*?)<\/item>/g)];
  const seenSlugs = new Set();

  const posts = itemMatches
    .map((match) => {
      const item = match[1];
      const title = extractTag(item, "title");
      const rawLink = extractTag(item, "link");
      const link = rawLink.replace(/\?source=.*/, "");
      const publishedAt = new Date(extractTag(item, "pubDate")).toISOString().slice(0, 10);
      const tags = extractTags(item, "category").map((tag) => tag.toLowerCase());
      const rawBody = extractTag(item, "content:encoded");
      const body = cleanBody(rawBody);
      const descriptionSource = [...body.matchAll(/<p>([\s\S]*?)<\/p>/gi)]
        .map((paragraph) => stripHtml(paragraph[1]))
        .find((paragraph) => paragraph.length > 0) || title;
      const description = trimDescription(descriptionSource);
      const coverMatch = body.match(/<img[^>]+src="([^"]+)"/i);
      const cover = coverMatch ? coverMatch[1] : undefined;
      const slug = deriveSlug(title, link, seenSlugs);

      return {
        title,
        description,
        publishedAt,
        tags,
        cover,
        body,
        link,
        slug
      };
    })
    .filter((post) => !EXCLUDED_SLUGS.has(post.slug))
    .sort((left, right) => right.publishedAt.localeCompare(left.publishedAt));

  for (const post of posts) {
    const fileName = `${post.slug}.md`;
    const filePath = path.join(blogDir, fileName);
    const contents = buildFrontmatter(post, FEATURED_SLUGS.has(post.slug));
    await writeFile(filePath, contents, "utf8");
  }

  console.log(`Synced ${posts.length} Medium post(s) into ${blogDir}`);
}

sync().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
