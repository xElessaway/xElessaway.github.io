import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import assert from "node:assert";

console.log("▶ Running Dark Theme & Search Audit Test Suite...\n");

// 1. Check CSS Dark Theme Tokens
console.log("1. Checking dark theme token coverage in global.css...");
const cssContent = readFileSync(resolve("src/styles/global.css"), "utf8");

assert(cssContent.includes('[data-theme="dark"] .archive-tag-chip'), "Missing dark theme .archive-tag-chip");
assert(cssContent.includes('[data-theme="dark"] .article-tag-chip'), "Missing dark theme .article-tag-chip");
assert(cssContent.includes('[data-theme="dark"] .difficulty-chip.medium'), "Missing dark theme .difficulty-chip.medium");
assert(cssContent.includes('[data-theme="dark"] .difficulty-chip.hard'), "Missing dark theme .difficulty-chip.hard");
assert(cssContent.includes('[data-theme="dark"] .difficulty-chip.easy'), "Missing dark theme .difficulty-chip.easy");
assert(cssContent.includes('[data-theme="dark"] .article-type-pill'), "Missing dark theme .article-type-pill");
assert(cssContent.includes('[data-theme="dark"] .archive-code-snippet'), "Missing dark theme .archive-code-snippet");
assert(cssContent.includes(".menu-toggle"), "Missing .menu-toggle rules");
console.log("  ✓ All dark theme token selectors verified.");

// 2. Check Owner Social Profiles (GitHub removal from presentation)
console.log("2. Verifying owner social profile presentation...");
const siteData = readFileSync(resolve("src/data/site.ts"), "utf8");
const aboutPage = readFileSync(resolve("src/pages/about.astro"), "utf8");

assert(!siteData.includes('label: "GitHub"'), "GitHub should be removed from siteMeta.socials");
assert(!aboutPage.includes('name: "github"'), "GitHub should be removed from about.astro socialProfiles");
assert(siteData.includes("LinkedIn") && siteData.includes("Medium") && siteData.includes("X"), "LinkedIn, Medium, and X must remain");
console.log("  ✓ Owner profile presentation cleanly excludes GitHub while maintaining verified channels.");

// 3. Check Imikom Asset Mapping
console.log("3. Verifying Imikom article cover asset mapping...");
const imikomArticle = readFileSync(resolve("src/content/blog/imikom-agent-analyzing-github-and-google-sheets-cloud-dead-drop-c2-tradecraft.md"), "utf8");
assert(!imikomArticle.includes("exposed-quickdav-malware-distribution-repository"), "Imikom article must not reference QuickDAV images");
assert(imikomArticle.includes("imikom-agent-analyzing-github-and-google-sheets-cloud-dead-drop-c2-tradecraft/img-01.png"), "Imikom article must reference dedicated exhibit image");
assert(existsSync(resolve("public/images/posts/imikom-agent-analyzing-github-and-google-sheets-cloud-dead-drop-c2-tradecraft/img-01.png")), "Imikom exhibit image file must exist on disk");
console.log("  ✓ Imikom asset path and exhibit file verified.");

// 4. Search Filter Logic Simulation
console.log("4. Testing Threat Intel Search filtering logic...");
const mockDossiers = [
  {
    title: "Threat Cluster 2.27.63.244",
    aliases: ["imikom", "agent47"],
    tags: ["dfir", "threat-intelligence", "malware-analysis"],
    motivation: "Targeted corporate perimeter infiltration",
    origin: "Global",
    status: "tracking"
  },
  {
    title: "RedHydra Adaptix Cluster",
    aliases: ["redhydra"],
    tags: ["c2-infrastructure", "threat-intelligence"],
    motivation: "Staging and credential theft",
    origin: "Eastern Europe",
    status: "active"
  }
];

function filterDossiers(query, items) {
  const q = query.trim().toLowerCase();
  return items.filter((item) => {
    const searchTokens = [
      item.title,
      ...(item.aliases || []),
      ...(item.tags || []),
      item.motivation,
      item.origin,
      item.status
    ].filter(Boolean).join(" ").toLowerCase();
    return !q || searchTokens.includes(q);
  });
}

// Test match query
const matchesImikom = filterDossiers("imikom", mockDossiers);
assert.strictEqual(matchesImikom.length, 1, "Query 'imikom' should match exactly 1 dossier");
assert.strictEqual(matchesImikom[0].title, "Threat Cluster 2.27.63.244");

// Test no-match query
const matchesNone = filterDossiers("zzzz-not-found", mockDossiers);
assert.strictEqual(matchesNone.length, 0, "Query 'zzzz-not-found' must match 0 dossiers");

// Test empty query (restoring all dossiers)
const matchesAll = filterDossiers("", mockDossiers);
assert.strictEqual(matchesAll.length, 2, "Empty query must restore all dossiers");

console.log("  ✓ Threat Intel search algorithm correctly handles matches, no-matches (empty state), and resets.");

console.log("\n✅ All audit tests passed successfully!");
