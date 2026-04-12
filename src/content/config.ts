import { defineCollection, z } from "astro:content";

const referenceSchema = z.object({
  title: z.string(),
  url: z.string().url(),
  publisher: z.string().optional()
});

const timelineSchema = z.object({
  date: z.string(),
  title: z.string(),
  summary: z.string()
});

const assetSchema = z.object({
  label: z.string(),
  url: z.string(),
  kind: z.enum(["image", "archive", "text", "external"]).default("text")
});

const blog = defineCollection({
  type: "content",
  schema: z.object({
    title: z.string(),
    description: z.string(),
    publishedAt: z.coerce.date(),
    archiveSection: z.enum(["reports", "writeups"]).default("reports"),
    tags: z.array(z.string()).default([]),
    cover: z.string().optional(),
    featured: z.boolean().default(false),
    draft: z.boolean().default(false),
    sourceLabel: z.string().optional(),
    sourceUrl: z.string().url().optional()
  })
});

const actors = defineCollection({
  type: "content",
  schema: z.object({
    name: z.string(),
    aliases: z.array(z.string()).default([]),
    status: z.enum(["active", "tracking", "disrupted", "historic"]),
    origin: z.string(),
    motivation: z.string(),
    targets: z.array(z.string()).default([]),
    firstSeen: z.string(),
    lastSeen: z.string(),
    tools: z.array(z.string()).default([]),
    ttps: z.array(z.string()).default([]),
    tags: z.array(z.string()).default([]),
    timeline: z.array(timelineSchema).default([]),
    references: z.array(referenceSchema).default([]),
    relatedPosts: z.array(z.string()).default([]),
    featured: z.boolean().default(false)
  })
});

const ctfCollections = defineCollection({
  type: "content",
  schema: z.object({
    title: z.string(),
    summary: z.string(),
    status: z.enum(["active", "retired", "archived"]),
    year: z.string(),
    githubUrl: z.string().url(),
    featured: z.boolean().default(false)
  })
});

const ctfChallenges = defineCollection({
  type: "content",
  schema: z.object({
    collection: z.string(),
    title: z.string(),
    difficulty: z.enum(["easy", "medium", "hard"]),
    prompt: z.string(),
    passwordFormat: z.string(),
    assets: z.array(assetSchema).default([]),
    image: z.string().optional(),
    hint: z.string().optional(),
    answerHashes: z.array(z.string()),
    acceptedAliases: z.array(z.string()).default([]),
    order: z.number().int().positive()
  })
});

export const collections = {
  blog,
  actors,
  ctfCollections,
  ctfChallenges
};
