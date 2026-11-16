import { defineCollection, z } from "astro:content";
import { glob } from "astro/loaders";

const docSchema = z.object({
  title: z.string(),
  description: z.string(),
  order: z.number(),
});

const docs = defineCollection({
  loader: glob({ pattern: "**/*.mdx", base: "./src/content/docs" }),
  schema: docSchema,
});

const docsEn = defineCollection({
  loader: glob({ pattern: "**/*.mdx", base: "./src/content/docs-en" }),
  schema: docSchema,
});

export const collections = { docs, docsEn };
