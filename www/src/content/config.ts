import { defineCollection, z } from 'astro:content';

const docsCollection = defineCollection({
  type: 'content',
  schema: z.object({
    title: z.string(),
    description: z.string().optional(),
    order: z.number().optional().default(999),
  }),
});

const blogCollection = defineCollection({
  type: 'content',
  schema: z.object({
    title: z.string(),
    subline: z.string(),
    date: z.date(),
    teaser: z.string(),
  }),
});

export const collections = {
  docs: docsCollection,
  blog: blogCollection,
};
