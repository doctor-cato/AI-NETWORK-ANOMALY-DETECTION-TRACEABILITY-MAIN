import { defineConfig } from "astro/config";
import mdx from "@astrojs/mdx";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  site: "https://doctor-cato.github.io",
  base:
    process.env.SITE_BASE ?? "/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN",
  trailingSlash: "always",
  integrations: [mdx()],
  vite: { plugins: [tailwindcss()] },
});
