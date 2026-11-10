# Research portal

Static Astro + MDX website for the public project record. It contains no inference runtime, traffic ingestion or backend. The content is pinned to the `main` evidence snapshot `b14dfeed9e7cbb07201cfb0ac8ce69c951434be1` (10 November 2026); update the [claim matrix](CLAIMS.md) and `src/lib/links.ts` when refreshing research statuses.

## Local development

From `website/`:

```text
npm ci
npm run dev
npm run check
npm run lint
npm run build
npm run verify:links
```

From the repository root, run `python website/scripts/check-evidence.py` to check source paths and dataset counts. For browser QA, start `npm run preview` from `website/` and then run `npm run smoke` in another terminal; it uses a local Chrome installation.

For a root-path smoke build in PowerShell, set `$env:SITE_BASE = '/'`, then run `npm run build`, `npm run verify:links`, `npm run preview` and `npm run smoke`. Clear it with `Remove-Item Env:SITE_BASE` before a production-subpath build. The default base is `/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN` for the GitHub Pages project URL.

## GitHub Pages setup

The [Pages workflow](../.github/workflows/pages.yml) builds on pull requests with read-only permissions and deploys only after a push to `main`. A PR does **not** publish the site.

After merge, a repository owner must open **Settings → Pages → Build and deployment → Source → GitHub Actions**. Ensure Actions and Pages are enabled and the `github-pages` environment permits deployments from `main`. Then inspect the **Research portal** workflow's `deploy` job and the returned Pages URL. The expected URL is `https://doctor-cato.github.io/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN/`; it should not be reported as live until that job and URL are checked.

Source code remains Apache-2.0. The UQ dataset has separate non-commercial reuse terms; no dataset bytes are shipped here.
