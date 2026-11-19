# Research portal — NetFlow Sentinel v2.0

Static Astro + MDX website on the dedicated `site-source` branch. It contains no inference runtime, traffic ingestion or backend. The [claim matrix](CLAIMS.md) is pinned to the NetFlow Sentinel `v2.0.0` evidence snapshot `36f63081bf30de98b1dc1058a780ae79ae2cf5b3` (19 November 2026, Issue `#152` / PR `#156`).

## Local development

From this branch root:

```text
npm ci
npm run dev
npm run check
npm run lint
npm run build
npm run verify:links
```

For browser QA, start `npm run preview` and run `npm run smoke` in another terminal; it uses a local Chrome installation. For claim verification against an existing research checkout, set `EVIDENCE_ROOT` to its absolute path and run `python scripts/check-evidence.py`. CI checks out the pinned evidence commit automatically.

The default base is `/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN`. To test root hosting in PowerShell, set `$env:SITE_BASE = '/'` before building, link validation and browser smoke; clear it with `Remove-Item Env:SITE_BASE` afterwards.

## GitHub Pages setup

The [Pages workflow](.github/workflows/pages.yml) builds on pushes to `site-source` and deploys from that branch only.

A repository owner must select **Settings → Pages → Build and deployment → Source → GitHub Actions** and ensure the `github-pages` environment permits deployments from `site-source`. Then inspect the workflow's `deploy` job and the returned Pages URL. The expected URL is `https://doctor-cato.github.io/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN/`; it is not live until that job and URL are verified.

The source code license is [Apache-2.0](LICENSE). Datasets (`AIT-NDS-v2` and `CTU-SME-11` under `CC BY 4.0`, evaluation-only `UWF-ZeekData24`, and isolated `AIT-LDS-v2.1` under `CC BY-NC-SA 4.0`) follow their publishers' separate reuse terms; no raw dataset bytes or `.joblib` model binaries are shipped here.
