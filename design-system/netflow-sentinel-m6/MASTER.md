# NetFlow Sentinel M6 — Desktop Design System (`MASTER.md`)

Applied via `ui-ux-pro-max` + `frontend-design` for Windows x64 Tauri 2 + Svelte 5 Desktop UI.

## 1. Visual Direction & Layout Discipline
- **Domain:** Offline Network Intrusion Detection & Scientific Traceability Workbench (`UNSW-NB15-v3`, `47 ML Features`).
- **Tone:** High-clarity engineering instrumentation panel — dense data readability, deterministic status attribution, zero neon noise or unverified mock gauges.
- **Spacing & Typography:**
  - UI Sans: `'Fira Sans', 'Segoe UI', system-ui, -apple-system, sans-serif`
  - Monospace / Numeric / IPs / SHA-256: `'Fira Code', 'Cascadia Code', 'Consolas', monospace` with `font-variant-numeric: tabular-nums`.
  - Grid rhythm: `4px` base unit (`12px` card padding, `16px` section gap, `24px` outer shell margin).
- **Offline Requirement:** Fonts load gracefully from installed Windows system stack or local CSS without blocking on external CDNs.

## 2. Theme Tokens (Light & Dark WCAG AA >= 4.5:1)
| Token | Light Mode | Dark Mode | Semantics |
|---|---|---|---|
| `--bg-canvas` | `#F8FAFC` | `#090E1A` | Application viewport backdrop |
| `--bg-surface` | `#FFFFFF` | `#111827` | Cards, panels, tables |
| `--bg-elevated` | `#EFF4FB` | `#1E293B` | Table headers, segmented tabs, hover rows |
| `--border-subtle` | `#CBD5E1` | `#334155` | Hairline container borders |
| `--text-primary` | `#0F172A` | `#F1F5F9` | Primary headings & tabular cells |
| `--text-secondary` | `#475569` | `#94A3B8` | Metadata labels, provenance digests |
| `--accent-primary` | `#1E40AF` | `#3B82F6` | Primary actions, active tab underline, focus ring |
| `--semantic-benign` | `#15803D` | `#22C55E` | Benign classification & READY badges |
| `--semantic-attack` | `#DC2626` | `#EF4444` | Attack classification & CRITICAL tier |
| `--semantic-warning` | `#B45309` | `#F59E0B` | OOD drift, RESEARCH_ONLY, ABSTAINED_OOD |
| `--semantic-blocked` | `#64748B` | `#94A3B8` | BLOCKED / NOT READY unverified artifacts |

## 3. Accessibility & Scientific Semantics Rules
1. **No Emoji Icons:** Use crisp inline Lucide-style SVG icons (`stroke-width="1.75"`, `aria-hidden="true"`).
2. **Double-Encoded Statuses:** Every `Benign`, `Attack`, `READY`, `BLOCKED`, and `ABSTAINED_OOD` indicator pairs distinct color with explicit text label + icon shape.
3. **Model Score Honesty:**
   - Supervised probabilistic (`Random Forest`): renders calibrated probability (`0.0% – 100.0%`) in column `Xác suất Attack`.
   - Unsupervised anomaly detector (`Isolation Forest`): renders unclamped `raw_anomaly_score` alongside frozen `decision_threshold` and displays `N/A (Unsupervised)` in probability slot.
   - Blocked models (`XGBoost`, `Autoencoder`): disabled selector card + `BLOCKED / NOT READY` badge + exact missing artifact reason.
4. **Reduced Motion & Focus:** Respect `@media (prefers-reduced-motion: reduce)` and render high-contrast `:focus-visible` `2px` outlines across keyboard navigation.
