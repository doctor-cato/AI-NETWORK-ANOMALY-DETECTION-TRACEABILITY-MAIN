"""Check that portal source links and published v2.0 dataset counts match repository evidence."""

import json
import os
import re
from pathlib import Path

website = Path(__file__).resolve().parents[1]
root = Path(os.environ.get("EVIDENCE_ROOT", website / "repository-evidence")).resolve()
content = [*website.glob("src/**/*.astro"), *website.glob("src/**/*.mdx")]
linked_paths = set()
for file in content:
    text = file.read_text(encoding="utf-8")
    linked_paths.update(re.findall(r"source\(\s*['\"]([^'\"]+)['\"]", text))
    linked_paths.update(
        re.findall(
            r"https://github\.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN/blob/(?:main|[0-9a-f]{40})/([^\s)<>]+)",
            text,
        )
    )

missing = sorted(path for path in linked_paths if not (root / path).is_file())
if missing:
    raise SystemExit(f"Missing repository evidence: {missing}")

manifest = json.loads(
    (root / "data/V2_SPLIT_MANIFEST.json").read_text(encoding="utf-8")
)
assert manifest["schema_version"] == 2
assert manifest["feature_contract_version"] == "canonical-flow-v2-18"

dataset_page = (website / "src/pages/dataset.astro").read_text(encoding="utf-8")
partitions = manifest["partitions"]
total_rows = manifest["total_labeled_rows"]
excluded_unmapped = manifest["excluded_unmapped_rows"]
total_benign = sum(p["benign_count"] for p in partitions.values())
total_attack = sum(p["attack_count"] for p in partitions.values())

for count in (total_rows, total_benign, total_attack, excluded_unmapped):
    assert f"{count:,}" in dataset_page, f"Count {count:,} absent from dataset page"

category_totals: dict[str, int] = {}
for p in partitions.values():
    for category, count in p["categories"].items():
        if category != "Benign":
            category_totals[category] = category_totals.get(category, 0) + count

for category, count in category_totals.items():
    pair = rf'\[\s*["\']{re.escape(category)}["\']\s*,\s*["\']{count:,}["\']\s*\]'
    assert re.search(
        pair, dataset_page
    ), f"{category} count {count:,} does not match manifest"

results_page = (website / "src/pages/results.astro").read_text(encoding="utf-8")
for partition in ("train", "validation", "test"):
    count = partitions[partition]["row_count"]
    assert (
        f"{count:,}" in results_page
    ), f"{partition} count {count:,} absent from results page"

ctu = manifest["ctu_sme_11_external"]
for subset in ("ctu_echo", "ctu_windows7ad"):
    count = ctu[subset]["labeled_rows"]
    assert (
        f"{count:,}" in results_page
    ), f"{subset} count {count:,} absent from results page"

print(
    f"PASS: {len(linked_paths)} repository source links and verified v2.0 dataset distribution"
)
