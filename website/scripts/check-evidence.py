"""Check that portal source links and published dataset counts match repository evidence."""

import json
import re
from pathlib import Path

root = Path(__file__).resolve().parents[2]
website = root / "website"
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

manifest = json.loads((root / "data/NF_UNSW_NB15_V3_MANIFEST.json").read_text(encoding="utf-8"))
dataset_page = (website / "src/pages/dataset.astro").read_text(encoding="utf-8")
distribution = manifest["verified_distribution"]
for label, count in distribution["Label"].items():
    assert f"{count:,}" in dataset_page, f"Label {label} count absent from dataset page"
for category, count in distribution["Attack"].items():
    if category != "Benign":
        pair = rf'\[\s*["\']{re.escape(category)}["\']\s*,\s*["\']{count:,}["\']\s*\]'
        assert re.search(pair, dataset_page), f"{category} count does not match manifest"
assert manifest["schema"]["column_count"] == 55
split = json.loads(
    (root / "reports/splits/nf_unsw_nb15_v3_split_manifest.json").read_text(encoding="utf-8")
)
results_page = (website / "src/pages/results.astro").read_text(encoding="utf-8")
for partition in ("train", "validation", "test", "purged_train_val_gap", "purged_val_test_gap"):
    assert (
        f'{split["partitions"][partition]["row_count"]:,}' in results_page
    ), f"{partition} count absent from results page"
print(f"PASS: {len(linked_paths)} repository source links and verified dataset distribution")
