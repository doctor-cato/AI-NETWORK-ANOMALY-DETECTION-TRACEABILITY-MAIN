"""Read-only workflow contract validation; Python stdlib only."""

import re
from pathlib import Path


def validate(root):
    errors = []
    skill = root / ".agents/skills/repo-workflow/SKILL.md"
    agents_path = root / "AGENTS.md"
    traceability_path = root / "docs/TRACEABILITY_MATRIX.md"
    paths = {agents_path, traceability_path, root / ".agents/README.md",
             root / ".agents/skills/README.md", skill}
    paths.update(root / f".agents/workflows/{stage}.md"
                 for stage in ("plan", "implement", "verify", "review"))
    paths.update((root / ".agents").rglob("*.md"))
    required_skills = {
        "repo-workflow", "network-intrusion-detection", "unsw-nb15-protocol",
        "ml-experiment-audit", "model-experiment",
    }
    names = set()
    for manifest in (root / ".agents/skills").glob("*/SKILL.md"):
        text = manifest.read_text(encoding="utf-8-sig")
        match = re.match(r"\A---\r?\n(.*?)\r?\n---(?:\r?\n|$)", text, re.S)
        if not match:
            errors.append(f"Invalid front matter: {manifest.relative_to(root)}")
            continue
        fields = {}
        for line in match[1].splitlines():
            key, separator, value = line.partition(":")
            if not separator or key in fields:
                errors.append(f"Invalid/duplicate metadata line: {manifest.relative_to(root)}")
            fields[key] = value.strip().strip('\"').strip("'")
        name = fields.get("name", "")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) or len(name) > 64:
            errors.append(f"Invalid name: {manifest.relative_to(root)}")
        if name != manifest.parent.name or name in names:
            errors.append(f"Mismatched/duplicate skill name: {name}")
        names.add(name)
        if not 1 <= len(fields.get("description", "")) <= 1024:
            errors.append(f"Missing/oversized description: {manifest.relative_to(root)}")
    for missing in sorted(required_skills - names):
        errors.append(f"Missing required skill: {missing}")
    for path in sorted(paths):
        if not path.is_file():
            errors.append(f"Missing file: {path.relative_to(root)}")
            continue
        text = path.read_text(encoding="utf-8-sig")
        for target in re.findall(r"(?<!!)\[[^\]]+\]\(([^)]+)\)", text):
            if target.startswith(("https://", "http://", "#")):
                continue
            resolved = (path.parent / target.split("#", 1)[0]).resolve()
            if not resolved.is_relative_to(root.resolve()) or not resolved.exists():
                errors.append(f"Broken/escaping link: {path.relative_to(root)} -> {target}")
    verify = root / ".agents/workflows/verify.md"
    if verify.is_file():
        content = verify.read_text(encoding="utf-8-sig")
        for status in ("PASS", "FAIL", "SKIPPED", "NOT VERIFIED"):
            if f"`{status}`" not in content:
                errors.append(f"Missing verification status: {status}")
    if agents_path.is_file():
        agents = agents_path.read_text(encoding="utf-8-sig")
        for name in sorted(required_skills):
            if name not in agents:
                errors.append(f"AGENTS.md does not route skill: {name}")
    if traceability_path.is_file():
        traceability = traceability_path.read_text(encoding="utf-8-sig")
        for state in ("PLANNED", "IMPLEMENTED", "TESTED", "EXPERIMENTALLY VALIDATED"):
            if f"`{state}`" not in traceability:
                errors.append(f"Missing traceability state: {state}")
    return errors


if __name__ == "__main__":
    failures = validate(Path(__file__).resolve().parents[4])
    for failure in failures:
        print(f"FAIL: {failure}")
    if not failures:
        print("PASS: workflow files, skill metadata, local links and verification statuses")
        print("NOT VERIFIED: runtime discovery, agent behavior, remote CI and external links")
    raise SystemExit(bool(failures))
