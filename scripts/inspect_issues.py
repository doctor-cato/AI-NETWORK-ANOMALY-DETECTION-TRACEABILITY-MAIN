import json
import sys

with open("docs/v2_issues_audit.json", "r", encoding="utf-8") as f:
    d = json.load(f)

start = int(sys.argv[1]) if len(sys.argv) > 1 else 82
end = int(sys.argv[2]) if len(sys.argv) > 2 else 93

for i in range(start, end + 1):
    it = d.get(str(i), {})
    print(f"=== #{i}: {it.get('title')} ===")
    print(f"Labels: {[lbl['name'] for lbl in it.get('labels', [])]}")
    body = it.get("body", "")
    for line in body.split("\n"):
        if (
            "acceptance criteria" in line.lower()
            or "- [ ]" in line
            or "- [x]" in line
            or "###" in line
        ):
            print(f"  {line}")
    print()
