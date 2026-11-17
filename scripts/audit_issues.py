import json
import sys

with open("docs/v2_issues_audit.json", "r", encoding="utf-8") as f:
    issues = json.load(f)

def print_issue(num):
    iss = issues.get(str(num))
    if not iss:
        print(f"Issue #{num} not found")
        return
    print("=" * 60)
    print(f"ISSUE #{num}: {iss['title']}")
    print(f"Labels: {[l['name'] for l in iss.get('labels', [])]}")
    print(f"Milestone: {iss.get('milestone', {}).get('title') if iss.get('milestone') else None}")
    print("-" * 60)
    body = iss.get("body", "")
    lines = body.splitlines()
    in_section = False
    for line in lines:
        if line.startswith("## "):
            sec = line.strip()
            if any(k in sec.lower() for k in ["mục tiêu", "expected deliverables", "acceptance criteria", "dependencies", "thiết kế"]):
                in_section = True
                print(f"\n{line}")
            else:
                in_section = False
        elif in_section:
            print(line)
    print("\n")

if __name__ == "__main__":
    ids = [int(x) for x in sys.argv[1:]] if len(sys.argv) > 1 else [76, 77, 78, 79, 80, 81, 155]
    for i in ids:
        print_issue(i)

