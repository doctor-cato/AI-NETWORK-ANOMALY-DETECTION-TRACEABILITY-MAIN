import json
import re
from collections import defaultdict, deque

with open("docs/v2_issues_audit.json", "r", encoding="utf-8") as f:
    issues = json.load(f)

# Build raw dependencies
raw_deps = {}
titles = {}
priorities = {}
milestones = {}

for num in range(76, 156):
    iss = issues[str(num)]
    titles[num] = iss["title"]
    prio = "P0" if any("priority:high" in lbl["name"] for lbl in iss.get("labels", [])) else "P1"
    priorities[num] = prio
    milestones[num] = iss.get("milestone", {}).get("title", "")

    body = iss.get("body", "")
    m = re.search(r"## 7\. Dependencies.*?\n(.*?)(?=\n## |\Z)", body, re.DOTALL)
    dep_text = m.group(1).strip() if m else ""

    # Special case: #155 declares dependency on #76-154, but user prompt clarifies:
    # "#155 khai báo phụ thuộc toàn bộ #76–154. Chuyển thành phạm vi tham chiếu để lập DAG, không phải dependency yêu cầu hoàn thành toàn bộ Issue trước."
    if num == 155:
        deps = []
    else:
        # Extract explicit issue references
        refs = [int(x) for x in re.findall(r"#(\d+)", dep_text)]
        # Filter refs to be in 76..154 or legacy
        deps = [x for x in refs if x != num]
    raw_deps[num] = deps

# In #155 body, DAG is formally declared as:
# M6.1: #76 -> #77 -> #78 -> #79 -> #80; #78 -> #81.
# M6.2: #82 -> #83 -> #84 -> #85; #79 -> #86 -> #88; #79 -> #87; #86/#87 -> #89, #90; #86/#87 -> #91 -> #92 -> #93. #93 phụ thuộc #85, #88, #89, #90, #91, #92.
# M6.3: #94 -> #95; #95 -> #96, #97; #94/#95 -> #98; #95/#98 -> #99; #94/#98 -> #100; #90/#93/#86 -> #101 -> #102 -> #103 -> #104; #94/#100 -> #105; #102/#99/#100 -> #106.
# M6.4: #79/#106 -> #107 -> #108 -> #109; #107/#104/#85/#90 -> #110 -> #111 -> #112 -> #113; #112/#111 -> #114; #111/#113 -> #115.
# M6.5: #81/#80 -> #116 -> #117 -> #118; #116/#117 -> #119 -> #120 -> #121 -> #122; #118/#120 -> #123; #117/#118/#119 -> #124; #121/#122/#123 -> #125; #117/#118/#120 -> #126.
# M6.6: #78/#79/#93 -> #127 -> #128 -> #131 -> #132 -> #133 -> #134; #127/#79 -> #129; #127/#89/#90 -> #130 -> #131; #134/#104/#111/#118 -> #135; #131/#133 -> #136; #127–#136 -> #137.
# M6.7: #106/#115/#118/#137 -> #138 -> #139 -> #140, #141, #142, #143, #144; #77/#94/#98/#104/#114/#125/#126 -> #145; #81/#117/#124/#127 -> #146; #126/#133/#134/#138 -> #147; #71/#73/#138/#139 -> #148 -> #149; #136/#137/#140–#143 -> #150; #78/#79/#93/#118/#137/#18 -> #151; #148/#150/#18 -> #152; #144/#145/#147/#19 -> #153; #138/#145–#150/#20 -> #154.

dag = {
    76: [],
    77: [76],
    78: [77],
    79: [78],
    80: [79],
    81: [78],
    82: [],
    83: [82],
    84: [83],
    85: [84],
    86: [79],
    87: [79],
    88: [86],
    89: [86, 87],
    90: [86, 87],
    91: [86, 87],
    92: [91],
    93: [85, 88, 89, 90, 91, 92],
    94: [],
    95: [94],
    96: [95],
    97: [95],
    98: [94, 95],
    99: [95, 98],
    100: [94, 98],
    101: [90, 93, 86],
    102: [101],
    103: [102],
    104: [103],
    105: [94, 100],
    106: [102, 99, 100],
    107: [79, 106],
    108: [107],
    109: [108],
    110: [107, 104, 85, 90],
    111: [110],
    112: [111],
    113: [112],
    114: [111, 112],
    115: [111, 113],
    116: [80, 81],
    117: [116],
    118: [117],
    119: [116, 117],
    120: [119],
    121: [120],
    122: [121],
    123: [118, 120],
    124: [117, 118, 119],
    125: [121, 122, 123],
    126: [117, 118, 120],
    127: [78, 79, 93],
    128: [127],
    129: [127, 79],
    130: [127, 89, 90],
    131: [128, 130],
    132: [131],
    133: [132],
    134: [133],
    135: [134, 104, 111, 118],
    136: [131, 133],
    # User prompt notes for #137:
    # "#137 yêu cầu nghiệm thu trên giao diện, trong khi #138, #139 và #140 có dependency khiến UI có thể chờ #137. Tách điều kiện backend-ready, UI-ready và full E2E acceptance để loại bỏ bế tắc mà không giảm Acceptance Criteria."
    # 137 backend-ready depends on 127..136. UI verification happens when UI is available.
    137: [127, 128, 129, 130, 131, 132, 133, 134, 135, 136],
    138: [106, 115, 118, 136],  # backend integration, unblocks early UI
    139: [138],
    140: [139],
    141: [139],
    142: [139],
    143: [139],
    144: [139],
    145: [77, 94, 98, 104, 114, 125, 126, 96],  # added 96 as required by user prompt
    146: [81, 117, 124, 127],
    147: [126, 133, 134, 138],
    # User prompt note: "#149 tham chiếu G11 (#145), trong khi G11 là #148."
    148: [71, 73, 138, 139],
    149: [148],  # fixed G11 reference to #148
    150: [136, 137, 140, 141, 142, 143],
    151: [78, 79, 93, 118, 137, 18],
    152: [148, 150, 18],
    153: [144, 145, 147, 19],
    # User prompt note: "#154 phải bao phủ toàn bộ deliverables bàn giao, bao gồm #151–153."
    154: [138, 145, 146, 147, 148, 149, 150, 151, 152, 153, 20],
    155: [76],  # Can start immediately with 76
}

# Verify DAG has no cycles and compute topological sort
in_degree = defaultdict(int)
adj = defaultdict(list)
legacy_nodes = {18, 19, 20, 25, 48, 60, 71, 73}
all_nodes = set(dag.keys())

for u in all_nodes:
    for v in dag[u]:
        if v in all_nodes:
            adj[v].append(u)
            in_degree[u] += 1
        elif v in legacy_nodes:
            # v is a legacy baseline dependency, already satisfied or tracked externally
            pass


q = deque([u for u in all_nodes if in_degree[u] == 0])
topo_order = []
while q:
    u = q.popleft()
    topo_order.append(u)
    for v in adj[u]:
        in_degree[v] -= 1
        if in_degree[v] == 0:
            q.append(v)

print(f"Total nodes in DAG: {len(all_nodes)}")
print(f"Topological sort visited: {len(topo_order)}")
if len(topo_order) == len(all_nodes):
    print("SUCCESS: DAG has NO cycles!")
else:
    print("CYCLE DETECTED in nodes:", all_nodes - set(topo_order))

# Calculate effective priority: if a P1 issue is a dependency of a P0 issue, its effective priority is P0 (Critical path)
effective_prio = dict(priorities)
# Reverse DFS from each P0
for p0_node in [n for n in all_nodes if priorities.get(n) == "P0"]:
    stack = [p0_node]
    visited = set()
    while stack:
        curr = stack.pop()
        for dep in dag.get(curr, []):
            if dep in all_nodes and dep not in visited:
                visited.add(dep)
                if effective_prio.get(dep) == "P1":
                    effective_prio[dep] = "P0 (Elevated - Blocks P0)"
                stack.append(dep)

# Compute longest path (critical path) in DAG
dist = {u: 1 for u in all_nodes}
prev = {u: None for u in all_nodes}

for u in topo_order:
    for v in adj[u]:
        if dist[u] + 1 > dist[v]:
            dist[v] = dist[u] + 1
            prev[v] = u

max_end = max(all_nodes, key=lambda x: dist[x])
path = []
curr = max_end
while curr is not None:
    path.append(curr)
    curr = prev[curr]
path.reverse()

print(f"Longest Critical Path length: {len(path)} steps")
print(" -> ".join(f"#{x}" for x in path))
