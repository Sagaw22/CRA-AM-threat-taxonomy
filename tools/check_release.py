#!/usr/bin/env python3
"""Consistency checks for an AMTT release. Usage: python3 tools/check_release.py <repo root>"""
import csv, os, re, sys

root = sys.argv[1] if len(sys.argv) > 1 else "."
MD = os.path.join(root, "3.0-additive-manufacturing-merged-threat-taxonomy.md")
DATA = os.path.join(root, "taxonomy-data", "amtt-3.0", "3.0-R1")
ANN = os.path.join(DATA, "annotations")
LABELS = ["Direct", "Conditional", "Partial", "Mostly outside CRA"]
errors, warnings = [], []

text = open(MD, encoding="utf-8").read()
lines = text.split("\n")

# 1. nodes in Sections 1 to 3
nodes = {}
head = re.compile(r"^(#{3,4}) (\d(?:\.\d){1,2}) (.+?) `\[([CIA, ]+)\]`$")
for i, line in enumerate(lines):
    m = head.match(line)
    if not m:
        continue
    meta = lines[i + 2]
    mm = re.match(r"^\*\*ID:\*\* `(AMTT-[A-Z]+-\d{3})` \| \*\*CRA strength:\*\* (.+?) \| \*\*Derivation:\*\* (\w+)", meta)
    if not mm:
        errors.append("node %s has no ID line" % m.group(2))
        continue
    if not lines[i + 3].startswith("**Source trace:**"):
        errors.append("node %s has no source trace" % m.group(2))
    nodes[m.group(2)] = {"id": mm.group(1), "strength": mm.group(2), "title": m.group(3)}
expected = {"G": 5, "TF": 5, "T": 24, "MF": 9, "M": 29}
for key, n in expected.items():
    got = sum(1 for v in nodes.values() if v["id"].startswith("AMTT-%s-" % key))
    if got != n:
        errors.append("expected %d %s nodes, found %d" % (n, key, got))
if len({v["id"] for v in nodes.values()}) != len(nodes):
    errors.append("duplicate node IDs")

# 2. strength vocabulary and family rule
for code, v in nodes.items():
    if v["strength"] not in LABELS:
        errors.append("node %s has unknown strength %r" % (code, v["strength"]))
for code, v in nodes.items():
    if code[0] in "23" and code.count(".") == 1:
        kids = {nodes[c]["strength"] for c in nodes if c.startswith(code + ".")}
        want = kids.pop() if len(kids) == 1 else "Conditional"
        if v["strength"] != want:
            errors.append("family %s is %s but its leaves imply %s" % (code, v["strength"], want))

# 3. every node has exactly one crosswalk row with the same strength
rows = {}
for line in lines:
    m = re.match(r"^\| \*{0,2}(\d(?:\.\d){1,2}) .+? \| \*\*(.+?)\*\* \|", line)
    if m:
        rows.setdefault(m.group(1), []).append(m.group(2))
for code, v in nodes.items():
    if len(rows.get(code, [])) != 1:
        errors.append("node %s has %d crosswalk rows" % (code, len(rows.get(code, []))))
    elif rows[code][0] != v["strength"]:
        errors.append("node %s: heading says %s, crosswalk says %s" % (code, v["strength"], rows[code][0]))

# 4. every method leaf has a mitigation block, identifiers are well formed
for code in nodes:
    if code.startswith("3.") and code.count(".") == 2:
        start = text.index("#### %s " % code)
        nxt = re.search(r"\n#{2,4} ", text[start + 5:])
        block = text[start: start + 5 + (nxt.start() if nxt else len(text))]
        if "**Primary:**" not in block or "**Residual coverage:**" not in block:
            errors.append("method %s has no complete mitigation block" % code)
for bad in set(re.findall(r"\bM\d{2,3}\b|\bM\d{5,}\b", text)):
    errors.append("malformed ATT&CK identifier %s" % bad)

# 5. relative links resolve
for target in set(re.findall(r"\]\((?!https?://|#)([^)]+)\)", text)):
    if not os.path.exists(os.path.join(root, target)):
        errors.append("link target missing: %s" % target)
for name in re.findall(r"^\| `([\w./-]+\.csv)` \|", text, flags=re.M):
    if not os.path.exists(os.path.join(DATA, name)):
        errors.append("file listed in Section C.1 is missing: %s" % name)

# 6. internal anchors resolve
def slug(h):
    return re.sub(r"[^a-z0-9 _-]", "", h.lower()).replace(" ", "-")
anchors = {slug(m.group(1)) for m in re.finditer(r"^#{1,4} (.+)$", text, flags=re.M)}
for a in set(re.findall(r"\]\(#([^)]+)\)", text)):
    if a not in anchors:
        errors.append("broken internal link #%s" % a)

# 7. annotation CSV agrees with the document
path = os.path.join(ANN, "node-annotations.csv")
if os.path.exists(path):
    for r in csv.DictReader(open(path, encoding="utf-8")):
        n = nodes.get(r["display_code"])
        if not n or n["id"] != r["node_id"] or n["strength"] != r["cra_strength"]:
            errors.append("node-annotations.csv disagrees with the document for %s" % r["display_code"])
else:
    errors.append("annotations/node-annotations.csv is missing")

# 8. IDs agree with nodes.csv, when present
path = os.path.join(DATA, "nodes.csv")
if os.path.exists(path):
    reg = open(path, encoding="utf-8").read()
    reg_ids = set(re.findall(r"AMTT-(?:G|TF|T|MF|M)-\d{3}", reg))
    doc_ids = {v["id"] for v in nodes.values()}
    for x in sorted(doc_ids - reg_ids):
        errors.append("ID in document but not in nodes.csv: %s" % x)
    for x in sorted(reg_ids - doc_ids):
        errors.append("ID in nodes.csv but not in document: %s" % x)
    rows_csv = list(csv.reader(open(path, encoding="utf-8")))
    for code, v in nodes.items():
        hit = [r for r in rows_csv if v["id"] in r]
        if hit and not any(code in cell.split() or cell == code for r in hit for cell in r):
            warnings.append("check that %s is display code %s in nodes.csv" % (v["id"], code))

# 9. no placeholders left
for f in ["3.0-additive-manufacturing-merged-threat-taxonomy.md", "README.md", "CITATION.cff"]:
    p = os.path.join(root, f)
    if os.path.exists(p) and "TODO(release)" in open(p, encoding="utf-8").read():
        errors.append("release placeholder left in %s" % f)
if not os.path.exists(os.path.join(root, "LICENSE")):
    errors.append("LICENSE file is missing")

for w in warnings:
    print("WARNING:", w)
for e in errors:
    print("ERROR:", e)
print("%d nodes checked, %d errors, %d warnings" % (len(nodes), len(errors), len(warnings)))
sys.exit(1 if errors else 0)
