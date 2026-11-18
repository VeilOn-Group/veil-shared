#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Replace em dashes (U+2014) with orthographically appropriate punctuation.

Policy (requested by the product owner, ADR-0058):
  * heading "A — B"                 -> "A: B"
  * table cell "—" (empty value)    -> "нет" (Cyrillic file) / "n/a"
  * numeric range "5—10"            -> en dash "5–10"
  * "A — B" when the sentence already has a colon before the dash
                                    -> "A (B)" up to the next , ; . or end
  * otherwise "A — B"               -> "A: B"
Run with --check to fail (exit 1) if any em dash remains (CI);
--root DIR checks another repository.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Other repositories run this copy on themselves: nodash.py --check --root .
if "--root" in sys.argv:
    ROOT = os.path.abspath(sys.argv[sys.argv.index("--root") + 1])
SKIP_DIRS = {"node_modules", "dist", ".git", "build", "testdata"}
EXT = {".md", ".go", ".ts", ".tsx", ".yaml", ".yml", ".py", ".proto", ".sql", ".kt", ".kts", ".xml", ".sh", ".json", ".html", ".css", ".txt"}
DASH = "\u2014"


def cyr(s):
    return re.search(r"[А-Яа-яЁё]", s) is not None


def fix_line(line, cyrillic_file):
    if DASH not in line:
        return line
    # numeric ranges
    line = re.sub(r"(\d)\s*" + DASH + r"\s*(\d)", "\\1\u2013\\2", line)
    # empty table cells
    line = re.sub(r"\|\s*" + DASH + r"\s*(?=\|)", "| " + ("нет" if cyrillic_file else "n/a") + " ", line)
    if DASH not in line:
        return line
    # headings
    if re.match(r"^\s*#", line) and not line.lstrip().startswith("#!"):
        head, _, rest = line.partition(" " + DASH + " ")
        sep = ". " if (":" in rest or re.search(r"ADR-[\d…]+$", head)) else ": "
        return head + sep + rest.replace(" " + DASH + " ", ", ").replace(DASH, ",")
    out = []
    i = 0
    while True:
        j = line.find(DASH, i)
        if j < 0:
            out.append(line[i:])
            break
        before = line[i:j]
        after = line[j + 1:]
        # clause of the ORIGINAL text that precedes this dash
        clause = re.split(r"[,;.!?|](?:\s|$)", line[:j])[-1]
        # Inside a string literal only the literal counts; keys such as
        # `text:` or `ru:` and URLs, times, code spans are not sentence colons.
        if '"' in clause:
            clause = clause.rsplit('"', 1)[1]
        clause = re.sub(r"^\s*[-\w.]+:\s", "", clause)
        clause = re.sub(r"\d:\d|https?:|`[^`]*`|\(([^)]*)\)|\*\*[^*]*\*\*", "", clause)
        b = before.rstrip()
        rest = after.lstrip()
        if re.match(r"(and|or|but|so|и|а|но|или|то есть)\b", rest):
            out.append(b.rstrip(",") + ", ")
            i = j + 1 + (len(after) - len(rest))
        elif ":" in clause:
            m = re.match(r"\s*(.+?)(?=[,;.!?](?:\s|$)|$)", after)
            inner = m.group(1).rstrip() if m else rest
            out.append(b + " (" + inner + ")")
            i = j + 1 + (m.end() if m else len(after))
        elif not b or b.endswith("|"):
            out.append(before)
            i = j + 1 + (len(after) - len(rest))
        else:
            out.append(b.rstrip(",") + ": ")
            i = j + 1 + (len(after) - len(rest))
    return "".join(out)


def files():
    for d, dirs, fs in os.walk(ROOT):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in fs:
            if os.path.splitext(f)[1] in EXT:
                yield os.path.join(d, f)


def main():
    check = "--check" in sys.argv
    bad = 0
    for p in files():
        if p.endswith(os.path.join("tools", "text", "nodash.py")):
            continue
        try:
            s = open(p, encoding="utf-8").read()
        except UnicodeDecodeError:
            continue
        if DASH not in s:
            continue
        if check:
            bad += s.count(DASH)
            print(f"{os.path.relpath(p, ROOT)}: {s.count(DASH)} em dash(es)")
            continue
        c = cyr(s)
        new = "\n".join(fix_line(l, c) for l in s.split("\n"))
        open(p, "w", encoding="utf-8").write(new)
    if check and bad:
        sys.exit(1)


if __name__ == "__main__":
    main()
