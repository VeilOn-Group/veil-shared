#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""MPL-2.0 notices (Exhibit A) in every veil-shared source file (ADR-0075).

  tools/license/mpl_headers.py --check   # CI: fail on a file without it
  tools/license/mpl_headers.py --fix     # add it where missing

Files without comment syntax (JSON, images, the binary rule set) are covered
by LICENSE and NOTICE.md; third-party files listed in NOTICE.md keep their
own licenses and are skipped.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LINES = [
    "This Source Code Form is subject to the terms of the Mozilla Public",
    "License, v. 2.0. If a copy of the MPL was not distributed with this",
    "file, You can obtain one at https://mozilla.org/MPL/2.0/.",
]
STYLE = {
    ".go": ("// ", None), ".proto": ("// ", None), ".kt": ("// ", None),
    ".py": ("# ", "#!"), ".sh": ("# ", "#!"), ".yaml": ("# ", None), ".yml": ("# ", None),
    ".css": ("css", None), ".svg": ("xml", "<?xml"), ".xml": ("xml", "<?xml"),
}
SKIP_DIRS = {".git", "node_modules", ".cache", "testdata"}
# Third-party content, not relicensed (NOTICE.md).
SKIP_FILES = {"assets/rulesets/geosite-category-ru.srs", "assets/rulesets/SOURCE.md"}


def notice(style):
    if style == "css":
        return "/* " + LINES[0] + "\n * " + LINES[1] + "\n * " + LINES[2] + " */\n"
    if style == "xml":
        return "<!-- " + LINES[0] + "\n   - " + LINES[1] + "\n   - " + LINES[2] + " -->\n"
    return "".join(style + l + "\n" for l in LINES)


def files():
    for d, dirs, fs in os.walk(ROOT):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in fs:
            p = os.path.join(d, f)
            rel = os.path.relpath(p, ROOT)
            ext = os.path.splitext(f)[1]
            if ext in STYLE and rel not in SKIP_FILES:
                yield p, rel, STYLE[ext]


def main():
    fix = "--fix" in sys.argv
    missing = []
    for p, rel, (style, first) in files():
        s = open(p, encoding="utf-8").read()
        if LINES[0] in s[:600]:
            continue
        if not fix:
            missing.append(rel)
            continue
        n = notice(style)
        if first and s.startswith(first):
            head, _, rest = s.partition("\n")
            if first == "<?xml" and "?>" not in head:
                head, rest = s.split("?>", 1)[0] + "?>", s.split("?>", 1)[1].lstrip("\n")
            s = head + "\n" + n + rest
        else:
            # Go: a blank line keeps the notice out of the package comment.
            s = n + ("\n" if style == "// " else "") + s
        open(p, "w", encoding="utf-8").write(s)
    if missing:
        print("missing MPL-2.0 notice:\n  " + "\n  ".join(missing))
        sys.exit(1)
    print("mpl headers: OK")


main()
