#!/usr/bin/env python3
"""Version checks and release notes for the release workflow.

Usage:
  python3 -I tools/release_info.py check [TAG]   versions agree (and match TAG, e.g. v1.1.0)
  python3 -I tools/release_info.py notes         release notes of the current version

The version lives in the Makefile, globalConfig.json and package/app.manifest;
the release notes in package/README.txt, under "Release notes", one block per
version starting with a line holding just the version.
"""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        return f.read()


def versions():
    make = re.search(r"^VERSION \?= (\S+)$", _read("Makefile"), re.M)
    return {
        "Makefile": make.group(1) if make else None,
        "globalConfig.json": json.loads(_read("globalConfig.json"))["meta"]["version"],
        "package/app.manifest": json.loads(_read("package/app.manifest"))["info"]["id"]["version"],
    }


def notes(version):
    text = _read("package/README.txt").split("Release notes\n-------------\n", 1)
    if len(text) < 2:
        return None
    block = re.search(r"^{}\n(.*?)(?:\n\n|\Z)".format(re.escape(version)), text[1], re.S | re.M)
    return block.group(1).rstrip() if block else None


def main(argv):
    found = versions()
    version = found["Makefile"]
    if argv[:1] == ["check"]:
        problems = ["{} has {}".format(f, v) for f, v in found.items() if v != version]
        if len(argv) > 1 and argv[1] != "v" + str(version):
            problems.append("tag {} does not match version {}".format(argv[1], version))
        if not notes(version):
            problems.append("package/README.txt has no release notes for {}".format(version))
        if problems:
            print("Version check failed: " + "; ".join(problems), file=sys.stderr)
            return 1
        print(version)
        return 0
    if argv[:1] == ["notes"]:
        print(notes(version) or "")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
