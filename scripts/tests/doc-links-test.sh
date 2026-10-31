#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

# Check local Markdown link and image targets, including reference definitions.
# External URLs and fragments are not fetched or resolved.
python3 - "$repo_root" "$@" <<'PY'
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

root = Path(sys.argv[1])
if len(sys.argv) > 2:
    files = [Path(name) if Path(name).is_absolute() else root / name for name in sys.argv[2:]]
else:
    listed = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", "*.md"],
        cwd=root,
    )
    files = sorted({root / name.decode() for name in listed.split(b"\0") if name})

inline = re.compile(r"!?\[[^\]]*\]\(\s*(<[^>]+>|[^\s)]+)(?:\s+[^)]*)?\)")
reference = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*(<[^>]+>|\S+)")
failures = []
checked = 0
for source in files:
    fence = None
    for number, line in enumerate(source.read_text().splitlines(), 1):
        marker = re.match(r"^\s{0,3}(`{3,}|~{3,})", line)
        if marker:
            token = marker.group(1)
            if fence is None:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = None
            continue
        if fence is not None:
            continue
        targets = [match.group(1) for match in inline.finditer(line)]
        definition = reference.match(line)
        if definition:
            targets.append(definition.group(1))
        for raw in targets:
            target = urlsplit(raw.strip("<>"))
            if target.scheme or target.netloc or not target.path:
                continue
            path = unquote(target.path)
            destination = root / path.lstrip("/") if path.startswith("/") else source.parent / path
            checked += 1
            if not destination.exists():
                failures.append(f"{source.relative_to(root)}:{number}: missing target {path}")

if failures:
    print("\n".join(failures), file=sys.stderr)
    sys.exit(1)
print(f"Checked {checked} local link/image targets in {len(files)} Markdown files.")
PY
