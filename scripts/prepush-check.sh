#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "[1/3] Validating manifest.json"
python3 -m json.tool manifest.json >/dev/null

echo "[2/3] Syntax checking extension JavaScript files"
for file in background-guards.js background.js content.js i18n.js mascot-bubbles.js options.js popup.js utils.js; do
  node --check "$file" >/dev/null
done

echo "[3/3] Scanning for obvious hardcoded secrets"
if command -v rg >/dev/null 2>&1; then
  if rg -n -i "(api[_-]?key\\s*[:=]\\s*['\\\"][A-Za-z0-9_\\-]{16,}['\\\"]|x-apikey\\s*[:=]\\s*['\\\"][A-Za-z0-9_\\-]{16,}['\\\"])" . --glob "*.js" --glob "*.json" --glob "*.md" > /tmp/pixelpaw_secret_hits.txt; then
    echo "Potential hardcoded secrets detected:"
    cat /tmp/pixelpaw_secret_hits.txt
    exit 1
  fi
else
  python3 - <<'PY'
import pathlib, re, sys
pattern = re.compile(r"(api[_-]?key\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]|x-apikey\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"])", re.IGNORECASE)
hits = []
for ext in (".js", ".json", ".md"):
    for path in pathlib.Path(".").rglob(f"*{ext}"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for line_no, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                hits.append(f"{path}:{line_no}:{line.strip()}")
if hits:
    print("Potential hardcoded secrets detected:")
    print("\n".join(hits))
    sys.exit(1)
PY
fi

echo "Pre-push checks passed."
