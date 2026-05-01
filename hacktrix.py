#!/usr/bin/env python3
import argparse
import os
import sys
from pathlib import Path

HACKTRICKS_PATH = Path.home() / "Tools" / "hacktricks"
PATT_PATH = Path.home() / "Tools" / "payloadsallthethings"


def source_label(path):
    for base in [HACKTRICKS_PATH, PATT_PATH]:
        if path.is_relative_to(base):
            return f"[{base.name}] {path.relative_to(base)}"
    return str(path)


def _find_match_idx(lines, terms):
    if not terms:
        return None
    for i, line in enumerate(lines):
        if any(term.lower() in line.lower() for term in terms):
            return i
    return None


def _find_heading_idx(lines, start):
    for i in range(start, -1, -1):
        if lines[i].startswith("#"):
            return i
    return 0


def extract_snippet(lines, terms, context=20):
    match_idx = _find_match_idx(lines, terms)

    if match_idx is None:
        return "\n".join(lines[:context])

    heading_idx = _find_heading_idx(lines, match_idx)
    end_idx = min(heading_idx + context, len(lines))
    return "\n".join(lines[heading_idx:end_idx])


_TITLE_MAX_LEN = 45


def extract_title(lines, terms, fallback: "Path | None" = None):
    match_idx = _find_match_idx(lines, terms)

    if match_idx is not None:
        heading_idx = _find_heading_idx(lines, match_idx)
        heading_line = lines[heading_idx]
        if heading_line.startswith("#"):
            title = heading_line.lstrip("#").strip()
            if len(title) > _TITLE_MAX_LEN:
                title = title[:_TITLE_MAX_LEN - 3] + "..."
            return title

    if fallback is not None:
        return fallback.name
    return "Unknown"


def find_matches(terms, search_paths=None):
    if search_paths is None:
        search_paths = [HACKTRICKS_PATH, PATT_PATH]
    matches = []
    for base_path in search_paths:
        if not base_path.exists():
            continue
        for md_file in base_path.rglob("*.md"):
            try:
                content = md_file.read_text(errors="ignore")
            except Exception:
                continue
            content_lower = content.lower()
            if all(term.lower() in content_lower for term in terms):
                snippet = extract_snippet(content.splitlines(), terms)
                matches.append((md_file, snippet))
    return matches


def ask_claude(matches, terms):
    import anthropic
    import json as _json
    client = anthropic.Anthropic()

    context = "\n\n---\n\n".join(
        f"Source: {source_label(path)}\n\n{snippet}" for path, snippet in matches
    )

    prompt = (
        f"You are a penetration tester. Based on these HackTricks and PayloadsAllTheThings "
        f"sections about {' '.join(terms)}:\n\n"
        f"{context}\n\n"
        "Select the single most impactful payload for these terms. "
        "Return ONLY a JSON object with these exact keys:\n"
        '  "vulnerability": short name of the vulnerability and target (e.g. "SSTI via Handlebars (Node.js)")\n'
        '  "technique": one sentence on how the exploit works\n'
        '  "language": the payload language as a pygments lexer name — one of: javascript, php, groovy, bash, python, java, text\n'
        '  "payload": the raw payload string, no markdown fences\n'
        '  "recommendation": one sentence explaining why this payload is the most impactful choice\n'
        "No markdown. No explanation outside the JSON object."
    )

    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = response.content[0].text.strip()
        if raw.startswith("```"):
            raw = "\n".join(raw.split("\n")[1:-1])
        return _json.loads(raw)
    except _json.JSONDecodeError:
        return {
            "vulnerability": "Unknown",
            "technique": "Claude returned malformed JSON",
            "language": "text",
            "payload": response.content[0].text,
            "recommendation": "Raw Claude output shown above."
        }
    except anthropic.APIError as e:
        return {
            "vulnerability": "API Error",
            "technique": str(e),
            "language": "text",
            "payload": "",
            "recommendation": ""
        }


def main():
    parser = argparse.ArgumentParser(
        prog="hacktrix",
        description="Search HackTricks and PayloadsAllTheThings for exploitation techniques"
    )
    parser.add_argument("terms", nargs="+", help="Search terms (all must match)")
    parser.add_argument("--exploit", action="store_true",
                        help="Generate exploit summary and payload via Claude")
    args = parser.parse_args()

    if args.exploit and not os.environ.get("ANTHROPIC_API_KEY"):
        print("Set ANTHROPIC_API_KEY to use --exploit")
        sys.exit(1)

    available = [p for p in [HACKTRICKS_PATH, PATT_PATH] if p.exists()]
    missing = [p for p in [HACKTRICKS_PATH, PATT_PATH] if not p.exists()]

    if not available:
        print(
            "No sources found. Clone:\n"
            "  git clone https://github.com/HackTricks-wiki/hacktricks ~/Tools/hacktricks\n"
            "  git clone https://github.com/swisskyrepo/PayloadsAllTheThings ~/Tools/payloadsallthethings"
        )
        sys.exit(1)

    for p in missing:
        if p == HACKTRICKS_PATH:
            print("Warning: HackTricks not found. Searching PayloadsAllTheThings only.")
        else:
            print("Warning: PayloadsAllTheThings not found. Searching HackTricks only.")

    matches = find_matches(args.terms, search_paths=available)

    if not matches:
        print(f"No results for: {' '.join(args.terms)}")
        sys.exit(0)

    print(f"Found {len(matches)} file(s)\n")
    for path, snippet in matches:
        print(f"\n{'=' * 60}")
        print(f"Source: {source_label(path)}")
        print(f"{'=' * 60}")
        print(snippet)

    if args.exploit:
        print(f"\n{'=' * 60}")
        print("Claude Exploit Analysis")
        print(f"{'=' * 60}")
        print(ask_claude(matches, args.terms))


if __name__ == "__main__":
    main()
