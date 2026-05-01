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


def extract_snippet(lines, terms, context=20):
    match_idx = None
    for i, line in enumerate(lines):
        if terms and any(term.lower() in line.lower() for term in terms):
            match_idx = i
            break

    if match_idx is None:
        return "\n".join(lines[:context])

    heading_idx = 0
    for i in range(match_idx, -1, -1):
        if lines[i].startswith("#"):
            heading_idx = i
            break

    end_idx = min(heading_idx + context, len(lines))
    return "\n".join(lines[heading_idx:end_idx])


def find_matches(terms, hacktricks_path=HACKTRICKS_PATH):
    if not hacktricks_path.exists():
        return []

    matches = []
    for md_file in hacktricks_path.rglob("*.md"):
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
    client = anthropic.Anthropic()

    context = "\n\n---\n\n".join(
        f"Source: {path}\n\n{snippet}" for path, snippet in matches
    )

    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=2048,
            messages=[{
                "role": "user",
                "content": (
                    f"Based on these HackTricks sections about {' '.join(terms)}:\n\n"
                    f"{context}\n\n"
                    "Provide:\n"
                    "1. Technique summary — what this vulnerability is and how it works\n"
                    "2. Ready-to-use payload or command to exploit it"
                )
            }]
        )
        return response.content[0].text
    except anthropic.APIError as e:
        return f"Claude API error: {e}"


def main():
    parser = argparse.ArgumentParser(
        prog="hacktrix",
        description="Search HackTricks for exploitation techniques"
    )
    parser.add_argument("terms", nargs="+", help="Search terms (all must match)")
    parser.add_argument("--exploit", action="store_true",
                        help="Generate exploit summary and payload via Claude")
    args = parser.parse_args()

    if args.exploit and not os.environ.get("ANTHROPIC_API_KEY"):
        print("Set ANTHROPIC_API_KEY to use --exploit")
        sys.exit(1)

    if not HACKTRICKS_PATH.exists():
        print(
            "HackTricks not found. Run: "
            "git clone https://github.com/HackTricks-wiki/hacktricks ~/Tools/hacktricks"
        )
        sys.exit(1)

    matches = find_matches(args.terms)

    if not matches:
        print(f"No results for: {' '.join(args.terms)}")
        sys.exit(0)

    print(f"Found {len(matches)} file(s)\n")
    for path, snippet in matches:
        print(f"\n{'=' * 60}")
        print(f"Source: {path.relative_to(HACKTRICKS_PATH)}")
        print(f"{'=' * 60}")
        print(snippet)

    if args.exploit:
        print(f"\n{'=' * 60}")
        print("Claude Exploit Analysis")
        print(f"{'=' * 60}")
        print(ask_claude(matches, args.terms))


if __name__ == "__main__":
    main()
