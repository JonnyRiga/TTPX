#!/usr/bin/env python3
import argparse
import os
import sys
from pathlib import Path

HACKTRICKS_PATH = Path.home() / "Tools" / "hacktricks"


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
            max_tokens=1024,
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
    pass


if __name__ == "__main__":
    main()
