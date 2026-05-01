#!/usr/bin/env python3
import argparse
import json
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax
from rich import box
from rich.rule import Rule
from rich.text import Text

console = Console()

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
        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start != -1 and end > start:
            raw = raw[start:end]
        return json.loads(raw)
    except json.JSONDecodeError:
        return {
            "vulnerability": "Unknown",
            "technique": "Claude returned malformed JSON",
            "language": "text",
            "payload": raw,
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


LANGUAGE_LABELS = {
    "javascript": "JavaScript",
    "php": "PHP",
    "groovy": "Groovy",
    "bash": "Bash",
    "python": "Python",
    "java": "Java",
    "text": "Text",
}


def display_payload_result(data, sources):
    lang = data.get("language", "text")
    label = LANGUAGE_LABELS.get(lang, lang.capitalize())

    console.print()
    console.rule(f"[bold red]{data['vulnerability']}[/bold red]")
    console.print(f"[bold]Technique:[/bold] {data['technique']}\n")
    console.print(f"[bold cyan]Payload[/bold cyan] [dim]({label})[/dim]")
    console.print(Syntax(data["payload"], lang, theme="monokai", line_numbers=False, padding=(1, 2)))
    console.print()
    console.print(Text("★ " + data["recommendation"], style="bold yellow"))
    console.print()
    source_str = "  ".join(sources)
    console.print(f"[dim]Source: {source_str}[/dim]")
    console.rule()


def display_find_results(matches):
    if not matches:
        console.print("[yellow]No results found.[/yellow]")
        return

    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan")
    table.add_column("Source", style="green", no_wrap=True, min_width=16)
    table.add_column("Title", style="white", min_width=30)
    table.add_column("Path", style="dim")

    for path, snippet in matches:
        label = source_label(path)
        lines = path.read_text(errors="ignore").splitlines()
        title = extract_title(lines, [], fallback=path)
        base = HACKTRICKS_PATH if HACKTRICKS_PATH in path.parents else PATT_PATH
        rel = str(path.relative_to(base))
        table.add_row(label, title, rel)

    console.print(table)
    console.print(f"[dim]{len(matches)} result(s)[/dim]")


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
