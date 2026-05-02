#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import sys
from datetime import date, datetime
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.syntax import Syntax
from rich import box
from rich.text import Text

console = Console()

HACKTRICKS_PATH = Path.home() / "Tools" / "hacktricks"
PATT_PATH = Path.home() / "Tools" / "payloadsallthethings"
LOG_PATH = Path.home() / "Tools" / "hacktrix-session.log"
MAX_PAYLOAD_MATCHES = 10


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


def extract_snippet(lines, terms, context=40):
    if not terms:
        return "\n".join(lines[:context])

    headings = [i for i, line in enumerate(lines) if line.startswith("#")]

    if not headings:
        match_idx = _find_match_idx(lines, terms)
        if match_idx is None:
            return "\n".join(lines[:context])
        start = max(0, match_idx - 2)
        return "\n".join(lines[start:start + context])

    best_start = headings[0]
    best_score = -1

    for idx, h_start in enumerate(headings):
        h_end = headings[idx + 1] if idx + 1 < len(headings) else len(lines)
        section_text = "\n".join(lines[h_start:h_end]).lower()
        heading_text = lines[h_start].lower()

        # Terms present anywhere in section
        score = sum(3 for term in terms if term.lower() in section_text)
        # Bonus for terms appearing in the heading itself
        score += sum(2 for term in terms if term.lower() in heading_text)

        if score > best_score:
            best_score = score
            best_start = h_start

    end_idx = min(best_start + context, len(lines))
    return "\n".join(lines[best_start:end_idx])


_TITLE_MAX_LEN = 45


def extract_title(lines, terms, fallback: "Path | None" = None):
    # Prefer a heading line that itself contains a term (most specific match)
    if terms:
        for line in lines:
            if line.startswith("#") and any(term.lower() in line.lower() for term in terms):
                title = line.lstrip("#").strip()
                if len(title) > _TITLE_MAX_LEN:
                    title = title[:_TITLE_MAX_LEN - 3] + "..."
                return title

    # Fall back to nearest heading above first text match
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


def ask_claude(matches, terms, details=None):
    import anthropic
    client = anthropic.Anthropic()

    context = "\n\n---\n\n".join(
        f"Source: {source_label(path)}\n\n{snippet}" for path, snippet in matches
    )

    if details:
        combined = "\n\n---\n\n".join(details)
        label = "Previous attempts produced" if len(details) > 1 else "A previous attempt produced"
        task = (
            f"{label} the following result(s):\n\n"
            f"{combined}\n\n"
            "Analyse the error(s), adapt your approach, and provide a corrected payload."
        )
    else:
        task = "Select the single most impactful payload for these terms."

    changes_field = (
        '  "changes": bullet list of the specific tokens or lines changed from the previous attempt\n'
        if details else
        '  "changes": ""\n'
    )

    prompt = (
        f"You are a penetration tester. Based on these HackTricks and PayloadsAllTheThings "
        f"sections about {' '.join(terms)}:\n\n"
        f"{context}\n\n"
        f"{task} "
        "Return ONLY a JSON object with these exact keys:\n"
        '  "vulnerability": short name of the vulnerability and target (e.g. "SSTI via Handlebars (Node.js)")\n'
        '  "technique": one sentence on how the exploit works\n'
        '  "language": the payload language as a pygments lexer name — one of: javascript, php, groovy, bash, python, java, text\n'
        '  "payload": the raw payload string, properly indented and line-broken as it would appear in a code editor; no markdown fences\n'
        + changes_field +
        '  "recommendation": one sentence explaining why this payload is the most impactful choice\n'
        "No markdown. No explanation outside the JSON object."
    )

    raw = ""
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
    except (IndexError, AttributeError) as e:
        return {
            "vulnerability": "Parse Error",
            "technique": f"Unexpected API response structure: {e}",
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
    console.print("[dim]── copy-paste ──[/dim]")
    console.print(escape(data["payload"]), soft_wrap=True)
    console.print()

    changes = data.get("changes", "")
    if changes:
        console.print("[bold magenta]What changed[/bold magenta]")
        console.print(changes)
        console.print()

    console.print(Text("★ " + data["recommendation"], style="bold yellow"))
    console.print()
    source_str = "  ".join(sources)
    console.print(f"[dim]Source: {escape(source_str)}[/dim]")
    console.rule()


def update_sources():
    sources = [
        ("HackTricks", HACKTRICKS_PATH),
        ("PayloadsAllTheThings", PATT_PATH),
    ]
    any_found = False
    for label, path in sources:
        if not path.exists():
            console.print(f"[yellow]{label} not found — skipping.[/yellow]")
            continue
        any_found = True
        console.print(f"[dim]Updating {label}...[/dim]")
        result = subprocess.run(
            ["git", "-C", str(path), "pull", "--ff-only"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            console.print(f"[red]{label} update failed:[/red] {result.stderr.strip()}")
            continue
        output = result.stdout.strip()
        if "up to date" in output.lower() or "up-to-date" in output.lower():
            console.print(f"[green]{label}:[/green] already up to date")
        else:
            stat = subprocess.run(
                ["git", "-C", str(path), "diff", "--stat", "HEAD@{1}", "HEAD"],
                capture_output=True, text=True
            )
            stat_line = stat.stdout.strip().splitlines()[-1] if stat.stdout.strip() else ""
            if stat_line:
                console.print(f"[green]{label}:[/green] updated  [dim]{stat_line}[/dim]")
            else:
                console.print(f"[green]{label}:[/green] updated")
    if not any_found:
        console.print(
            "[red]No sources found. Clone:[/red]\n"
            "  git clone https://github.com/HackTricks-wiki/hacktricks ~/Tools/hacktricks\n"
            "  git clone https://github.com/swisskyrepo/PayloadsAllTheThings ~/Tools/payloadsallthethings"
        )
        sys.exit(1)


def _recently_changed_dirs(base_path: Path, days: int) -> set:
    result = subprocess.run(
        ["git", "-C", str(base_path), "log",
         f"--since={days} days ago", "--name-only", "--pretty=format:", "--", "*.md"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return set()
    dirs = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if line:
            parts = Path(line).parts
            if parts:
                dirs.add(parts[0])
    return dirs


def list_categories(since_days=None):
    sources = [
        (HACKTRICKS_PATH, "hacktricks"),
        (PATT_PATH, "payloadsallthethings"),
    ]
    any_found = False
    for path, name in sources:
        if not path.exists():
            continue
        any_found = True
        all_dirs = sorted(
            d.name for d in path.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        )
        if since_days is not None:
            recent = _recently_changed_dirs(path, since_days)
            dirs = [d for d in all_dirs if d in recent]
            footer = f"[dim]{len(dirs)} of {len(all_dirs)} categories (last {since_days}d)[/dim]"
        else:
            dirs = all_dirs
            footer = f"[dim]{len(dirs)} categories[/dim]"

        table = Table(
            box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan",
            title=f"\\[{name}]", title_style="bold green"
        )
        table.add_column("Category", style="white")
        table.add_column("Files", style="dim", justify="right")
        for d in dirs:
            file_count = sum(1 for _ in (path / d).rglob("*.md"))
            table.add_row(d, str(file_count))
        console.print(table)
        console.print(footer)
    if not any_found:
        console.print(
            "[red]No sources found. Clone:[/red]\n"
            "  git clone https://github.com/HackTricks-wiki/hacktricks ~/Tools/hacktricks\n"
            "  git clone https://github.com/swisskyrepo/PayloadsAllTheThings ~/Tools/payloadsallthethings"
        )
        sys.exit(1)


def display_find_results(matches, terms):
    if not matches:
        console.print("[yellow]No results found.[/yellow]")
        return

    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold cyan")
    table.add_column("Source", style="green", no_wrap=True, min_width=14)
    table.add_column("Title", style="white", min_width=30)
    table.add_column("Path", style="dim")

    for path, snippet in matches:
        title = extract_title(path.read_text(errors="ignore").splitlines(), terms, fallback=path)
        for base in [HACKTRICKS_PATH, PATT_PATH]:
            if path.is_relative_to(base):
                src = f"\\[{base.name}]"
                rel = str(path.relative_to(base))
                break
        else:
            src = "\\[unknown]"
            rel = str(path)
        table.add_row(src, title, rel)

    console.print(table)
    console.print(f"[dim]{len(matches)} result(s)[/dim]")


def strip_markdown(text):
    # code fences — keep content, drop fence lines
    text = re.sub(r"```[^\n]*\n", "", text)
    text = re.sub(r"```", "", text)
    # images — must run before links to avoid leaving a bare '!' artifact
    text = re.sub(r"!\[[^\]]*\]\([^\)]+\)", "", text)
    # links — keep display text
    text = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", text)
    # headings — keep text, drop # symbols
    text = re.sub(r"^#{1,6}\s+", "", text, flags=re.MULTILINE)
    # bold/italic with asterisks only — skip underscore variants to preserve
    # __dunder__ names in Python payloads and shell glob patterns like *.php
    text = re.sub(r"(?<!\*)\*\*\*(?!\s)(.+?)(?<!\s)\*\*\*(?!\*)", r"\1", text)
    text = re.sub(r"(?<!\*)\*\*(?!\s)(.+?)(?<!\s)\*\*(?!\*)", r"\1", text)
    text = re.sub(r"(?<!\*)\*(?!\s)([^\*\n]+?)(?<!\s)\*(?!\*)", r"\1", text)
    # strikethrough
    text = re.sub(r"~~(.+?)~~", r"\1", text)
    # inline code — keep content
    text = re.sub(r"`(.+?)`", r"\1", text)
    # blockquotes
    text = re.sub(r"^>\s?", "", text, flags=re.MULTILINE)
    # horizontal rules
    text = re.sub(r"^[-*_]{3,}\s*$", "", text, flags=re.MULTILINE)
    # collapse 3+ blank lines to 2
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def extract_section(text, section_term):
    lines = text.splitlines()
    start = None
    heading_level = None

    for i, line in enumerate(lines):
        if line.startswith("#") and section_term.lower() in line.lower():
            start = i
            heading_level = len(line) - len(line.lstrip("#"))
            break

    if start is None:
        return None

    end = len(lines)
    for i in range(start + 1, len(lines)):
        if lines[i].startswith("#"):
            level = len(lines[i]) - len(lines[i].lstrip("#"))
            if level <= heading_level:
                end = i
                break

    return "\n".join(lines[start:end]).strip()


def mirror_file(rel_path, section=None):
    target = None
    for base in [HACKTRICKS_PATH, PATT_PATH]:
        candidate = base / rel_path
        try:
            candidate.resolve().relative_to(base.resolve())
        except ValueError:
            continue
        if candidate.exists():
            target = candidate
            break

    if target is None:
        console.print(f"[red]File not found in any source:[/red] {rel_path}")
        console.print("  Check the path matches a -f result exactly.")
        sys.exit(1)

    content = target.read_text(errors="ignore")

    for base in [HACKTRICKS_PATH, PATT_PATH]:
        if target.is_relative_to(base):
            source_header = f"# Source: [{base.name}] {target.relative_to(base)}  (mirrored: {date.today()})\n\n"
            break
    else:
        source_header = f"# Source: {target}  (mirrored: {date.today()})\n\n"

    if section:
        raw_section = extract_section(content, section)
        if raw_section is None:
            console.print(f"[yellow]Section '{section}' not found — mirroring full file.[/yellow]")
            plain = strip_markdown(content)
        else:
            plain = strip_markdown(raw_section)
    else:
        plain = strip_markdown(content)

    out = Path.cwd() / (target.stem + ".txt")
    out.write_text(source_header + plain)
    console.print(f"[green]Mirrored:[/green] {out.name}  [dim]({len(plain.splitlines())} lines)[/dim]")


def log_payload_result(terms, data):
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M")
        first_line = (data.get("payload") or "").splitlines()[0] if data.get("payload") else ""
        entry = (
            f"[{ts}] {' '.join(terms)}\n"
            f"  {data.get('vulnerability', 'Unknown')}\n"
            f"  {first_line}\n\n"
        )
        with LOG_PATH.open("a") as f:
            f.write(entry)
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(
        prog="hacktrix",
        description=(
            "Search HackTricks and PayloadsAllTheThings for exploitation techniques.\n\n"
            "Use -f to browse matching entries (fast, no API cost), then use -p with\n"
            "refined terms to generate a ready-to-use payload via Claude. Feed errors\n"
            "back with -d to get an adapted payload on the next attempt."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  hacktrix -l                                         # browse all categories\n"
            "  hacktrix -l --since 7d                              # categories updated in last 7 days\n"
            "  hacktrix -u                                         # update knowledge bases\n"
            "  hacktrix -f ssti handlebars\n"
            "  hacktrix -f lfi php windows\n"
            "  hacktrix -p ssti handlebars groovy rce\n"
            "  hacktrix -p sqli union mysql -d \"WAF blocking SELECT keyword\"\n"
            "  hacktrix -p lfi php -d \"../etc/passwd filtered, got 403\"\n"
            "  hacktrix -m \"Server Side Template Injection/JavaScript.md\"\n"
            "  hacktrix -m \"Server Side Template Injection/JavaScript.md\" -s handlebars\n\n"
            "sources:\n"
            "  HackTricks:           ~/Tools/hacktricks\n"
            "  PayloadsAllTheThings: ~/Tools/payloadsallthethings\n\n"
            "environment:\n"
            "  ANTHROPIC_API_KEY     required for -p / --payload"
        )
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--find", nargs="+", metavar="TERM",
                       help="search both sources and display a table of matching entries (no Claude, no API cost)")
    group.add_argument("-p", "--payload", nargs="+", metavar="TERM",
                       help="search both sources then send findings to Claude for a syntax-highlighted, ready-to-use payload")
    group.add_argument("-m", "--mirror", metavar="PATH",
                       help="copy a file from a -f result to cwd as plain text, stripping markdown. Optionally add a section term to extract only that section.")
    group.add_argument("-l", "--list", action="store_true",
                       help="list all top-level categories in both sources (browse blind, no search terms needed)")
    group.add_argument("-u", "--update", action="store_true",
                       help="git pull both knowledge bases and print a change summary")
    parser.add_argument("-d", "--details", metavar="CONTEXT", action="append",
                        help="error output or context from a previous -p attempt; repeat for multi-turn chaining")
    parser.add_argument("-s", "--section", metavar="TERM",
                        help="section term to extract when using -m (e.g. handlebars)")
    parser.add_argument("--since", metavar="N[d]",
                        help="use with -l: filter categories updated in the last N days (e.g. 7d or 7)")
    parser.add_argument("--no-log", dest="no_log", action="store_true",
                        help="skip auto-logging this -p result to ~/Tools/hacktrix-session.log")
    args = parser.parse_args()

    if args.since and not args.list:
        console.print("[yellow]Warning: --since has no effect without -l/--list[/yellow]")

    if args.update:
        update_sources()
        sys.exit(0)

    if args.list:
        since_days = None
        if args.since:
            m = re.match(r'^(\d+)[d]?$', args.since.strip())
            if m and int(m.group(1)) > 0:
                since_days = int(m.group(1))
            elif m:
                console.print("[yellow]Warning: --since value must be greater than 0 — ignoring.[/yellow]")
            else:
                console.print(f"[yellow]Warning: unrecognised --since format '{args.since}' — ignoring.[/yellow]")
        list_categories(since_days=since_days)
        sys.exit(0)

    if args.mirror:
        mirror_file(args.mirror, section=args.section)
        sys.exit(0)

    if args.details and args.find:
        console.print("[yellow]Warning: -d/--details has no effect with -f/--find[/yellow]")

    if args.section and not args.mirror:
        console.print("[yellow]Warning: -s/--section has no effect without -m/--mirror[/yellow]")

    if args.payload and not os.environ.get("ANTHROPIC_API_KEY"):
        console.print("[red]Set ANTHROPIC_API_KEY to use -p / --payload[/red]")
        sys.exit(1)

    terms = args.find or args.payload
    available = [p for p in [HACKTRICKS_PATH, PATT_PATH] if p.exists()]
    missing = [p for p in [HACKTRICKS_PATH, PATT_PATH] if not p.exists()]

    if not available:
        console.print(
            "[red]No sources found. Clone:[/red]\n"
            "  git clone https://github.com/HackTricks-wiki/hacktricks ~/Tools/hacktricks\n"
            "  git clone https://github.com/swisskyrepo/PayloadsAllTheThings ~/Tools/payloadsallthethings"
        )
        sys.exit(1)

    for p in missing:
        label = "HackTricks" if p == HACKTRICKS_PATH else "PayloadsAllTheThings"
        console.print(f"[yellow]Warning: {label} not found — skipping.[/yellow]")

    console.print("[dim]Searching HackTricks + PayloadsAllTheThings...[/dim]")
    matches = find_matches(terms, search_paths=available)

    if args.find:
        display_find_results(matches, terms)

    else:
        if not matches:
            console.print(f"[yellow]No results for: {' '.join(terms)}[/yellow]")
            sys.exit(0)
        if len(matches) > MAX_PAYLOAD_MATCHES:
            console.print(
                f"[yellow]Warning: {len(matches)} matches — capped at {MAX_PAYLOAD_MATCHES}. "
                f"Use more specific terms for a focused payload.[/yellow]"
            )
            matches = matches[:MAX_PAYLOAD_MATCHES]
        console.print("[dim]Sending findings to Claude...[/dim]")
        data = ask_claude(matches, terms, details=args.details)
        sources = list(dict.fromkeys(source_label(path) for path, _ in matches))
        display_payload_result(data, sources)
        if not args.no_log:
            log_payload_result(terms, data)


if __name__ == "__main__":
    main()
