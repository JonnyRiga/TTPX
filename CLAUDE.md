# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Primary Codebase: ttpx.py

The only actively developed Python codebase here is `ttpx.py` — a single-file CLI tool (~1100 lines). Everything else is standalone shell scripts or third-party binaries.

## Tests

```bash
cd ~/Tools && python -m pytest tests/test_ttpx.py -v         # all 118 tests
cd ~/Tools && python -m pytest tests/test_ttpx.py::test_name -v  # single test
```

Tests live in `tests/test_ttpx.py`. All Claude API calls are mocked via `unittest.mock.patch`.

## Architecture of ttpx.py

**Data flow for the main modes:**

| Flag | Flow |
|------|------|
| `-f` | `find_matches()` → `display_find_results()` |
| `-p` | `find_matches()` → `ask_claude()` → `display_payload_result()` → `log_payload_result()` |
| `-m` | `mirror_file()` → `extract_section()` (optional) |
| `--csrf` | `parse_raw_request()` → `generate_csrf_poc()` → `detect_csrf_tokens()` → optionally `ask_claude_csrf_bypass()` → `display_csrf_poc()` |
| `--script` | reads file → `ask_claude_script()` → `display_script_result()` → `log_script_result()` |

**Key module-level constants:**

```python
HACKTRICKS_PATH = Path.home() / "Tools" / "hacktricks"
PATT_PATH       = Path.home() / "Tools" / "payloadsallthethings"
LOG_PATH        = Path.home() / "Tools" / "ttpx-session.log"
MAX_PAYLOAD_MATCHES = 10
SCRIPT_LANG_MAP = {".sh": "bash", ".py": "python", ".ps1": "powershell", ".rb": "ruby", ".pl": "perl"}
```

**Three Claude API functions** (all use `claude-sonnet-4-6`, import `anthropic` locally):
- `ask_claude(matches, terms, details)` — payload generation, `max_tokens=2048`, returns JSON dict
- `ask_claude_csrf_bypass(parsed, tokens)` — CSRF bypass analysis, `max_tokens=1024`, returns JSON dict
- `ask_claude_script(script_content, filename, details)` — script analysis + weaponization, `max_tokens=8192`, returns JSON dict

All three functions: expect Claude to return raw JSON (no markdown fences), parse with `json.loads()`, handle `json.JSONDecodeError` and `anthropic.APIError` gracefully by returning a structured error dict.

**`find_matches(terms, search_paths=None)`** — greps both knowledge bases for files containing all terms (AND logic). Returns list of `(Path, snippet_str)` tuples, capped at `MAX_PAYLOAD_MATCHES`. `search_paths` defaults to `[HACKTRICKS_PATH, PATT_PATH]`.

**`extract_snippet(lines, terms, context=40)`** — finds the best heading in a markdown file for the given terms and returns ~40 lines of context from that section.

**`parse_raw_request(file_path)`** — parses a raw HTTP request file (Burp/Caido format) into a dict with keys: `method`, `path`, `host`, `scheme`, `headers`, `body`, `content_type`. The scheme is inferred from the port (443 → https, else http).

**`generate_csrf_poc(parsed)`** — offline, returns HTML string. PoC type selected by Content-Type: form-urlencoded → `<form>`, JSON → `fetch()`, multipart → `FormData`, GET → `<form method="GET">`.

**`_content_root(base_path)`** — resolves the actual markdown root within a knowledge base (e.g., skips into a `src/` subdirectory if present). Used by `list_categories()` and `mirror_file()`.

## Adding a New Claude-backed Mode

Pattern used by all three existing modes:
1. Add an `ask_claude_*()` function that builds a structured prompt, calls `client.messages.create()`, strips and `json.loads()` the response, returns a dict (with error fallback).
2. Add a `display_*()` function using `rich` (Console, Table, Syntax) for terminal output.
3. Add a `log_*()` function that appends to `LOG_PATH` with timestamp.
4. Wire up in `main()` under a new `argparse` argument group.
5. Guard the mode behind `if not os.environ.get("ANTHROPIC_API_KEY")` with a clear error message.

## Shell Scripts

The `.sh` files are standalone — no shared library, no imports. Each is self-contained. `privy.sh` / `privyctf.sh` and `mscanz.sh` are the most complex; the rest are simple wrappers.
