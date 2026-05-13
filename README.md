# Hacktrix

Search [HackTricks](https://github.com/HackTricks-wiki/hacktricks) and [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) for exploitation techniques, get AI-generated payloads, and generate CSRF PoCs from raw captured requests — all free, offline-first, and from the CLI.

## Why this exists

Hacktrix brings together features that normally require multiple paid tools into a single free CLI workflow.

The closest comparison overall is SearchSploit — same offline-first, terminal-based feel — but SearchSploit only indexes Exploit-DB CVEs. Hacktrix goes further by searching local HackTricks/PATT knowledge bases and supporting AI-assisted payload generation.

Its CSRF PoC generator also replaces functionality usually locked behind paid platforms like Burp Suite Pro or Caido. Unlike those GUI-only tools, Hacktrix is free, CLI-based, and supports all major request types (form, JSON, multipart, and GET), along with HTML injection prevention, offline token detection, and optional AI-powered bypass analysis.

The only cost is if the user chooses to connect a Claude API key for AI payload generation — everything else works fully offline and free out of the box.

## Install

```bash
git clone https://github.com/JonnyRiga/hacktrix ~/Tools/hacktrix-repo
# tool lives at ~/Tools/hacktrix.py, symlinked to /usr/local/bin/hacktrix
```

**Dependencies:**

```bash
pip install anthropic rich
```

**Knowledge bases** (clone once, search forever):

```bash
git clone https://github.com/HackTricks-wiki/hacktricks ~/Tools/hacktricks
git clone https://github.com/swisskyrepo/PayloadsAllTheThings ~/Tools/payloadsallthethings
```

**API key** (required for `-p` and `--bypass` only):

```bash
echo 'export ANTHROPIC_API_KEY="sk-ant-..."' >> ~/.zshrc && source ~/.zshrc
```

---

## Usage

```
hacktrix -l [--since Nd]
hacktrix -u
hacktrix -f TERM [TERM ...]
hacktrix -p TERM [TERM ...] [-d CONTEXT [-d CONTEXT ...]] [--no-log]
hacktrix -m PATH [-s TERM]
hacktrix --csrf FILE [--bypass]
```

### `-l` / `--list` — browse categories (no terms needed)

List every top-level directory in both sources. Use this when you don't yet know what to search for. Add `--since Nd` to filter to categories updated in the last N days — useful right after `-u`.

```bash
hacktrix -l
hacktrix -l --since 7d     # categories with commits in the last 7 days
```

```
  [hacktricks]                         [payloadsallthethings]
  ──────────────────────── ──────       ─────────────────────────── ──────
  Network Services            12        Command Injection                 8
  Pentesting Web              47        File Inclusion                   11
  Reversing                    5        Server Side Template Injection    9
  ...                                  SQL Injection                    14
47 categories                          31 categories
```

### `-u` / `--update` — pull latest (keep payloads current)

Run `git pull` on both knowledge bases and show what changed. Run this before an engagement.

```bash
hacktrix -u
```

```
Updating HackTricks...
HackTricks: updated  12 files changed, 340 insertions(+), 18 deletions(-)
Updating PayloadsAllTheThings...
PayloadsAllTheThings: already up to date
```

### `-f` / `--find` — browse (no Claude, no cost)

Search both sources and display a clean table. Use this to see what content exists before generating a payload or grabbing a file.

```bash
hacktrix -f ssti handlebars
hacktrix -f lfi php windows
hacktrix -f sqli union mysql
```

```
Searching HackTricks + PayloadsAllTheThings...

  Source                   Title                        Path
 ─────────────────────────────────────────────────────────────────────
  [hacktricks]             SSTI (Server Side Template   src/pentesting-web/...
  [payloadsallthethings]   Handlebars                   Server Side Template...

2 result(s)
```

### `-p` / `--payload` — generate payload (Claude)

Search both sources, send the findings to Claude, get the single most impactful payload — syntax-highlighted by language with a recommendation.

```bash
hacktrix -p ssti handlebars groovy rce
hacktrix -p sqli union mysql
hacktrix -p xss csp bypass reflected
hacktrix -p lfi php windows iis read
hacktrix -p log4shell jndi rce java
```

```
Searching HackTricks + PayloadsAllTheThings...
Sending findings to Claude...

──────────────── SSTI via Handlebars (Node.js) ────────────────
Technique: Handlebars allows access to the JS prototype chain...

Payload (JavaScript)

  {{#with "s" as |string|}}
    {{#with "e"}}
      {{#with split as |conslist|}}
        ...
      {{/with}}
    {{/with}}
  {{/with}}

── copy-paste ──
{{#with "s" as |string|}}
  ...
{{/with}}

★ Most impactful: gives direct RCE via constructor chain traversal.

Source: [hacktricks] src/pentesting-web/ssti/README.md
```

The syntax-highlighted block is for reading; the `── copy-paste ──` block below it is the raw payload with no terminal formatting — safe to select and paste directly.

### `-d` / `--details` — adapt after a failed attempt

Feed back an error or context from a previous `-p` attempt. Claude analyses the failure, produces a corrected payload, and adds a **What changed** section showing exactly which tokens or lines were modified from the previous attempt. Repeat `-d` to chain multiple error contexts across attempts.

```bash
hacktrix -p ssti handlebars groovy rce -d "'require' is not defined"
hacktrix -p sqli union mysql -d "WAF blocking SELECT and UNION keywords"
hacktrix -p lfi php -d "../etc/passwd filtered, got 403" -d "double-encoded also blocked"
```

### `--no-log` — skip session logging

Every `-p` call appends a timestamped entry (terms, vulnerability, first payload line) to `~/Tools/hacktrix-session.log`. Pass `--no-log` to suppress it for a specific call.

```bash
hacktrix -p xss reflected --no-log
```

### `-m` / `--mirror` — grab a file to cwd

Copy a file from a `-f` result to the current directory as plain text with markdown stripped. Path must match the `-f` output exactly — quote paths with spaces.

```bash
hacktrix -m "Server Side Template Injection/JavaScript.md"          # full file
hacktrix -m "Server Side Template Injection/JavaScript.md" -s handlebars  # section only
```

Use `-s` / `--section` to extract just the section whose heading matches the term, stopping at the next heading of equal or higher level. Falls back to the full file if the section isn't found.

```bash
hacktrix -m "File Inclusion/README.md" -s lfi
hacktrix -m "SQL Injection/README.md" -s mysql
```

### `--csrf` — generate CSRF PoC (offline)

Parse a raw HTTP request file (copied from Burp Suite or Caido) and generate a self-contained `csrf_poc.html` in the current directory. No API call. PoC type is selected automatically by Content-Type:

| Request | PoC |
|---|---|
| GET | `<img src="...">` zero-click tag |
| POST `application/x-www-form-urlencoded` | Auto-submitting `<form>` with hidden inputs |
| POST `application/json` | `fetch()` with `credentials: include` + CORS note |
| POST `multipart/form-data` | `FormData` fetch skeleton (fill fields manually) |

```bash
hacktrix --csrf req.txt             # generate csrf_poc.html
hacktrix --csrf req.txt --bypass    # PoC + Claude bypass analysis
```

`req.txt` is the raw request as copied from Burp/Caido — request line, headers, blank line, body.

After generating the PoC, hacktrix automatically checks the request for known CSRF token fields and headers (form-encoded body, JSON body, and request headers) and warns if any are found — no API call required. Covers common frameworks including Django, Rails, ASP.NET, Laravel, WordPress, and Ant Design, plus several common headers (`X-CSRF-Token`, `X-XSRF-Token`, `X-CSRFToken`, `X-Request-Token`, `X-Ant-CSRF-Token`). The heuristic also fires on form-encoded bodies when the `Content-Type` header is absent, as long as `=` is present in the body.

> **Detection limits:** Tokens in nested JSON objects, multipart fields, and cookies are not detected. A clean warning does not guarantee the endpoint has no CSRF protection.

`--bypass` calls Claude (requires `ANTHROPIC_API_KEY`) and adds a bypass analysis section. The offline token detection results are fed directly into the prompt so Claude skips re-detection and goes straight to strategy:

- **Token found** → focuses on token stripping/prediction, leakage via CORS/XSS, Content-Type manipulation, method override
- **No token found** → focuses on SameSite enforcement, Origin/Referer validation, Content-Type restrictions, and whether the offline PoC is already sufficient

Use `--bypass` when the offline PoC fails and you want Claude's read on what's blocking it.

---

## Workflow

```bash
# 0. Keep sources current before an engagement
hacktrix -u

# 1. Don't know what to search? Browse categories first
hacktrix -l

# 2. See what content exists
hacktrix -f ssti handlebars

# 3. Grab the relevant section to read offline
hacktrix -m "Server Side Template Injection/JavaScript.md" -s handlebars

# 4. Generate a payload
hacktrix -p ssti handlebars groovy rce

# 5. Hit an error? Feed it back
hacktrix -p ssti handlebars groovy rce -d "sandbox active, require not available"
```

More specific terms = fewer matched files = more focused payload + lower API cost.
If `-p` returns no results, drop a term.

---

## Cost

Each `-p` call costs roughly **$0.001–$0.005** (claude-sonnet-4-6, ~200–500 tokens output). `--csrf --bypass` costs roughly **$0.001–$0.002** (~200–400 tokens output). `-f`, `-m`, and `--csrf` (without `--bypass`) are free.

---

## Man page

```bash
man ~/Tools/hacktrix.1
```

---

## Tests

```bash
cd ~/Tools && python -m pytest tests/test_hacktrix.py -v
```
