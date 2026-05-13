# Changelog

All notable changes to ttpx are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

---

## [2026-05-13] — Rename: hacktrix → ttpx

### Changed
- Tool renamed from `hacktrix` to `ttpx` (Tactics, Techniques, Procedures + x).
- `hacktrix.py` → `ttpx.py`, `hacktrix.1` → `ttpx.1`, `test_hacktrix.py` → `test_ttpx.py`.
- Symlink updated: `/usr/local/bin/ttpx → ~/Tools/ttpx.py`.
- Session log renamed: `hacktrix-session.log` → `ttpx-session.log`.
- `htm` / `htx` shell aliases replaced with `ttm='ttpx -m'`.

---

## [2026-05-13] — CSRF PoC HTML5 boilerplate

### Fixed
- Generated `csrf_poc.html` now includes proper HTML5 boilerplate: `<!DOCTYPE html>`,
  `lang="en"`, and a `<head>` with UTF-8 charset, viewport meta, and
  `<title>CSRF PoC</title>`. Previously the output was a bare `<html><body>` skeleton.
  Output now matches Caido's PoC generator format.
- Shared boilerplate extracted to `_HTML_OPEN` / `_HTML_CLOSE` module-level constants
  to keep all four PoC branches (GET, JSON, multipart, form-urlencoded) DRY.

### Tests
- Added `test_generate_csrf_poc_html5_boilerplate` to assert DOCTYPE, lang, charset,
  viewport, and title are present in generated output (103 tests total).

---

## [2026-05-13] — Doc accuracy pass

### Fixed
- README and man page: framework/header coverage list now accurate — added Ant Design,
  listed all five headers explicitly (`X-CSRF-Token`, `X-XSRF-Token`, `X-CSRFToken`,
  `X-Request-Token`, `X-Ant-CSRF-Token`), removed overstated Laravel-specificity claim.
- README and man page: heuristic fallback now documented — detection fires on
  form-encoded bodies even when `Content-Type` is absent, as long as `=` is in the body.
- README and man page: known detection limits now documented — nested JSON, multipart
  fields, and cookie-based tokens are not detected; a clean warning does not guarantee
  no CSRF protection.
- README and man page: `--bypass` cost estimate corrected from ~100 to ~200–400 tokens
  output ($0.001–$0.002 per call).

---

## [2026-05-13] — --bypass optimisation

### Changed
- `--bypass` now feeds the offline token detection results directly into the
  Claude prompt instead of asking Claude to re-detect them. Claude skips
  detection entirely and focuses on bypass strategy.
- Conditional prompting based on offline findings:
  - Token present → prompt focuses on token stripping/prediction, leakage via
    CORS/XSS, Content-Type manipulation, and method override tricks.
  - No token → prompt focuses on SameSite enforcement, Origin/Referer validation,
    Content-Type restrictions, and whether the offline PoC is already sufficient.
    Includes a caveat that cookie-based tokens were not checked.
- `csrf_token_present` and `token_field` removed from Claude's JSON response
  schema — already known from offline detection, no longer needed in the output.
- `--bypass` hint ("Use --bypass for Claude's analysis") suppressed when bypass
  analysis is already being shown alongside the token warning.

---

## [2026-05-13] — CSRF token detection

### Added
- Offline CSRF token detection in `--csrf`: after generating the PoC, ttpx
  checks the request for known CSRF token field names (form-encoded and JSON bodies)
  and headers, and warns immediately if any are found — no API call required.
  Covers common frameworks: Django (`csrfmiddlewaretoken`), Rails (`authenticity_token`),
  ASP.NET (`__RequestVerificationToken`), Laravel (`_token`), WordPress (`_wpnonce`),
  and standard headers (`X-CSRF-Token`, `X-XSRF-Token`, etc.).
  Warning includes the field/header name, location, and a hint to use `--bypass`.

### Fixed
- `token` and `nonce` removed from the token field list — too generic, produced
  false positives on OAuth bearer token fields and payment nonce fields.
- `X-Requested-With` removed from the token header list — it is a same-origin hint,
  not a secret CSRF token; flagging it as one was misleading.
- Single-field form body (`csrf_token=abc` with no `&`) was silently missed when
  the `Content-Type` header was absent. Fixed by dropping the `&` requirement from
  the heuristic.

---

## [2026-05-13] — CSRF PoC generation

### Added
- `--csrf FILE` flag: parse a raw HTTP request file (Burp/Caido format) and generate a
  self-contained `csrf_poc.html` offline — no API call required.
  PoC type selected automatically by Content-Type:
  - `application/x-www-form-urlencoded` → auto-submitting `<form>` with hidden inputs
  - `application/json` → `fetch()` with `credentials: include` and CORS note
  - `multipart/form-data` → `FormData` fetch skeleton (fields filled manually)
  - GET → `<img>` tag for zero-click delivery
- `--bypass` flag: use with `--csrf` to call Claude for bypass analysis — CSRF token
  detection, Content-Type attack suggestions, and up to four bypass variants with
  PoC adaptation notes. Requires `ANTHROPIC_API_KEY`.
- Man page, README, and `-h` updated with new flags, PoC type table, and cost note.

### Fixed (security)
- **`</script>` injection via JSON body** — `json.dumps` does not escape `/`; a JSON
  body containing `</script>` in a string value would break out of the inline
  `<script>` block. Fixed by replacing `</` → `<\/` on the serialised body.
- **`</script>` injection via URL** — `_js_escape` was missing `/` → `\/`, allowing a
  crafted URL to close the script block. Fixed.
- **Unquoted JS expression from invalid-JSON fallback** — when the body failed JSON
  parse, the raw value was embedded as a bare JS expression inside `JSON.stringify()`,
  making arbitrary body content executable on PoC load. Fixed by wrapping in quotes
  and applying `_js_escape`.
- **`}});` syntax error in fetch PoC** — the JSON and multipart templates closed the
  `fetch()` options object with `}});` (two literal `}` chars from a plain string)
  instead of `});`, producing a `SyntaxError` that prevented the PoC from executing.
- **HTML injection in form PoC** — field names, values, `action`, and `method`
  attributes were interpolated unsanitised. Fixed with `html.escape(..., quote=True)`
  throughout.

### Fixed (correctness)
- Scheme detection: non-standard ports (`:8080`, `:3000`, etc.) now correctly produce
  `http://` URLs. Previously any host without `:80` was assumed HTTPS, silently
  breaking PoCs against plain-HTTP targets.

---

## [2026-05-04] — Prompt hardening and token visibility

### Added
- Token usage and estimated cost printed after every `-p` call (input tokens,
  output tokens, USD estimate at Sonnet 4.6 rates).
- Expanded language support for syntax highlighting: added Groovy, Java, Perl, Ruby,
  XML, and Text to the pygments lexer allowlist.

### Changed
- Claude system prompt hardened: `<script>` tags preferred over event handler
  attributes for XSS/CSRF payloads (attribute-embedded JS breaks double-quote
  quoting); relative URLs enforced; no trailing fetch after a successful POST.
- Display tightened: rule lines, copy-paste block, and source footer made
  consistent.

### Fixed
- Two recurring payload generation issues corrected in the prompt.
- `<script>` tag instruction added to prevent broken payloads from attribute
  parsing interference.

---

## [2026-05-02] — UX overhaul and HackTricks GitBook fix

### Added
- **Smarter snippet extraction**: section-aware scoring selects the most relevant
  heading block rather than the first keyword match.
- **Result cap** (`MAX_PAYLOAD_MATCHES = 10`): more than 10 matches triggers a
  warning and caps the Claude context to keep costs predictable.
- **Session log**: every `-p` call appends a timestamped entry (terms, vulnerability,
  first payload line) to `~/Tools/ttpx-session.log`. Suppress with `--no-log`.
- **Multi-pass `-d`**: repeat `--details` / `-d` to chain multiple error contexts
  across attempts; prompt distinguishes singular vs plural correctly.
- **Source header in mirrored files**: `-m` output includes a `# Source:` line with
  origin path and mirror date.
- **File count column** in `-l` table.
- **`--since Nd`** for `-l`: filter category list to directories updated in the last N
  days.

### Fixed
- HackTricks GitBook restructure: content moved to `src/` subdirectory. `_content_root`
  helper detects the layout and `_recently_changed_dirs` strips the `src/` prefix when
  building category names.

---

## [2026-05-01] — Mirror, section extraction, rich display, and dual-source support

### Added
- `-m` / `--mirror` flag (`htm` alias): copy a knowledge base file to cwd as plain
  text with markdown stripped.
- `-s` / `--section TERM`: use with `-m` to extract only the section whose heading
  matches the term, stopping at the next heading of equal or higher level.
- `-d` / `--details CONTEXT`: feed back error output or context from a previous `-p`
  attempt; Claude analyses the failure and adds a **What changed** section to the
  response.
- Rich terminal output for both `-f` (table with source tag, title, path) and `-p`
  (syntax-highlighted payload, copy-paste block, recommendation, source footer).
- Language-aware rendering: Claude returns a pygments lexer name; the payload is
  highlighted accordingly.
- Man page (`ttpx.1`), detailed `--help` epilog, and README.
- PayloadsAllTheThings (PATT) as a second search source alongside HackTricks.
- `source_label()` helper: short `[hacktricks]` / `[payloadsallthethings]` tags used
  in output and Claude context (avoids leaking absolute paths to the API).

### Changed
- CLI refactored from positional args to `-f` / `--find` and `-p` / `--payload`
  mutually-exclusive flags.

### Fixed
- `extract_title` now searches the full file for a term-matching heading rather than
  stopping at the first match.
- Rich markup in source labels escaped to prevent rendering artefacts.
- `ask_claude` guarded against malformed API responses and JSON fence stripping.
- `strip_markdown` preserves `__dunder__` names and glob patterns (`*.php`).
- `mirror_file` path containment check prevents directory traversal.

---

## [2026-04-30] — Initial release

### Added
- `find_matches()`: grep HackTricks for files containing all search terms
  (AND-match, case-insensitive, recursive).
- `extract_snippet()`: pull the most relevant section from a matched file.
- `ask_claude()`: send matched content to Claude API, receive a structured JSON
  payload response (vulnerability, technique, language, payload, recommendation).
- `ttpx -f TERM [TERM ...]`: search and display results.
- `ttpx -p TERM [TERM ...]`: search then generate a payload via Claude.
  Requires `ANTHROPIC_API_KEY`.
- `ttpx -l`: list top-level categories in both sources.
- `ttpx -u`: `git pull` both knowledge bases and print a change summary.
- Symlink to `/usr/local/bin/ttpx` for system-wide access.
