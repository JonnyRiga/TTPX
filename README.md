# hacktrix

Search [HackTricks](https://github.com/HackTricks-wiki/hacktricks) and [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) for exploitation techniques. Get a clean searchsploit-style table with `-f`, or send the findings straight to Claude for a syntax-highlighted, ready-to-use payload with `-p`.

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

**API key** (required for `-p` only):

```bash
echo 'export ANTHROPIC_API_KEY="sk-ant-..."' >> ~/.zshrc && source ~/.zshrc
```

---

## Usage

```
hacktrix -f TERM [TERM ...]
hacktrix -p TERM [TERM ...] [-d CONTEXT]
```

### `-f` / `--find` — browse (no Claude, no cost)

Search both sources and display a clean table. Use this to see what content exists before generating a payload.

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
    ...
  {{/with}}

★ Most impactful: gives direct RCE via constructor chain traversal.

Source: [hacktricks] src/pentesting-web/ssti/README.md
```

### `-d` / `--details` — adapt after a failed attempt

Feed back an error or context from a previous `-p` attempt. Claude analyses the failure and produces a corrected payload.

```bash
hacktrix -p ssti handlebars groovy rce -d "'require' is not defined"
hacktrix -p sqli union mysql -d "WAF blocking SELECT and UNION keywords"
hacktrix -p lfi php -d "../etc/passwd filtered, server returned 403"
```

---

## Workflow

The intended pattern — find first, then payload:

```bash
# 1. See what content exists
hacktrix -f ssti handlebars

# 2. Refine terms based on what you see, generate payload
hacktrix -p ssti handlebars nodejs rce

# 3. Hit an error? Feed it back
hacktrix -p ssti handlebars nodejs rce -d "sandbox active, require not available"
```

More specific terms = fewer matched files = more focused payload + lower API cost.
If `-p` returns no results, drop a term.

---

## Cost

Each `-p` call costs roughly **$0.001–$0.005** (claude-sonnet-4-6, ~200–500 tokens output). `-f` is free.

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
