# hacktrix PATT Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add PayloadsAllTheThings as a second search source so `hacktrix` searches both repos by default.

**Architecture:** Add `PATT_PATH` constant and `source_label()` helper to `hacktrix.py`, update `find_matches` to accept a `search_paths` list (defaulting to both repos), update `main()` to warn on missing sources and use the new label helper in output.

**Tech Stack:** Python 3 stdlib, pytest

---

### Task 1: PATT_PATH constant and source_label helper

**Files:**
- Modify: `~/Tools/hacktrix.py` — add constant + helper function
- Modify: `~/Tools/tests/test_hacktrix.py` — add tests

- [ ] **Step 1: Write failing tests for source_label**

First, update the existing import line at the top of `~/Tools/tests/test_hacktrix.py`. Find:

```python
from hacktrix import extract_snippet, find_matches, ask_claude
```

Replace with:

```python
from hacktrix import extract_snippet, find_matches, ask_claude, source_label, HACKTRICKS_PATH, PATT_PATH
```

Then append the new tests to the bottom of the file:

```python
def test_source_label_identifies_hacktricks_path():
    path = HACKTRICKS_PATH / "web" / "ssti.md"
    assert source_label(path) == "[hacktricks] web/ssti.md"


def test_source_label_identifies_patt_path():
    path = PATT_PATH / "SSTI" / "README.md"
    assert source_label(path) == "[payloadsallthethings] SSTI/README.md"


def test_source_label_falls_back_to_str_for_unknown_path():
    path = Path("/tmp/unknown.md")
    assert source_label(path) == "/tmp/unknown.md"
```

- [ ] **Step 2: Run to verify tests fail**

```bash
cd ~/Tools && python -m pytest tests/test_hacktrix.py::test_source_label_identifies_hacktricks_path tests/test_hacktrix.py::test_source_label_identifies_patt_path tests/test_hacktrix.py::test_source_label_falls_back_to_str_for_unknown_path -v
```

Expected: ImportError — `source_label` and `PATT_PATH` not defined

- [ ] **Step 3: Add PATT_PATH constant and source_label to hacktrix.py**

After the `HACKTRICKS_PATH` line (line 7), add:

```python
PATT_PATH = Path.home() / "Tools" / "payloadsallthethings"


def source_label(path):
    for base in [HACKTRICKS_PATH, PATT_PATH]:
        if path.is_relative_to(base):
            return f"[{base.name}] {path.relative_to(base)}"
    return str(path)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd ~/Tools && python -m pytest tests/test_hacktrix.py -v
```

Expected: all pass (12 existing + 3 new = 15)

- [ ] **Step 5: Commit**

```bash
cd ~/Tools && git add hacktrix.py tests/test_hacktrix.py
git commit -m "feat: add PATT_PATH constant and source_label helper"
```

---

### Task 2: Update find_matches to accept search_paths

**Files:**
- Modify: `~/Tools/hacktrix.py` — update `find_matches` signature and body
- Modify: `~/Tools/tests/test_hacktrix.py` — update existing tests + add new ones

- [ ] **Step 1: Update existing find_matches tests to use new parameter name**

In `~/Tools/tests/test_hacktrix.py`, replace every occurrence of `hacktricks_path=tmp_path` with `search_paths=[tmp_path]`. There are 5 occurrences across these tests:
- `test_find_matches_returns_match_when_all_terms_present`
- `test_find_matches_excludes_file_missing_a_term`
- `test_find_matches_is_case_insensitive`
- `test_find_matches_returns_empty_list_when_repo_missing`
- `test_find_matches_searches_subdirectories`

The updated tests look like:

```python
def test_find_matches_returns_match_when_all_terms_present(tmp_path):
    md = tmp_path / "test.md"
    md.write_text("## SSTI\nHandlebars template RCE\n{{7*7}}")
    results = find_matches(["handlebars", "ssti", "rce"], search_paths=[tmp_path])
    assert len(results) == 1
    assert results[0][0] == md


def test_find_matches_excludes_file_missing_a_term(tmp_path):
    md = tmp_path / "test.md"
    md.write_text("## SSTI\nHandlebars template injection\n{{7*7}}")
    results = find_matches(["handlebars", "ssti", "rce"], search_paths=[tmp_path])
    assert results == []


def test_find_matches_is_case_insensitive(tmp_path):
    md = tmp_path / "test.md"
    md.write_text("## SSTI\nHANDLEBARS RCE template\n{{7*7}}")
    results = find_matches(["handlebars", "rce"], search_paths=[tmp_path])
    assert len(results) == 1


def test_find_matches_returns_empty_list_when_repo_missing(tmp_path):
    nonexistent = tmp_path / "nonexistent"
    results = find_matches(["ssti"], search_paths=[nonexistent])
    assert results == []


def test_find_matches_searches_subdirectories(tmp_path):
    subdir = tmp_path / "pentesting" / "web"
    subdir.mkdir(parents=True)
    md = subdir / "ssti.md"
    md.write_text("## Handlebars\nRCE via SSTI\n{{7*7}}")
    results = find_matches(["handlebars", "rce", "ssti"], search_paths=[tmp_path])
    assert len(results) == 1
```

- [ ] **Step 2: Add two new find_matches tests**

Append to `~/Tools/tests/test_hacktrix.py`:

```python
def test_find_matches_combines_results_from_multiple_paths(tmp_path):
    src1 = tmp_path / "source1"
    src1.mkdir()
    (src1 / "file1.md").write_text("## SSTI\nHandlebars RCE example")
    src2 = tmp_path / "source2"
    src2.mkdir()
    (src2 / "file2.md").write_text("## SSTI\nHandlebars RCE payload {{7*7}}")
    results = find_matches(["handlebars", "rce"], search_paths=[src1, src2])
    assert len(results) == 2


def test_find_matches_skips_missing_path(tmp_path):
    existing = tmp_path / "existing"
    existing.mkdir()
    (existing / "test.md").write_text("## SSTI\nHandlebars RCE here")
    missing = tmp_path / "missing"
    results = find_matches(["handlebars", "rce"], search_paths=[existing, missing])
    assert len(results) == 1
```

- [ ] **Step 3: Run to verify existing tests now fail (parameter name mismatch)**

```bash
cd ~/Tools && python -m pytest tests/test_hacktrix.py -v 2>&1 | grep -E "FAIL|ERROR|passed|failed"
```

Expected: 5 failures — `find_matches` doesn't accept `search_paths` yet

- [ ] **Step 4: Update find_matches in hacktrix.py**

Replace the entire `find_matches` function:

```python
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
```

- [ ] **Step 5: Run all tests to verify they pass**

```bash
cd ~/Tools && python -m pytest tests/test_hacktrix.py -v
```

Expected: all pass (15 existing + 2 new = 17)

- [ ] **Step 6: Commit**

```bash
cd ~/Tools && git add hacktrix.py tests/test_hacktrix.py
git commit -m "feat: update find_matches to search multiple source paths"
```

---

### Task 3: Update main() — multi-source error handling and output labels

**Files:**
- Modify: `~/Tools/hacktrix.py` — replace `main()` body

- [ ] **Step 1: Run existing CLI tests to confirm they currently pass**

```bash
cd ~/Tools && python -m pytest tests/test_hacktrix.py::test_cli_no_results tests/test_hacktrix.py::test_cli_exploit_flag_without_api_key -v
```

Expected: both pass (baseline before changes)

- [ ] **Step 2: Replace main() in hacktrix.py**

Replace the entire `main` function:

```python
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
```

- [ ] **Step 3: Run all tests**

```bash
cd ~/Tools && python -m pytest tests/test_hacktrix.py -v
```

Expected: all 17 pass

- [ ] **Step 4: Commit**

```bash
cd ~/Tools && git add hacktrix.py
git commit -m "feat: update main() for multi-source error handling and source labels"
```

---

### Task 4: Update Claude prompt

**Files:**
- Modify: `~/Tools/hacktrix.py` — update prompt string in `ask_claude`

- [ ] **Step 1: Update the prompt in ask_claude**

In `~/Tools/hacktrix.py`, find this line inside `ask_claude`:

```python
                f"Based on these HackTricks sections about {' '.join(terms)}:\n\n"
```

Replace with:

```python
                f"Based on these HackTricks and PayloadsAllTheThings sections about {' '.join(terms)}:\n\n"
```

- [ ] **Step 2: Run all tests**

```bash
cd ~/Tools && python -m pytest tests/test_hacktrix.py -v
```

Expected: all 17 pass (the mock test only checks that `"handlebars"` is in the prompt, not the full text)

- [ ] **Step 3: Commit**

```bash
cd ~/Tools && git add hacktrix.py
git commit -m "feat: update Claude prompt to mention PayloadsAllTheThings"
```

---

### Task 5: Clone PATT and smoke test

**Files:** none (system operation)

- [ ] **Step 1: Clone PayloadsAllTheThings**

```bash
git clone https://github.com/swisskyrepo/PayloadsAllTheThings ~/Tools/payloadsallthethings
```

- [ ] **Step 2: Run all tests**

```bash
cd ~/Tools && python -m pytest tests/test_hacktrix.py -v
```

Expected: all 17 pass

- [ ] **Step 3: Smoke test — both sources**

```bash
hacktrix ssti handlebars
```

Expected: results from both `[hacktricks]` and `[payloadsallthethings]` sources with `Found N file(s)` summary

- [ ] **Step 4: Smoke test — verify source labels**

```bash
hacktrix xss payload | head -20
```

Expected: output lines showing `Source: [hacktricks] ...` and/or `Source: [payloadsallthethings] ...`

- [ ] **Step 5: Push to GitHub**

```bash
cd ~/Tools && git push
```
