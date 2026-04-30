# hacktrix — PayloadsAllTheThings Integration Design Spec
Date: 2026-04-30

## Overview

Add PayloadsAllTheThings (PATT) as a second search source alongside HackTricks. Both repos are searched by default with no flags required.

## Installation

- PATT repo: `~/Tools/payloadsallthethings/` (cloned from https://github.com/swisskyrepo/PayloadsAllTheThings)

## Changes

### 1. New Constant

```python
PATT_PATH = Path.home() / "Tools" / "payloadsallthethings"
```

### 2. `find_matches` signature change

```python
def find_matches(terms, search_paths=None):
    if search_paths is None:
        search_paths = [HACKTRICKS_PATH, PATT_PATH]
```

- Walks each path in `search_paths` that exists
- Skips paths that don't exist (no crash)
- Returns `list[tuple[Path, str]]` as before

### 3. Output label helper

```python
def source_label(path):
    for base in [HACKTRICKS_PATH, PATT_PATH]:
        if path.is_relative_to(base):
            return f"[{base.name}] {path.relative_to(base)}"
    return str(path)
```

Replaces `path.relative_to(HACKTRICKS_PATH)` in `main()`. Uses global constants directly — no need to thread `search_paths` through to the output layer.

### 4. Error handling in `main()`

- If ALL sources missing → exit with clone instructions for both
- If ONE source missing → warn, continue with the other

### 5. Claude prompt update

Change "HackTricks" → "HackTricks and PayloadsAllTheThings" in `ask_claude`.

## Error Messages

| Condition | Output |
|---|---|
| Both repos missing | `No sources found. Clone:\n  git clone ... ~/Tools/hacktricks\n  git clone ... ~/Tools/payloadsallthethings` |
| Only PATT missing | `Warning: PayloadsAllTheThings not found. Searching HackTricks only.` |
| Only HackTricks missing | `Warning: HackTricks not found. Searching PayloadsAllTheThings only.` |

## Test Changes

- Update `find_matches` tests to pass `search_paths=[tmp_path]` instead of `hacktricks_path=tmp_path`
- Add test: searching two paths returns combined results
- Add test: missing path is skipped without error

## Out of Scope

- `--source` flag
- Deduplication across sources (different files, won't overlap)
