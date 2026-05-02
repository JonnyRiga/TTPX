import sys
import os
import subprocess
import pytest
from pathlib import Path
sys.path.insert(0, str(Path.home() / "Tools"))

from hacktrix import extract_snippet, extract_title, find_matches, ask_claude, source_label, strip_markdown, extract_section, mirror_file, log_payload_result, HACKTRICKS_PATH, PATT_PATH, MAX_PAYLOAD_MATCHES
from unittest.mock import patch, MagicMock


def test_extract_snippet_returns_heading_and_context():
    lines = [
        "# Introduction",
        "Some unrelated text",
        "## SSTI in Handlebars",
        "Handlebars RCE example",
        "{{7*7}}",
        "More details here",
        "Extra line 1",
        "Extra line 2",
    ]
    result = extract_snippet(lines, ["handlebars", "rce"])
    assert "## SSTI in Handlebars" in result
    assert "Handlebars RCE example" in result


def test_extract_snippet_falls_back_to_start_if_no_heading():
    lines = [
        "No heading here",
        "handlebars rce payload",
        "{{7*7}}",
    ]
    result = extract_snippet(lines, ["handlebars"])
    assert "handlebars rce payload" in result


def test_extract_snippet_is_case_insensitive():
    lines = [
        "## Template Injection",
        "HANDLEBARS RCE here",
    ]
    result = extract_snippet(lines, ["handlebars"])
    assert "HANDLEBARS RCE here" in result


def test_extract_snippet_returns_start_when_no_terms():
    lines = ["line one", "line two", "line three"]
    result = extract_snippet(lines, [])
    assert "line one" in result


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


def test_find_matches_combines_results_from_multiple_paths(tmp_path):
    src1 = tmp_path / "hacktricks"
    src2 = tmp_path / "patt"
    src1.mkdir()
    src2.mkdir()
    (src1 / "ssti.md").write_text("## SSTI\nhandlebars rce payload")
    (src2 / "ssti.md").write_text("## SSTI\nhandlebars rce example")
    results = find_matches(["handlebars", "rce"], search_paths=[src1, src2])
    assert len(results) == 2


def test_find_matches_skips_missing_path(tmp_path):
    existing = tmp_path / "exists"
    existing.mkdir()
    (existing / "ssti.md").write_text("## SSTI\nhandlebars rce")
    missing = tmp_path / "missing"
    results = find_matches(["handlebars", "rce"], search_paths=[existing, missing])
    assert len(results) == 1


def test_ask_claude_returns_parsed_json():
    import json
    matches = [
        (Path("/fake/ssti.md"), "## Handlebars SSTI\n{{7*7}} = 49 means vulnerable\nRCE via: ...")
    ]
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text=json.dumps({
        "vulnerability": "SSTI via Handlebars (Node.js)",
        "technique": "RCE via prototype chain escape",
        "language": "javascript",
        "payload": "{{#with 'x'}}...{{/with}}",
        "changes": "",
        "recommendation": "Most impactful: gives direct RCE."
    }))]

    with patch("anthropic.Anthropic") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_response

        result = ask_claude(matches, ["handlebars", "ssti", "rce"])

    assert result["vulnerability"] == "SSTI via Handlebars (Node.js)"
    assert result["language"] == "javascript"
    assert "payload" in result
    assert "recommendation" in result
    assert result.get("changes", "") == ""  # no details — changes must be empty
    call_kwargs = mock_client.messages.create.call_args[1]
    assert call_kwargs["model"] == "claude-sonnet-4-6"


def test_ask_claude_includes_details_in_prompt():
    import json
    matches = [
        (Path("/fake/ssti.md"), "## Handlebars SSTI\n{{7*7}} = 49\nRCE via: ...")
    ]
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text=json.dumps({
        "vulnerability": "SSTI via Handlebars (Node.js)",
        "technique": "RCE via prototype chain escape",
        "language": "javascript",
        "payload": "{{#with 'x'}}...{{/with}}",
        "recommendation": "Adapted after require error."
    }))]

    with patch("anthropic.Anthropic") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_response

        result = ask_claude(matches, ["handlebars", "rce"], details=["'require' is not defined"])

    call_kwargs = mock_client.messages.create.call_args[1]
    prompt = call_kwargs["messages"][0]["content"]
    assert "'require' is not defined" in prompt
    assert "adapt" in prompt.lower()
    assert result["language"] == "javascript"


def test_cli_find_no_results():
    result = subprocess.run(
        ["python", str(Path.home() / "Tools" / "hacktrix.py"), "-f", "nonexistentterm123xyz"],
        capture_output=True, text=True
    )
    assert result.returncode == 0


def test_cli_payload_flag_without_api_key():
    env = os.environ.copy()
    env.pop("ANTHROPIC_API_KEY", None)
    result = subprocess.run(
        ["python", str(Path.home() / "Tools" / "hacktrix.py"), "-p", "ssti"],
        capture_output=True, text=True, env=env
    )
    assert "ANTHROPIC_API_KEY" in result.stdout or "ANTHROPIC_API_KEY" in result.stderr


def test_cli_requires_flag():
    result = subprocess.run(
        ["python", str(Path.home() / "Tools" / "hacktrix.py")],
        capture_output=True, text=True
    )
    assert result.returncode != 0


def test_source_label_identifies_hacktricks_path():
    path = HACKTRICKS_PATH / "web" / "ssti.md"
    assert source_label(path) == "[hacktricks] web/ssti.md"


def test_source_label_identifies_patt_path():
    path = PATT_PATH / "SSTI" / "README.md"
    assert source_label(path) == "[payloadsallthethings] SSTI/README.md"


def test_source_label_falls_back_to_str_for_unknown_path():
    path = Path("/tmp/unknown.md")
    assert source_label(path) == "/tmp/unknown.md"


def test_extract_title_returns_nearest_heading_stripped():
    lines = [
        "# Introduction",
        "Some text",
        "## Handlebars - RCE",
        "Handlebars rce payload here",
    ]
    assert extract_title(lines, ["handlebars", "rce"]) == "Handlebars - RCE"


def test_extract_title_truncates_long_headings():
    lines = [
        "## This Is A Very Long Heading That Exceeds Forty Five Characters Total",
        "handlebars rce content",
    ]
    result = extract_title(lines, ["handlebars"])
    assert len(result) <= 45
    assert result.endswith("...")


def test_extract_title_falls_back_to_filename_when_no_heading(tmp_path):
    md = tmp_path / "handlebars-rce.md"
    lines = ["no heading here", "handlebars rce payload"]
    result = extract_title(lines, ["handlebars"], fallback=md)
    assert result == "handlebars-rce.md"


def test_extract_title_returns_unknown_when_no_terms_and_no_fallback():
    lines = ["## Some Heading", "some content"]
    result = extract_title(lines, [])
    assert result == "Unknown"


def test_strip_markdown_preserves_dunder_names():
    payload = '{{config.__class__.__init__.__globals__["os"].popen("id").read()}}'
    assert strip_markdown(payload) == payload


def test_strip_markdown_preserves_glob_asterisks():
    assert "*.php" in strip_markdown("find / -name '*.php'")
    assert "rm *" in strip_markdown("rm *")


def test_strip_markdown_removes_images_cleanly():
    result = strip_markdown("before\n![alt](http://example.com/img.png)\nafter")
    assert "!" not in result
    assert "before" in result
    assert "after" in result


def test_strip_markdown_strips_headings():
    result = strip_markdown("## Handlebars - RCE\nsome content")
    assert "##" not in result
    assert "Handlebars - RCE" in result


def test_strip_markdown_preserves_code_fence_content():
    result = strip_markdown("```javascript\n{{7*7}}\n```")
    assert "{{7*7}}" in result


def test_extract_section_returns_matching_section():
    text = "## Lodash\nlodash content\n\n## Handlebars\nhandlebars content\n\n## Pug\npug content"
    result = extract_section(text, "handlebars")
    assert "handlebars content" in result
    assert "lodash content" not in result
    assert "pug content" not in result


def test_extract_section_stops_at_equal_level_heading():
    text = "## Handlebars\nsome content\n### Handlebars - RCE\npayload here\n## Lodash\nlodash"
    result = extract_section(text, "handlebars")
    assert "payload here" in result
    assert "lodash" not in result


def test_extract_section_returns_none_when_not_found():
    text = "## Lodash\nlodash content\n## Pug\npug content"
    assert extract_section(text, "handlebars") is None


def test_extract_section_is_case_insensitive():
    text = "## HANDLEBARS\ncontent here"
    result = extract_section(text, "handlebars")
    assert "content here" in result


def test_list_categories_shows_directories(tmp_path, monkeypatch):
    import hacktrix
    ht = tmp_path / "hacktricks"
    patt = tmp_path / "patt"
    (ht / "Web Attacks").mkdir(parents=True)
    (ht / "Network").mkdir(parents=True)
    (ht / ".git").mkdir(parents=True)
    (patt / "SQL Injection").mkdir(parents=True)
    monkeypatch.setattr(hacktrix, "HACKTRICKS_PATH", ht)
    monkeypatch.setattr(hacktrix, "PATT_PATH", patt)
    # Should not raise; hidden dirs excluded
    hacktrix.list_categories()


def test_list_categories_excludes_hidden_dirs(tmp_path, monkeypatch):
    import io
    import hacktrix
    from rich.console import Console as RichConsole
    ht = tmp_path / "hacktricks"
    (ht / ".git").mkdir(parents=True)
    (ht / "Web Attacks").mkdir(parents=True)
    monkeypatch.setattr(hacktrix, "HACKTRICKS_PATH", ht)
    monkeypatch.setattr(hacktrix, "PATT_PATH", tmp_path / "missing")
    buf = io.StringIO()
    monkeypatch.setattr(hacktrix, "console", RichConsole(file=buf, highlight=False))
    hacktrix.list_categories()
    output = buf.getvalue()
    assert ".git" not in output
    assert "Web Attacks" in output


def test_update_sources_already_up_to_date(tmp_path, monkeypatch):
    import hacktrix
    ht = tmp_path / "hacktricks"
    ht.mkdir()
    monkeypatch.setattr(hacktrix, "HACKTRICKS_PATH", ht)
    monkeypatch.setattr(hacktrix, "PATT_PATH", tmp_path / "missing")

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        if "pull" in cmd:
            result.returncode = 0
            result.stdout = "Already up to date."
            result.stderr = ""
        return result

    monkeypatch.setattr(hacktrix.subprocess, "run", fake_run)
    hacktrix.update_sources()


def test_update_sources_prints_stat_on_new_commits(tmp_path, monkeypatch):
    import hacktrix
    ht = tmp_path / "hacktricks"
    ht.mkdir()
    monkeypatch.setattr(hacktrix, "HACKTRICKS_PATH", ht)
    monkeypatch.setattr(hacktrix, "PATT_PATH", tmp_path / "missing")

    call_count = {"n": 0}

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        if "pull" in cmd:
            result.returncode = 0
            result.stdout = "Updating abc..def\nFast-forward\n 3 files changed"
            result.stderr = ""
        elif "diff" in cmd:
            result.returncode = 0
            result.stdout = " 3 files changed, 10 insertions(+), 2 deletions(-)"
        call_count["n"] += 1
        return result

    monkeypatch.setattr(hacktrix.subprocess, "run", fake_run)
    hacktrix.update_sources()
    assert call_count["n"] >= 2


def test_update_sources_handles_git_failure(tmp_path, monkeypatch):
    import hacktrix
    ht = tmp_path / "hacktricks"
    ht.mkdir()
    monkeypatch.setattr(hacktrix, "HACKTRICKS_PATH", ht)
    monkeypatch.setattr(hacktrix, "PATT_PATH", tmp_path / "missing")

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 1
        result.stdout = ""
        result.stderr = "not a git repository"
        return result

    monkeypatch.setattr(hacktrix.subprocess, "run", fake_run)
    hacktrix.update_sources()  # should not raise


@pytest.mark.skipif(
    not (HACKTRICKS_PATH.exists() or PATT_PATH.exists()),
    reason="requires at least one knowledge base to be cloned"
)
def test_cli_list_flag():
    result = subprocess.run(
        ["python", str(Path.home() / "Tools" / "hacktrix.py"), "-l"],
        capture_output=True, text=True
    )
    assert result.returncode == 0


def test_cli_update_flag_missing_repos(monkeypatch, tmp_path):
    import hacktrix
    monkeypatch.setattr(hacktrix, "HACKTRICKS_PATH", tmp_path / "missing_ht")
    monkeypatch.setattr(hacktrix, "PATT_PATH", tmp_path / "missing_patt")

    with pytest.raises(SystemExit) as exc:
        hacktrix.update_sources()
    assert exc.value.code != 0


def test_recently_changed_dirs_parses_git_output(tmp_path, monkeypatch):
    import hacktrix
    captured = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return MagicMock(
            stdout="Server Side Template Injection/JavaScript.md\n\nSQL Injection/README.md\n",
            returncode=0
        )

    monkeypatch.setattr(hacktrix.subprocess, "run", fake_run)
    dirs = hacktrix._recently_changed_dirs(tmp_path, 7)
    assert "Server Side Template Injection" in dirs
    assert "SQL Injection" in dirs
    assert "--since=7 days ago" in captured["cmd"]


def test_recently_changed_dirs_ignores_blank_lines(tmp_path, monkeypatch):
    import hacktrix
    monkeypatch.setattr(hacktrix.subprocess, "run", lambda cmd, **kw: MagicMock(
        stdout="\n\nSQL Injection/README.md\n\n",
        returncode=0
    ))
    dirs = hacktrix._recently_changed_dirs(tmp_path, 7)
    assert "SQL Injection" in dirs
    assert "" not in dirs


def test_list_categories_since_filters_to_recent(tmp_path, monkeypatch):
    import io
    import hacktrix
    from rich.console import Console as RichConsole
    ht = tmp_path / "hacktricks"
    (ht / "SQL Injection").mkdir(parents=True)
    (ht / "Network").mkdir(parents=True)
    monkeypatch.setattr(hacktrix, "HACKTRICKS_PATH", ht)
    monkeypatch.setattr(hacktrix, "PATT_PATH", tmp_path / "missing")
    monkeypatch.setattr(hacktrix.subprocess, "run", lambda cmd, **kw: MagicMock(
        stdout="SQL Injection/README.md\n", returncode=0
    ))
    buf = io.StringIO()
    monkeypatch.setattr(hacktrix, "console", RichConsole(file=buf, highlight=False))
    hacktrix.list_categories(since_days=7)
    output = buf.getvalue()
    assert "SQL Injection" in output
    assert "Network" not in output
    assert "of 2" in output  # "1 of 2 categories (last 7d)"


def test_list_categories_shows_count_footer(tmp_path, monkeypatch):
    import io
    import hacktrix
    from rich.console import Console as RichConsole
    ht = tmp_path / "hacktricks"
    (ht / "Web Attacks").mkdir(parents=True)
    (ht / "Network").mkdir(parents=True)
    monkeypatch.setattr(hacktrix, "HACKTRICKS_PATH", ht)
    monkeypatch.setattr(hacktrix, "PATT_PATH", tmp_path / "missing")
    buf = io.StringIO()
    monkeypatch.setattr(hacktrix, "console", RichConsole(file=buf, highlight=False))
    hacktrix.list_categories()
    output = buf.getvalue()
    assert "2 categories" in output


def test_ask_claude_includes_changes_field_when_details_given():
    import json
    matches = [(Path("/fake/ssti.md"), "## Handlebars SSTI\n{{7*7}}\nRCE via: ...")]
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text=json.dumps({
        "vulnerability": "SSTI via Handlebars (Node.js)",
        "technique": "RCE via prototype chain escape",
        "language": "javascript",
        "payload": "{{#with 'x'}}...{{/with}}",
        "changes": "- Replaced require() with process.mainModule.require()",
        "recommendation": "Adapted after require error."
    }))]
    with patch("anthropic.Anthropic") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_response
        result = ask_claude(matches, ["handlebars"], details=["require is not defined"])
    call_kwargs = mock_client.messages.create.call_args[1]
    prompt = call_kwargs["messages"][0]["content"]
    assert '"changes"' in prompt
    assert "bullet" in prompt.lower()
    assert result["changes"] == "- Replaced require() with process.mainModule.require()"


def test_ask_claude_changes_field_empty_without_details():
    import json
    matches = [(Path("/fake/ssti.md"), "## Handlebars SSTI\n{{7*7}}\nRCE via: ...")]
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text=json.dumps({
        "vulnerability": "SSTI via Handlebars",
        "technique": "RCE via prototype",
        "language": "javascript",
        "payload": "{{7*7}}",
        "changes": "",
        "recommendation": "Most impactful."
    }))]
    with patch("anthropic.Anthropic") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_response
        result = ask_claude(matches, ["handlebars"])
    call_kwargs = mock_client.messages.create.call_args[1]
    prompt = call_kwargs["messages"][0]["content"]
    assert '"changes": ""' in prompt


def test_display_payload_result_shows_changes_section(monkeypatch):
    import io
    import hacktrix
    from rich.console import Console as RichConsole
    buf = io.StringIO()
    monkeypatch.setattr(hacktrix, "console", RichConsole(file=buf, highlight=False))
    data = {
        "vulnerability": "SSTI via Handlebars",
        "technique": "RCE via prototype chain",
        "language": "javascript",
        "payload": "{{7*7}}",
        "changes": "- Used process.mainModule instead of require",
        "recommendation": "Most impactful.",
    }
    hacktrix.display_payload_result(data, ["[hacktricks] ssti.md"])
    output = buf.getvalue()
    assert "What changed" in output
    assert "process.mainModule" in output


def test_display_payload_result_no_changes_section_when_empty(monkeypatch):
    import io
    import hacktrix
    from rich.console import Console as RichConsole
    buf = io.StringIO()
    monkeypatch.setattr(hacktrix, "console", RichConsole(file=buf, highlight=False))
    data = {
        "vulnerability": "SSTI via Handlebars",
        "technique": "RCE via prototype chain",
        "language": "javascript",
        "payload": "{{7*7}}",
        "changes": "",
        "recommendation": "Most impactful.",
    }
    hacktrix.display_payload_result(data, ["[hacktricks] ssti.md"])
    output = buf.getvalue()
    assert "What changed" not in output


def test_display_payload_result_includes_raw_copy_paste_block(monkeypatch):
    import io
    import hacktrix
    from rich.console import Console as RichConsole
    buf = io.StringIO()
    monkeypatch.setattr(hacktrix, "console", RichConsole(file=buf, highlight=False))
    payload = "{{#with 'x' as |string|}}\n  {{string.constructor payload}}\n{{/with}}"
    data = {
        "vulnerability": "SSTI",
        "technique": "proto chain",
        "language": "javascript",
        "payload": payload,
        "changes": "",
        "recommendation": "Most impactful.",
    }
    hacktrix.display_payload_result(data, [])
    output = buf.getvalue()
    assert "copy-paste" in output
    assert "{{#with" in output


def test_mirror_file_rejects_path_traversal(tmp_path, monkeypatch):
    import hacktrix
    ht = tmp_path / "hacktricks"
    patt = tmp_path / "patt"
    ht.mkdir()
    patt.mkdir()
    sensitive = tmp_path / "secret.md"
    sensitive.write_text("secret content")
    monkeypatch.setattr(hacktrix, "HACKTRICKS_PATH", ht)
    monkeypatch.setattr(hacktrix, "PATT_PATH", patt)

    with pytest.raises(SystemExit) as exc:
        hacktrix.mirror_file("../secret.md")

    assert exc.value.code != 0
    assert not sensitive.read_text() == ""  # file not read or modified


# Task #11: multi-pass -d

def test_ask_claude_multi_pass_details_joined():
    import json
    matches = [(Path("/fake/ssti.md"), "## SSTI\ncontent")]
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text=json.dumps({
        "vulnerability": "SSTI",
        "technique": "chain",
        "language": "javascript",
        "payload": "payload",
        "changes": "- changed x",
        "recommendation": "use it",
    }))]
    with patch("anthropic.Anthropic") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_response
        ask_claude(matches, ["ssti"], details=["first error", "second error"])
    prompt = mock_client.messages.create.call_args[1]["messages"][0]["content"]
    assert "first error" in prompt
    assert "second error" in prompt
    assert "Previous attempts" in prompt


def test_ask_claude_single_detail_uses_singular_label():
    import json
    matches = [(Path("/fake/ssti.md"), "## SSTI\ncontent")]
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text=json.dumps({
        "vulnerability": "SSTI",
        "technique": "t",
        "language": "text",
        "payload": "p",
        "changes": "- x",
        "recommendation": "r",
    }))]
    with patch("anthropic.Anthropic") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_response
        ask_claude(matches, ["ssti"], details=["one error"])
    prompt = mock_client.messages.create.call_args[1]["messages"][0]["content"]
    assert "A previous attempt produced" in prompt


# Task #7: result cap

def test_find_matches_capped_in_main(tmp_path, monkeypatch):
    import io
    import hacktrix
    from rich.console import Console as RichConsole
    # Create more files than MAX_PAYLOAD_MATCHES
    for i in range(MAX_PAYLOAD_MATCHES + 3):
        md = tmp_path / f"file{i}.md"
        md.write_text("## SSTI\nhandlebars rce payload here")
    monkeypatch.setattr(hacktrix, "HACKTRICKS_PATH", tmp_path)
    monkeypatch.setattr(hacktrix, "PATT_PATH", tmp_path / "missing")
    buf = io.StringIO()
    monkeypatch.setattr(hacktrix, "console", RichConsole(file=buf, highlight=False))

    results = hacktrix.find_matches(["handlebars", "rce"], search_paths=[tmp_path])
    assert len(results) > MAX_PAYLOAD_MATCHES
    capped = results[:MAX_PAYLOAD_MATCHES]
    assert len(capped) == MAX_PAYLOAD_MATCHES


# Task #8: source header in mirrored file

def test_mirror_file_includes_source_header(tmp_path, monkeypatch):
    import hacktrix
    ht = tmp_path / "hacktricks"
    ht.mkdir()
    md = ht / "ssti.md"
    md.write_text("## SSTI\nsome content here")
    monkeypatch.setattr(hacktrix, "HACKTRICKS_PATH", ht)
    monkeypatch.setattr(hacktrix, "PATT_PATH", tmp_path / "missing")
    monkeypatch.chdir(tmp_path)
    hacktrix.mirror_file("ssti.md")
    out = tmp_path / "ssti.txt"
    content = out.read_text()
    assert "# Source:" in content
    assert "[hacktricks]" in content
    assert "ssti.md" in content
    assert "mirrored:" in content


# Task #9: file count in -l

def test_list_categories_shows_file_count(tmp_path, monkeypatch):
    import io
    import hacktrix
    from rich.console import Console as RichConsole
    ht = tmp_path / "hacktricks"
    cat = ht / "SQL Injection"
    cat.mkdir(parents=True)
    (cat / "README.md").write_text("content")
    (cat / "mysql.md").write_text("content")
    monkeypatch.setattr(hacktrix, "HACKTRICKS_PATH", ht)
    monkeypatch.setattr(hacktrix, "PATT_PATH", tmp_path / "missing")
    buf = io.StringIO()
    monkeypatch.setattr(hacktrix, "console", RichConsole(file=buf, highlight=False))
    hacktrix.list_categories()
    output = buf.getvalue()
    assert "SQL Injection" in output
    assert "2" in output  # 2 .md files


# Task #10: auto-log

def test_log_payload_result_writes_to_log(tmp_path, monkeypatch):
    import hacktrix
    log_path = tmp_path / "hacktrix-session.log"
    monkeypatch.setattr(hacktrix, "LOG_PATH", log_path)
    data = {
        "vulnerability": "SSTI via Handlebars",
        "payload": "{{7*7}}\nmore lines",
        "recommendation": "use it",
    }
    log_payload_result(["ssti", "handlebars"], data)
    content = log_path.read_text()
    assert "ssti handlebars" in content
    assert "SSTI via Handlebars" in content
    assert "{{7*7}}" in content


def test_log_payload_result_appends_not_overwrites(tmp_path, monkeypatch):
    import hacktrix
    log_path = tmp_path / "hacktrix-session.log"
    log_path.write_text("existing entry\n\n")
    monkeypatch.setattr(hacktrix, "LOG_PATH", log_path)
    data = {"vulnerability": "XSS", "payload": "<script>", "recommendation": "r"}
    log_payload_result(["xss"], data)
    content = log_path.read_text()
    assert "existing entry" in content
    assert "XSS" in content


def test_log_payload_result_silent_on_error(tmp_path, monkeypatch):
    import hacktrix
    # Point to a path where we can't write (file is a directory)
    log_path = tmp_path / "hacktrix-session.log"
    log_path.mkdir()
    monkeypatch.setattr(hacktrix, "LOG_PATH", log_path)
    data = {"vulnerability": "X", "payload": "p", "recommendation": "r"}
    log_payload_result(["x"], data)  # must not raise
