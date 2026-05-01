import sys
import os
import subprocess
from pathlib import Path
sys.path.insert(0, str(Path.home() / "Tools"))

from hacktrix import extract_snippet, extract_title, find_matches, ask_claude, source_label, HACKTRICKS_PATH, PATT_PATH
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

        result = ask_claude(matches, ["handlebars", "rce"], details="'require' is not defined")

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
