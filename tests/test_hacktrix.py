import sys
from pathlib import Path
sys.path.insert(0, str(Path.home() / "Tools"))

from hacktrix import extract_snippet, find_matches, ask_claude
from unittest.mock import patch, MagicMock


def test_placeholder():
    assert True


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
    results = find_matches(["handlebars", "ssti", "rce"], hacktricks_path=tmp_path)
    assert len(results) == 1
    assert results[0][0] == md


def test_find_matches_excludes_file_missing_a_term(tmp_path):
    md = tmp_path / "test.md"
    md.write_text("## SSTI\nHandlebars template injection\n{{7*7}}")
    results = find_matches(["handlebars", "ssti", "rce"], hacktricks_path=tmp_path)
    assert results == []


def test_find_matches_is_case_insensitive(tmp_path):
    md = tmp_path / "test.md"
    md.write_text("## SSTI\nHANDLEBARS RCE template\n{{7*7}}")
    results = find_matches(["handlebars", "rce"], hacktricks_path=tmp_path)
    assert len(results) == 1


def test_find_matches_returns_empty_list_when_repo_missing(tmp_path):
    nonexistent = tmp_path / "nonexistent"
    results = find_matches(["ssti"], hacktricks_path=nonexistent)
    assert results == []


def test_find_matches_searches_subdirectories(tmp_path):
    subdir = tmp_path / "pentesting" / "web"
    subdir.mkdir(parents=True)
    md = subdir / "ssti.md"
    md.write_text("## Handlebars\nRCE via SSTI\n{{7*7}}")
    results = find_matches(["handlebars", "rce", "ssti"], hacktricks_path=tmp_path)
    assert len(results) == 1


def test_ask_claude_sends_terms_and_snippets_to_api():
    matches = [
        (Path("/fake/ssti.md"), "## Handlebars SSTI\n{{7*7}} = 49 means vulnerable\nRCE via: ...")
    ]
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="Summary: SSTI in Handlebars\nPayload: {{7*7}}")]

    with patch("anthropic.Anthropic") as mock_client_cls:
        mock_client = MagicMock()
        mock_client_cls.return_value = mock_client
        mock_client.messages.create.return_value = mock_response

        result = ask_claude(matches, ["handlebars", "ssti", "rce"])

    assert "Summary" in result or "Payload" in result
    call_kwargs = mock_client.messages.create.call_args[1]
    assert call_kwargs["model"] == "claude-sonnet-4-6"
    assert "handlebars" in call_kwargs["messages"][0]["content"].lower()
