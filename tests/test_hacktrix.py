import sys
from pathlib import Path
sys.path.insert(0, str(Path.home() / "Tools"))

from hacktrix import extract_snippet, find_matches


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
