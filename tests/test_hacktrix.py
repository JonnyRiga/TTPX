import sys
from pathlib import Path
sys.path.insert(0, str(Path.home() / "Tools"))

from hacktrix import extract_snippet, find_matches


def test_placeholder():
    assert True
