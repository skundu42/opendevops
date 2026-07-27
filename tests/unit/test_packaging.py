"""Distribution metadata and release-version invariants."""

from importlib.metadata import version

from opendevops import __version__


def test_distribution_version_matches_runtime_version() -> None:
    assert version("opendevops") == __version__
