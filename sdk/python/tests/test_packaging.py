"""Packaging metadata must be buildable from the `sdk/python` directory alone."""

from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10; `tomli` comes with the `dev` extra there.
    import tomli as tomllib

PROJECT = Path(__file__).resolve().parents[1]


def test_readme_lies_inside_the_project_directory() -> None:
    meta = tomllib.loads((PROJECT / "pyproject.toml").read_text(encoding="utf-8"))
    readme = (PROJECT / meta["project"]["readme"]).resolve()
    # hatchling refuses a readme outside the project root, which breaks `pip install`.
    assert readme.is_relative_to(PROJECT), readme
    assert readme.is_file(), readme
