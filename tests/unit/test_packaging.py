"""The data files the frozen build bundles exist and are found through package-relative paths."""

from __future__ import annotations

from pathlib import Path

from simplysec.app import paths

PKG = Path(__file__).resolve().parents[2] / "src" / "simplysec"


def test_bundled_data_exists():
    for rel in (
        "core/knowledge/ports.toml",
        "core/knowledge/programs.toml",
        "core/knowledge/services.toml",
        "windows/scripts/facts.ps1",
        "core/report/templates/report.html.j2",
        "resources/oui.csv.gz",
        "resources/simplysec.ico",
    ):
        assert (PKG / rel).is_file(), rel


def test_paths_resolve_inside_package():
    assert paths.facts_script().is_file()
    assert paths.resource("oui.csv.gz").is_file()


def test_spec_lists_the_same_data():
    spec = (PKG.parents[1] / "packaging" / "simplysec.spec").read_text(encoding="utf-8")
    for needle in (
        "knowledge",
        "*.ps1",
        "templates",
        "oui.csv.gz",
        "simplysec.ico",
        "uac_admin=False",
    ):
        assert needle in spec
