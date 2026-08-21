from pathlib import Path
from shutil import copytree

from sap_sod_evidence_audit.loader import load_bundle

PROJECT_ROOT = Path(__file__).parents[1]
EXAMPLE = PROJECT_ROOT / "examples" / "synthetic"
RULES = PROJECT_ROOT / "rules" / "sap-sod-core-1.0.0.json"


def copy_example(parent: Path) -> Path:
    destination = parent / "bundle"
    copytree(EXAMPLE, destination)
    return destination


def replace(path: Path, old: str, new: str) -> None:
    content = path.read_text(encoding="utf-8")
    if old not in content:
        raise AssertionError(f"fixture text not found: {old}")
    path.write_text(content.replace(old, new), encoding="utf-8")


def example_bundle():
    return load_bundle(EXAMPLE, RULES)
