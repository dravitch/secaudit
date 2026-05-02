"""
tools/_scope.py
Helper partagé : valide qu'une cible est autorisée par config/scope.yaml.

Mindset 9 — Test Before Trust : aucun outil n'envoie de paquet
sans avoir consulté ce fichier au préalable.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import yaml

DEFAULT_SCOPE_PATH = Path(__file__).resolve().parent.parent / "config" / "scope.yaml"


def normalize_host(target: str) -> str:
    """Accept 'example.com', 'http://example.com', 'https://example.com:443/path'."""
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split("/")[0].split(":")[0]


def load_scope(path: Optional[Path] = None) -> dict:
    p = Path(path) if path else DEFAULT_SCOPE_PATH
    with p.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def assert_in_scope(
    target: str, sprint: int, scope_path: Optional[Path] = None
) -> dict:
    """Raise ValueError if target is not authorized for this sprint. Returns the matching entry."""
    scope = load_scope(scope_path)
    host = normalize_host(target)
    for entry in scope.get("authorized_targets", []) or []:
        if entry.get("host") == host:
            sprint_max = int(entry.get("sprint_max", 5))
            if sprint > sprint_max:
                raise ValueError(
                    f"Target '{host}' is in scope but sprint {sprint} exceeds "
                    f"sprint_max={sprint_max}"
                )
            return entry
    raise ValueError(
        f"Target '{host}' not in authorized scope. "
        f"Add it to config/scope.yaml before scanning."
    )
