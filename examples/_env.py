"""Tiny helper: load TYPESAFE_API_KEY from ../.env so the examples run without exporting anything."""
import os
from pathlib import Path

_env = Path(__file__).parent.parent / ".env"
if _env.exists():
    for line in _env.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())
