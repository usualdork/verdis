"""Allow ``python -m verdis``."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":  # pragma: no cover - the module entry point
    main()
