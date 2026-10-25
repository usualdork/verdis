"""Verdis: reproduce-first triage for security reports.

The core bet of the tool is *an LLM proposes, the sandbox disposes*: models
read prose and draft plans, but whether a bug reproduced is decided by
observable oracles, never by a model's opinion.
"""

from __future__ import annotations

__version__ = "0.1.1"

__all__ = ["__version__"]
