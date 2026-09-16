"""Compatibility entry point for the Day 2 detection engine.

The implementation lives in :mod:`detection.rule_engine`; this module keeps
``import rule_engine`` compatible with the phase-2 contract tests.
"""

from detection.rule_engine import detect

__all__ = ["detect"]
