"""
profile_loader.py - Model profile selection for LLM Strata
Author : Venkateshwara Doijode
Project: LLM Strata - End-to-End LLM Security & Safety Framework

Reads profiles.yaml and returns the active profile's model settings.
Each run_*.py calls get_model() to resolve the model, with this priority:

    ACTIVE_PROFILE env var -> profiles.yaml active_profile -> module YAML config -> code default

Usage in any run_*.py:
    from profile_loader import get_model
    model = get_model("model", config.get("model", "gpt-4o-mini"))
"""

import os
from pathlib import Path
import yaml

_PROFILES_PATH = Path(__file__).resolve().parent / "profiles.yaml"
_profile_cache: dict | None = None
_active_name_cache: str | None = None


def load_profile() -> dict:
    """Return the active profile dict from profiles.yaml.
    Respects ACTIVE_PROFILE env var over the active_profile key in the file.
    Returns an empty dict if profiles.yaml does not exist.
    """
    global _profile_cache, _active_name_cache
    if _profile_cache is not None:
        return _profile_cache

    if not _PROFILES_PATH.exists():
        _profile_cache = {}
        return _profile_cache

    with open(_PROFILES_PATH) as f:
        data = yaml.safe_load(f) or {}

    active = os.environ.get("ACTIVE_PROFILE") or data.get("active_profile", "cost_optimized")
    profiles = data.get("profiles", {})

    if active not in profiles:
        available = list(profiles.keys())
        raise ValueError(
            f"Profile '{active}' not found in profiles.yaml. "
            f"Available profiles: {available}"
        )

    _active_name_cache = active
    _profile_cache = profiles[active]
    return _profile_cache


def get_model(key: str, fallback: str) -> str:
    """Resolve a model name from the active profile, falling back to the module config value.
    Args:
        key:      Profile key to look up (e.g. 'model', 'judge_model', 'attacker_model').
        fallback: Value from the module's YAML config (or hardcoded default) to use
                  if the active profile does not define this key.

    Returns:
        Resolved model name string.
    """
    profile = load_profile()
    return profile.get(key, fallback)


def active_profile_name() -> str:
    """Return the name of the currently active profile (for display purposes)."""
    if not _PROFILES_PATH.exists():
        return "none"
    if _active_name_cache is not None:
        return _active_name_cache
    with open(_PROFILES_PATH) as f:
        data = yaml.safe_load(f) or {}
    return os.environ.get("ACTIVE_PROFILE") or data.get("active_profile", "cost_optimized")
    