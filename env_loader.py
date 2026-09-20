"""
env_loader.py - Minimal .env file loader (no external dependencies)
Author : Venkateshwara Doijode
Project: LLM Strata - End-to-End LLM Security & Safety Framework

Reads key-value pairs from .env and sets them as environment variables.
Drop-in replacement for python-dotenv's load_dotenv().

Priority order (highest to lowest):
  1. System environment variable  - already set in OS (e.g. via PowerShell,
                                     Windows System Properties, or CI/CD pipeline)
                                     These are NEVER overwritten by .env.
  2. .env file                   - only applied if the variable is NOT already
                                     set in the system environment.

This means:
  - Set OPENAI_API_KEY in your .env for local development
  - Set it as a system/CI variable in production - it will take precedence
  - You never need to change code between environments
"""

import os
import sys
from pathlib import Path


def load_dotenv(env_path: str = ".env"):
    """Load variables from .env file into os.environ."""
    path = Path(env_path)
    if not path.is_absolute():
        path = Path(__file__).resolve().parent / path
    if not path.exists():
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key and value and key not in os.environ:
                os.environ[key] = value


def require_env(*keys: str):
    """
    Check that all required environment variables are set.
    Exits with an error message if any are missing.
    Use this for tools that CANNOT run without the key.

    Example:
        require_env("OPENAI_API_KEY")
        require_env("OPENAI_API_KEY", "LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY")
    """
    missing = [k for k in keys if not os.environ.get(k)]
    if missing:
        for k in missing:
            print(f"  ERROR: {k} not set.")
            print("         Add it to your .env file or set it as a system environment variable.")
        sys.exit(1)


def require_provider_env(provider: str | None = None):
    """Require credentials for the active provider or a named provider."""
    from profile_loader import load_profile

    profile = load_profile()
    selected = (provider or profile.get("provider", "openai")).lower()
    required_by_provider = {
        "openai": ("OPENAI_API_KEY",),
        "azure": ("AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT"),
        "ollama": (),
        "gemini": ("GEMINI_API_KEY",),
        "huggingface": ("HF_TOKEN",),
        "anthropic": ("ANTHROPIC_API_KEY",),
        "bedrock": ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION_NAME"),
    }

    if selected in ("openai_compatible", "custom"):
        required = () if profile.get("base_url") or os.environ.get("OPENAI_COMPATIBLE_BASE_URL") else (
            "OPENAI_COMPATIBLE_BASE_URL",
        )
        if profile.get("api_key_required", True):
            required += (profile.get("api_key_env", "OPENAI_COMPATIBLE_API_KEY"),)
    elif selected not in required_by_provider:
        raise ValueError(f"Unknown provider '{selected}'.")
    else:
        required = required_by_provider[selected]

    require_env(*required)


def warn_env(*keys: str):
    """
    Warn if environment variables are missing but continue execution.
    Use this for tools that have an offline/mock fallback.

    Example:
        warn_env("OPENAI_API_KEY")
    """
    missing = [k for k in keys if not os.environ.get(k)]
    if missing:
        for k in missing:
            print(f"  WARNING: {k} not set - tool may run in offline/mock mode.")