"""
client_factory.py - Multi-provider LLM client factory for LLM Strata
Author : Venkateshwara Doijode
Project: LLM Strata - End-to-End LLM Security & Safety Framework

Returns an OpenAI-compatible client for the active provider.
All clients expose the same interface:
   client.chat.completions.create(model=..., messages=[...])
   response.choices[0].message.content

Supported providers (set in profiles.yaml > provider):
  openai            - OpenAI API (default)         requires: OPENAI_API_KEY
  azure             - Azure OpenAI                 requires: AZURE_OPENAI_API_KEY, AZURE_OPENAI_ENDPOINT
  ollama            - Local via Ollama              requires: Ollama running on localhost
  gemini            - Google Gemini (OpenAI-compatible)  requires: GEMINI_API_KEY
  anthropic         - Anthropic Claude via LiteLLM  requires: ANTHROPIC_API_KEY + pip install litellm
  bedrock           - AWS Bedrock via LiteLLM       requires: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION_NAME + pip install litellm
  huggingface       - Hugging Face Inference API    requires: HF_TOKEN
  openai_compatible - Private/on-prem OpenAI-compatible endpoint

Usage in any run_*.py:
   from client_factory import get_client, get_provider
   client = get_client()
   response = client.chat.completions.create(model=model, messages=[...])
"""

import os

from profile_loader import load_profile


def get_provider() -> str:
    """Return the provider from the active profile."""
    return load_profile().get("provider", "openai")


def get_client(provider: str | None = None):
    """Return an OpenAI-compatible client for the given (or active profile) provider.

    Args:
        provider: Override the provider. If None, reads from active profile.

    Returns:
        A client object with .chat.completions.create() interface.

    Raises:
        ValueError: If the provider is unknown.
        KeyError: If required environment variables are missing.
    """
    profile = load_profile()
    if provider is None:
        provider = get_provider()

    provider = provider.lower()

    if provider == "openai":
        from openai import OpenAI
        return OpenAI()

    elif provider == "azure":
        from openai import AzureOpenAI
        return AzureOpenAI(
            api_key=os.environ["AZURE_OPENAI_API_KEY"],
            azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
            api_version=os.environ.get("AZURE_OPENAI_API_VERSION", "2024-12-01-preview"),
        )

    elif provider == "ollama":
        from openai import OpenAI
        base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
        return OpenAI(base_url=base_url, api_key="ollama")

    elif provider == "gemini":
        from openai import OpenAI
        return OpenAI(
            base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
            api_key=os.environ["GEMINI_API_KEY"],
        )

    elif provider == "huggingface":
        from openai import OpenAI
        return OpenAI(
            base_url="https://api-inference.huggingface.co/v1/",
            api_key=os.environ["HF_TOKEN"],
        )

    elif provider in ("openai_compatible", "custom"):
        from openai import OpenAI
        base_url = profile.get("base_url") or os.environ.get("OPENAI_COMPATIBLE_BASE_URL")
        if not base_url:
            raise ValueError(
                "OPENAI_COMPATIBLE_BASE_URL or profiles.yaml base_url is required "
                "for the openai_compatible provider."
            )
        api_key = os.environ.get(profile.get("api_key_env", "OPENAI_COMPATIBLE_API_KEY"), "not-needed")
        return OpenAI(base_url=base_url, api_key=api_key)

    elif provider == "anthropic":
        return _LiteLLMClient(prefix="anthropic/")

    elif provider == "bedrock":
        return _LiteLLMClient(prefix="bedrock/")

    else:
        supported = [
            "openai", "azure", "ollama", "gemini", "huggingface",
            "anthropic", "bedrock", "openai_compatible",
        ]
        raise ValueError(
            f"Unknown provider '{provider}'. Supported: {supported}\n"
            f"Set provider in profiles.yaml under your active profile."
        )


# --- LiteLLM wrapper - OpenAI-compatible shim for Anthropic, Gemini ---------------

class _LiteLLMCompletions:
    def __init__(self, prefix: str):
        self._prefix = prefix

    def create(self, model: str, messages: list, **kwargs):
        try:
            import litellm
        except ImportError:
            raise ImportError(
                "litellm is required for Anthropic/Gemini providers.\n"
                "Run: pip install litellm"
            )
        full_model = f"{self._prefix}{model}" if not model.startswith(self._prefix) else model
        return litellm.completion(model=full_model, messages=messages, **kwargs)


class _LiteLLMChat:
    def __init__(self, prefix: str):
        self.completions = _LiteLLMCompletions(prefix)


class _LiteLLMClient:
    """OpenAI-compatible shim around LiteLLM for non-OpenAI providers.

    Exposes client.chat.completions.create() and returns responses with
    response.choices[0].message.content - identical to the OpenAI SDK.
    """

    def __init__(self, prefix: str = ""):
        self.chat = _LiteLLMChat(prefix)
