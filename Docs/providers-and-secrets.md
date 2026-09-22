# Providers and Secrets

## Profile selection

Use `profiles.yaml` to select the target, evaluator, attacker, judge, and scorer models. Set `ACTIVE_PROFILE` for a one-run override:

```powershell
$env:ACTIVE_PROFILE = "redteam"
python run_security.py
```

The profile loader caches the active profile for the current Python process. Start a new process after changing the environment variable.

## Environment precedence

The project loads `.env` values only when the operating-system environment does not already define the key. This gives CI and production variables priority over local files.

Recommended order:

1. CI or system environment variables
2. Local `.env` for development
3. Never hard-code credentials in Python or YAML

## Provider matrix

| Provider | Profile provider | Required credentials |
|---|---|---|
| OpenAI | `openai` | `OPENAI_API_KEY` |
| Azure OpenAI | `azure` | `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT` |
| Ollama | `ollama` / `local` | Ollama service; no cloud key by default |
| Gemini | `gemini` | `GEMINI_API_KEY` |
| Hugging Face | `huggingface` | `HF_TOKEN` |
| Anthropic | `anthropic` | `ANTHROPIC_API_KEY` and LiteLLM |
| Bedrock | `bedrock` | AWS credentials, region, LiteLLM, and boto3 |
| Private endpoint | `openai_compatible` | Base URL and optional API key |

Garak runs in a separate environment and uses its own target type/model settings. LangFuse additionally requires LangFuse public and secret keys. 

## Adding a Proprietary Cloud LLM

Three paths depending on the provider's API format:

### Path 1 — OpenAI-compatible endpoint (2-minute addition)

Most modern enterprise LLMs (vLLM, TGI, Together AI, Fireworks AI, Perplexity, xAI/Grok, Databricks, etc.) expose an OpenAI-compatible `/v1/chat/completions` endpoint.

**Step 1 — Add an `elif` block inside the `get_client()` function in `client_factory.py`, just before the final `else` block:**
```python
def get_client(provider: str | None = None):
    ...
    elif provider == "bedrock":          # last existing provider
        return _LiteLLMClient(prefix="bedrock/")

    elif provider == "your_provider":    # ← add here
        from openai import OpenAI
        return OpenAI(
            base_url="https://your-company-llm-endpoint.com/v1",
            api_key=os.environ["YOUR_API_KEY"],
        )

    else:                                # keep this last
        supported = [..., "your_provider"]   # ← also add here
        raise ValueError(...)
```

**Step 2 — Add a profile in `profiles.yaml`:**
```yaml
  your_provider:
    provider: your_provider
    model: your-model-name
    judge_model: your-model-name
    evaluator_model: your-model-name
    attacker_model: your-model-name
    scorer_model: your-model-name
```

**Step 3 — Add the API key in `.env`:**
```env
YOUR_API_KEY=...
```

**Step 4 — Activate the profile:**
```yaml
# profiles.yaml
active_profile: your_provider
```

Done — the client-based security modules use the active provider profile. Garak and some integrations retain provider-specific configuration.

### Path 2 — LiteLLM-supported provider (100+ providers)

If your provider is listed at [docs.litellm.ai/docs/providers](https://docs.litellm.ai/docs/providers) (IBM watsonx, Cohere, AI21, Vertex AI, Snowflake Cortex, etc.), LiteLLM is already wired in.

**Step 1 — Add an `elif` block inside the `get_client()` function in `client_factory.py`, just before the final `else` block:**
```python
def get_client(provider: str | None = None):
    ...
    elif provider == "bedrock":          # last existing provider
        return _LiteLLMClient(prefix="bedrock/")

    elif provider == "your_provider":    # ← add here
        return _LiteLLMClient(prefix="your_provider/")

    else:                                # keep this last
        supported = [..., "your_provider"]
        raise ValueError(...)
```

The prefix must match the LiteLLM provider prefix from their docs (e.g. `watsonx/`, `cohere/`, `vertex_ai/`).

**Step 2 — Add a profile in `profiles.yaml`:**
```yaml
  your_provider:
    provider: your_provider
    model: your-model-name          # e.g. ibm/granite-13b-instruct-v2
    judge_model: your-model-name
    evaluator_model: your-model-name
    attacker_model: your-model-name
    scorer_model: your-model-name
```

**Step 3 — Add credentials in `.env`** (varies by provider, see LiteLLM docs):
```env
# Example for watsonx
WATSONX_API_KEY=...
WATSONX_URL=https://us-south.ml.cloud.ibm.com
WATSONX_PROJECT_ID=...
```

**Step 4 — Install litellm if not already:**
```bash
pip install litellm
```

## Setup

```text
python setup.py
copy .env.example .env
python run_security.py --dry-run
```

Use the local provider profile for offline model testing where supported, but confirm that the selected model exposes the OpenAI-compatible chat-completions interface.

## Secret handling

- Mark CI variables as masked and protected.
- Do not include `.env`, API keys, provider endpoints with embedded credentials, or raw reports in commits.
- Rotate any credential that appears in a prompt, response, trace, or report.
- Restrict access to `results/` and LangFuse projects.
- Avoid sending real customer data to red-team providers.
