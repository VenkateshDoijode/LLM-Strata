# CI/CD Operations

## Pipeline stages

The GitLab pipeline has three stages:

1. **scan:** Garak, DeepEval, RAGAS, PyRIT, and LLM Guard
2. **attack:** encoded, in-context, multilingual, tool injection, backdoor, and RAG security tests
3. **monitor:** LangFuse when its credentials are present

Human Red Team is interactive and is intentionally excluded from CI.

## Required variables

- `OPENAI_API_KEY` or credentials for the selected profile
- `ACTIVE_PROFILE` optional; defaults to `cost_optimized`
- `LANGFUSE_PUBLIC_KEY` and `LANGFUSE_SECRET_KEY` for monitoring

## Skip variables

Use these variables to reduce cost or skip unavailable application-specific tests:

```text
SKIP_RAGAS=true
SKIP_PYRIT=true
SKIP_LANGFUSE=true
SKIP_ENCODED=true
SKIP_MANY_SHOT=true
SKIP_MULTILINGUAL=true
SKIP_TOOL_INJECT=true
SKIP_BACKDOOR=true
SKIP_RAG_SECURITY=true
```

## Important CI semantics

Attack-stage jobs use `allow_failure: true`, so a job can be technically successful even when its report contains unsafe findings. Review artifacts rather than relying only on the GitLab job status.

The attack jobs store artifacts under `results/` for 30 days. Reports may contain sensitive prompts and responses; restrict artifact access and set a retention period appropriate for your data policy.

## Release gating

For a release gate, define explicit rules for:

- Any confirmed `UNSAFE` or `BREACHED` result
- Authorization failures
- PII leakage
- Tool-injection success
- Test `ERROR` or `UNKNOWN` rates
- Missing reports

Do not use a single aggregate pass count as the release decision. A layer with zero executed tests must not be treated as a passing layer.

## Local CI-equivalent checks

```text
python run_security.py --dry-run
python run_security.py --ci --skip-langfuse
python -m unittest discover -s agent_security/tests -v
```

Run a reduced smoke suite on pull requests and the complete matrix nightly or before release.
