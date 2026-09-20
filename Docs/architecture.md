# Architecture and Data Flow

## Purpose

LLM Strata is a collection of independent security and safety runners coordinated by `run_security.py`. The runners share provider/profile utilities and report conventions, but they do not form one production enforcement service.

## Pipeline phases

### 1. Pre-deployment discovery

These layers send controlled prompts or simulated contexts to a target model:

- Garak
- DeepEval
- RAGAS
- PyRIT
- Encoded Attacks
- In-Context Attacks
- Multilingual Attacks
- Backdoor Triggers
- RAG Security
- Tool Injection
- Agent Security model tests

### 2. Runtime and operational controls

- **LLM Guard:** local input/output scanning demonstration
- **Agent Security:** policy primitives that can be embedded in an application
- **Tool Injection:** simulated agent boundary testing

These tests do not automatically protect a separate production application. The production request path must explicitly call the controls.

### 3. Production monitoring

- **LangFuse:** traces, scores, and drift monitoring for instrumented requests
- **Human Red Team:** periodic manual testing and review

## Shared execution flow

```text
module YAML configuration
        |
profiles.yaml + ACTIVE_PROFILE
        |
env_loader.py loads credentials
        |
client_factory.py creates an OpenAI-compatible client
        |
target model / evaluator / attacker / scorer
        |
layer-specific test runner
        |
JSON report, console result, or LangFuse trace
```

The target model and evaluator model may be the same by default. For high-confidence assessment, use independent evaluator models and record the profile used for every run.

## Trust boundaries

1. **Configuration boundary:** YAML files are test instructions, not runtime authorization policy.
2. **Provider boundary:** prompts and responses may leave the local environment and be retained by the provider.
3. **Evaluator boundary:** an evaluator model provides a judgment; it is not an authoritative security control.
4. **Report boundary:** result files may contain harmful prompts, PII, secrets accidentally returned by a model, and full responses.
5. **Production boundary:** the test harness does not automatically authorize tools, isolate memory, or protect a real RAG store.

## Simulation versus production connectivity

| Area | Current behavior |
|---|---|
| Tool Injection | Simulates tool results; does not call real tools |
| RAG Security | Simulates retrieved context; does not connect to a vector database |
| Agent Security memory | Uses an in-memory test model |
| Agent Security authorization | Evaluates local policy data |
| Human Red Team | Sends real prompts to the configured target model |
| LLM Guard | Runs local scanners and may use a mock response |
| LangFuse | Connects to the configured LangFuse service |
| Garak | Runs Garak in its isolated environment |

## Design principle

A model response is untrusted input. Security decisions must be enforced by application code, identity and access controls, tool schemas, data-layer authorization, and monitoring outside the model.
