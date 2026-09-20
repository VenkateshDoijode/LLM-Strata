# LLM Strata (AI LLM Safety and Security Testing Framework)

**An open-source, end-to-end framework for testing the security, safety, reliability, and behavioral robustness of LLM and AI applications.**

LLM Strata is a collection of independent security and safety test layers. The layers share provider profiles, credential loading, and report conventions, so you can switch the model under test with one setting and run every layer against it.

---

## Table of contents

- [Features](#features)
- [Test layers](#test-layers)
- [Compatibility](#compatibility)
- [Supported providers](#supported-providers)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Configuration reference](#configuration-reference)
- [Architecture](#architecture)
- [Data handling](#data-handling)
- [Threat model and scope](#threat-model-and-scope)
- [Production integration](#production-integration)
- [CI/CD](#cicd)
- [Project structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **14 test layers** covering vulnerability scanning, safety evaluation, RAG security, agentic security, adversarial red teaming, runtime protection, and production monitoring.
- **One profile file** (`profiles.yaml`) switches the model used by every module. No per-module YAML edits are needed.
- **Ten provider profiles** across cloud, enterprise, local, and private endpoints.
- **Separate model roles** for the target, judge, evaluator, attacker, and scorer, so you can use independent evaluator models for high-confidence assessments.
- **Simulation-first design.** Tool-injection and RAG-security tests run against simulated tool results and retrieved context, so no real tools or vector databases are touched.
- **CI-ready.** A `--ci` mode, skip variables, and a `--dry-run` mode make the pipeline easy to automate.
- **Cross-platform.** Runs on Windows and Linux.

---

## Test layers

| Layer | Name | Module | Guide | Purpose |
|---|---|---|---|---|
| 1 | Garak | `garak/run_garak.py` | [garak.md](garak/garak.md) | Vulnerability scanning and red teaming before deployment |
| 2 | DeepEval | `deepeval/run_deepeval.py` | [deepeval.md](deepeval/deepeval.md) | Safety testing: bias, toxicity, hallucination, PII, prompt injection |
| 3 | RAGAS | `ragas/run_ragas.py` | [ragas.md](ragas/ragas.md) | RAG pipeline quality and safety: context poisoning, faithfulness |
| 4 | PyRIT | `pyrit/run_pyrit.py` | [pyrit.md](pyrit/pyrit.md) | Multi-turn, goal-directed agentic red teaming |
| 5 | LLM Guard | `llm_guard/run_guard.py` | [llm-guard.md](llm_guard/llm-guard.md) | Runtime input/output scanner demonstration |
| 6 | LangFuse | `langfuse/run_langfuse.py` | [langfuse.md](langfuse/langfuse.md) | Production monitoring, tracing, and scoring |
| 7 | Human Red Team | `human_redteam/run_redteam.py` | [human-redteam.md](human_redteam/human-redteam.md) | Interactive manual attack sessions |
| 8 | Encoded Attacks | `encoded_attacks/run_encoded_attacks.py` | [encoded-attacks.md](encoded_attacks/encoded-attacks.md) | Base64, ROT13, hex, Morse, leetspeak, homoglyphs, and similar obfuscation |
| 9 | Many-Shot Jailbreaks | `many_shot/run_many_shot.py` | [many-shot.md](many_shot/many-shot.md) | In-context conditioning: pure-harmful, gradual-escalation, and camouflaged strategies |
| 10 | Multilingual Attacks | `multilingual/run_multilingual.py` | [multilingual.md](multilingual/multilingual.md) | Cross-language safety bypass (Arabic, Chinese, Russian, Hindi, Spanish, French, German, and more) |
| 11 | Tool-Call Injection | `tool_inject/run_tool_inject.py` | [tool-injection.md](tool_inject/tool-injection.md) | Indirect prompt injection through search, file, database, email, and calendar results |
| 12 | Backdoor Triggers | `backdoor/run_backdoor.py` | [backdoor.md](backdoor/backdoor.md) | Trojan phrase amplification (DAN, authority, and roleplay triggers) |
| 13 | RAG Security | `rag_security/run_rag_security.py` | [rag-security.md](rag_security/rag-security.md) | Vector and embedding weaknesses (OWASP LLM08) |
| 14 | Agent Security | `agent_security/run_agent_security.py` | [agent-security.md](agent_security/agent-security.md) | Multi-turn attacks, tool authorization, and memory isolation |

---

## Compatibility

| Item | Support |
|---|---|
| Operating systems | Windows and Linux |
| Python | 3.9 or later |
| API style | OpenAI-compatible clients, plus LiteLLM for Anthropic and AWS Bedrock |
| Local models | Ollama and any OpenAI-compatible server |
| CI systems | GitLab CI (pipeline definition included); other systems can call `run_security.py --ci` |

---

## Supported providers

Every provider is configured as a profile in `profiles.yaml`.

| Profile | Provider value | Default model | Required environment variables | Notes |
|---|---|---|---|---|
| `production` | `openai` | `gpt-4o` | `OPENAI_API_KEY` | Real-world security assessments |
| `cost_optimized` (default) | `openai` | `gpt-4o-mini` | `OPENAI_API_KEY` | Quick scans and CI/CD |
| `azure` | `azure` | Your deployment name | `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT` | Enterprise, data residency, compliance |
| `local` | `ollama` | `llama3.2` | None (optional `OLLAMA_BASE_URL`) | No API key needed; run `ollama run llama3.2` first |
| `private_compatible` | `openai_compatible` | `local-model` | `OPENAI_COMPATIBLE_API_KEY` if the endpoint is protected | Private or on-premises OpenAI-compatible endpoint |
| `gemini` | `gemini` | `gemini-2.0-flash` | `GEMINI_API_KEY` | Uses Google's OpenAI-compatible endpoint |
| `anthropic` | `anthropic` | `claude-opus-4-5` | `ANTHROPIC_API_KEY` | Via LiteLLM |
| `bedrock` | `bedrock` | `anthropic.claude-3-5-sonnet-20241022-v2:0` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION_NAME` | Via LiteLLM and `boto3` |
| `huggingface` | `huggingface` | `meta-llama/Llama-3.1-70B-Instruct` | `HF_TOKEN` | The model must have the Inference API enabled |
| `redteam` | `openai` | `gpt-4o` (target and attacker) | `OPENAI_API_KEY` | Strongest available models for maximum coverage |

Supported `provider` values: `openai`, `azure`, `ollama`, `openai_compatible`, `gemini`, `huggingface`, `anthropic`, `bedrock`.

---

## Quick start

```bash
# 1. Clone the repository
git clone https://github.com/VenkateshDoijode/LLM-Strata.git
cd LLM-Strata

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure credentials (see Configuration reference)
#    Create a .env file or export the variables for your chosen provider
export OPENAI_API_KEY="your-key-here"

# 4. Preview the pipeline without executing anything
python run_security.py --dry-run

# 5. Run the full pipeline
python run_security.py
```

On Windows PowerShell, set variables with `$env:OPENAI_API_KEY="your-key-here"`.

If `OPENAI_API_KEY` is not set, Garak and LLM Guard fall back to mock or offline mode.

---

## Usage

### Other options

| Flag | Description |
|---|---|
| `--garak-depth {quick,standard,all}` | Garak probe depth. The default is `standard`; `all` is slow. |
| `--dry-run` | Print all steps without executing them |
| `--ci` | CI mode: skip interactive tools and exit with code 1 if any layer fails |

Human Red Team is interactive and never runs as part of the default pipeline.

---

## Configuration reference

### Configuration precedence

Settings are resolved in this order, from highest to lowest priority:

1. `ACTIVE_PROFILE` environment variable
2. `active_profile` in `profiles.yaml`
3. Each module's own YAML file
4. Code defaults

### Selecting a profile

```bash
# Change active_profile in profiles.yaml, or override at runtime:
export ACTIVE_PROFILE=redteam          # Linux and macOS
$env:ACTIVE_PROFILE="redteam"          # Windows PowerShell

python run_security.py
```

### Profile fields

| Field | Description |
|---|---|
| `provider` | Provider type (see [Supported providers](#supported-providers)) |
| `model` | The model under test, used by all modules |
| `judge_model` | RAGAS: faithfulness and relevancy judge |
| `evaluator_model` | DeepEval: safety metric judge |
| `attacker_model` | PyRIT: generates adversarial prompts |
| `scorer_model` | PyRIT and LangFuse: judges attacks and scores traces |
| `base_url` | `openai_compatible` only: endpoint URL, for example `http://localhost:8000/v1` |
| `api_key_required` | `openai_compatible` only: set to `true` for a protected endpoint |

PyRIT uses separate attacker and scorer roles. Set them independently per profile for the best red-team coverage. For high-confidence assessments, use evaluator models that are independent of the target model, and record the profile used for every run.

### Example profile

```yaml
active_profile: cost_optimized

profiles:
  redteam:
    provider: openai
    model: gpt-4o              # strongest model as target (hardest test)
    judge_model: gpt-4o-mini
    evaluator_model: gpt-4o-mini
    attacker_model: gpt-4o     # strongest attacker for maximum coverage
    scorer_model: gpt-4o-mini
```

### Skip variables (CI)

Set these variables to reduce cost or to skip application-specific tests that do not apply to you:

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

---

## Architecture

### Pipeline phases

**1. Pre-deployment discovery.** These layers send controlled prompts or simulated contexts to a target model: Garak, DeepEval, RAGAS, PyRIT, Encoded Attacks, In-Context Attacks, Multilingual Attacks, Backdoor Triggers, RAG Security, Tool Injection, and Agent Security model tests.

**2. Runtime and operational controls.**

- **LLM Guard:** local input/output scanning demonstration
- **Agent Security:** policy primitives that can be embedded in an application
- **Tool Injection:** simulated agent boundary testing

These tests do not automatically protect a separate production application. The production request path must explicitly call the controls.

**3. Production monitoring.**

- **LangFuse:** traces, scores, and drift monitoring for instrumented requests
- **Human Red Team:** periodic manual testing and review

### Shared execution flow

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

The target model and evaluator model may be the same by default. For high-confidence assessments, use independent evaluator models and record the profile used for every run.

### Trust boundaries

1. **Configuration boundary:** YAML files are test instructions, not runtime authorization policy.
2. **Provider boundary:** prompts and responses may leave the local environment and be retained by the provider.
3. **Evaluator boundary:** an evaluator model provides a judgment; it is not an authoritative security control.
4. **Report boundary:** result files may contain harmful prompts, PII, secrets accidentally returned by a model, and full responses.
5. **Production boundary:** the test harness does not automatically authorize tools, isolate memory, or protect a real RAG store.

### Simulation versus production connectivity

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

### Design principle

A model response is untrusted input. Security decisions must be enforced by application code, identity and access controls, tool schemas, data-layer authorization, and monitoring outside the model.

---

## Data handling

LLM Strata sends adversarial prompts to models and stores the responses. Plan for that before you run it against real systems.

**What leaves your environment**

- Prompts, simulated contexts, and model responses are sent to the configured provider. The provider may retain or process them according to its own policy. Use the `local` or `private_compatible` profiles, or Azure with your data-residency settings, when data must stay within your control.
- LangFuse traces are sent to the configured LangFuse service. Mask secrets and unnecessary PII before instrumenting real traffic.

**What is stored locally**

- Reports are written under `results/<layer>/` (for example `results/rag_security/`, `results/tool_inject/`, and `results/ragas/`).
- Reports can contain harmful prompts, PII from test fixtures, secrets that a model returned by accident, and full model responses. Treat report files as sensitive.
- Human red-team session logs are written to `results/human_redteam/`.

---

## Threat model and scope

### In scope

The framework evaluates LLM-powered applications before and after deployment. It focuses on model behavior, prompt handling, RAG context, agent tools, memory policies, runtime scanning, and operational monitoring.

### Protected assets

- System and developer instructions
- User prompts and conversation history
- Personal, financial, health, and confidential business data
- Tool permissions and side-effecting actions
- Agent memory and tenant boundaries
- RAG documents, embeddings, and retrieval metadata
- Model and provider credentials
- Security reports and LangFuse traces
- Application availability and cost budget

### Threat actors

- A malicious or compromised end user
- An attacker who controls a document, email, web page, database row, or calendar entry
- A user attempting privilege escalation or authority impersonation
- A malicious fine-tuning or training-data contributor
- A compromised or misconfigured provider endpoint
- An evaluator or scanner failure that causes a team to misread results

### Threat coverage mapping

| Threat | Primary layers |
|---|---|
| Direct jailbreak and unsafe output | Garak, DeepEval, PyRIT |
| Prompt injection | Garak, LLM Guard, Tool Injection, RAG Security |
| Multi-turn escalation | PyRIT, Agent Security, Human Red Team |
| In-context conditioning | Many-Shot Jailbreaks |
| Encoding and obfuscation | Encoded Attacks, Garak red-team probes |
| Cross-language evasion | Multilingual Attacks |
| Trigger sensitivity | Backdoor Triggers |
| PII output leakage | DeepEval, RAGAS, LLM Guard, RAG Security |
| Tool privilege misuse | Agent Security, Tool Injection |
| Memory isolation | Agent Security |
| Production drift | LangFuse |

### Trust assumptions

The following are untrusted unless explicitly validated:

- User prompts
- Model outputs
- Retrieved documents
- Tool results
- Assistant-generated tool arguments
- Human-entered red-team prompts
- Test configuration values supplied from outside source control

---

## Production integration

The runners find weaknesses; they do not automatically protect a separate application. Production enforcement must be implemented in the application's request, tool, data, and response paths.

### Recommended request flow

```text
authenticate user
  -> validate tenant and request
  -> scan or classify input
  -> build trusted system/developer context
  -> call model
  -> validate structured output
  -> authorize requested tool independently
  -> require approval for high-impact actions
  -> execute tool with scoped credentials
  -> scan/redact response
  -> trace security metadata without secrets
```

### Tool authorization

Never use the model's claim that a tool is allowed as the authorization decision. Use an external policy evaluator with:

- Explicit role/tool allowlists
- Deny-by-default behavior
- Tenant and resource checks
- Schema and argument validation
- Approval for destructive, external, financial, or export actions
- Audit logging
- Fail-closed behavior when policy is missing or unavailable

The Agent Security layer provides local policy regression tests; production code must enforce the same policy at the actual tool boundary.

### Prompt and tool-result separation

Treat retrieved documents, web pages, files, emails, database rows, and tool results as untrusted data. Delimit them, label their trust level, and do not allow their contents to grant permissions or override system policy. Use the Tool Injection and RAG Security modules to test this boundary.

### Runtime scanning

LLM Guard is a local scanner demonstration. A production integration should define what happens when each scanner triggers:

- Block the request
- Redact sensitive data
- Ask for confirmation
- Route to human review
- Log a privacy-preserving event

Benchmark latency, false positives, false negatives, Unicode behavior, multilingual behavior, and scanner failure handling before deployment.

### Memory and RAG

- Scope memory by authenticated tenant and user.
- Authenticate trusted writes.
- Apply data-layer ACLs before retrieval.
- Track document provenance.
- Never treat retrieved text as an instruction with higher priority than policy.
- Test deletion, reset, export, and cross-tenant access paths.

Recommended RAG controls include document provenance, tenant/ACL-aware retrieval, content sanitization, prompt/data separation, chunk-level trust labels, output filtering, and post-retrieval authorization. A trusted application user does not make every retrieved document trusted.

### Monitoring

Use LangFuse or another approved telemetry system to monitor production behavior, but mask secrets and unnecessary PII. Monitoring detects and helps investigate failures; it does not prevent unauthorized actions by itself.

---

## CI/CD

The included GitLab pipeline has three stages:

1. **scan:** Garak, DeepEval, RAGAS, PyRIT, and LLM Guard
2. **attack:** encoded, in-context, multilingual, tool injection, backdoor, and RAG security tests
3. **monitor:** LangFuse, when its credentials are present

Human Red Team is interactive and is intentionally excluded from CI.

### Release gating

For a release gate, define explicit rules for:

- Any confirmed `UNSAFE` or `BREACHED` result
- Authorization failures
- PII leakage
- Tool-injection success
- Test `ERROR` or `UNKNOWN` rates
- Missing reports

Do not use a single aggregate pass count as the release decision. A layer with zero executed tests must not be treated as a passing layer.

### Local CI-equivalent checks

```bash
python run_security.py --dry-run
python run_security.py --ci --skip-langfuse
python -m unittest discover -s agent_security/tests -v
```

Run a reduced smoke suite on pull requests and the complete matrix nightly or before release. Each case calls the target model and, for some layers, several scoring components, so a full run is more expensive than a simple prompt test. Use `--scenario` for pull-request smoke tests, poisoned-only or targeted cases for development, and the complete corpus nightly or before release. Triage RAGAS quality failures separately from retrieval-security failures.

---

## Project structure

```text
LLM-Strata/
├── run_security.py          # Main pipeline runner
├── profiles.yaml            # Model profile selection
├── profile_loader.py        # Profile loading
├── env_loader.py            # Credential and .env loading
├── client_factory.py        # OpenAI-compatible client creation
├── ragas_config.yaml        # RAGAS configuration
├── requirements.txt         # Python dependencies
├── setup.py                 # Package setup
├── gitlab-ci.yml            # GitLab CI pipeline definition
├── garak/                   # Layer 1
├── deepeval/                # Layer 2
├── ragas/                   # Layer 3
├── pyrit/                   # Layer 4
├── llm_guard/               # Layer 5
├── langfuse/                # Layer 6
├── human_redteam/           # Layer 7
├── encoded_attacks/         # Layer 8
├── many_shot/               # Layer 9
├── multilingual/            # Layer 10
├── tool_inject/             # Layer 11
├── backdoor/                # Layer 12
├── rag_security/            # Layer 13
├── agent_security/          # Layer 14
├── docs/                    # Threat model, architecture, CI/CD, triage, integration
└── results/                 # Generated reports (do not commit)
```

---

## Contributing

Contributions are welcome. Fork the repository, make your change, and open a pull request with a short description of what you changed and why.

---

## License

LLM Strata is open source. See the `LICENSE` file for the license terms.

---

## Author

Created and maintained by [Venkateshwara Doijode](https://github.com/VenkateshDoijode).
