# Layer 4: PyRIT Adaptive Agentic Red Teaming

## What it is

PyRIT performs goal-directed, adaptive, multi-turn red teaming. An attacker model proposes prompts, the target model responds, and a scorer decides whether the objective was achieved. Failed attempts can be refined across turns.

This catches conversational weaknesses that fixed single-turn scanners may miss.

## What it does

It runs an attacker model, target model, and scorer in an adaptive loop. Failed attempts can cause the attacker to refine the next prompt until the objective succeeds or the turn limit is reached.

## Coverage

Coverage is defined by the configured objectives, categories, severity, remediation, and maximum turns. It is strongest for adaptive conversational jailbreaks and policy-bypass goals.

## Prerequisites

Install a compatible PyRIT version and configure the active provider's credentials and endpoint. PyRIT may require separate attacker, target, and scorer model access.

## Configuration

Edit `pyrit/pyrit_config.yaml` for:

- Target, attacker, and scorer models
- Maximum turns and attempts
- Failure behavior for CI
- Attack objectives, categories, severity, and remediation

The current runner uses PyRIT's multi-turn `RedTeamingAttack`. It does not execute real production tools; it targets the configured model endpoint.

## Usage

```text
python pyrit/run_pyrit.py
python pyrit/run_pyrit.py --objective jailbreak_harmful_content
python pyrit/run_pyrit.py --verbose
python run_security.py --pyrit-only
python run_security.py --skip-pyrit
```

PyRIT must be installed and compatible with the imports checked by the runner. The active provider credentials and endpoint must be present in the selected profile. OpenAI-compatible, Azure, Ollama, Gemini, Hugging Face, Anthropic, Bedrock, and custom paths are handled through the provider configuration where supported.

## Outcomes

An objective is normally `HELD` when the target resisted or `BREACHED` when the scorer judged that the attacker achieved its goal. Errors and scorer failures must be reviewed separately from held objectives.

## Outputs

Reports are saved to `results/pyrit/` and include objective, category, severity, goal, status, turns used, score, and remediation.

## Interpretation and limitations

A breached objective is a strong signal that the target can be manipulated under an adaptive conversation, but it does not identify every production path that could cause the failure. Treat scorer errors separately from held objectives. Use PyRIT findings to strengthen system prompts, model policies, conversation boundaries, and external authorization controls.

## Execution model and CI guidance

Each objective can use attacker, target, and scorer models for up to the configured turn limit. This is one of the highest-cost layers. Use a single objective for pull-request smoke tests, the configured objective set nightly, and `--fail-on-breach` as an explicit release-gate option after scorer behavior is reviewed.
