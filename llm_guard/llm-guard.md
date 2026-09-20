# Layer 5: LLM Guard Runtime Scanning

## What it is

LLM Guard is the runtime protection demonstration. It scans inputs before a model call and outputs after a model call for prompt injection, PII, banned topics or substrings, toxicity, sensitivity, and relevance.

The repository contains a self-contained pure-Python implementation so the demo can run without the archived external scanner package.

## What it does

It scans a request before the model call and scans the model response afterward. Depending on the scanner, it can block, redact, anonymize, or score content.

## Coverage

Coverage is determined by the configured input and output scanners. The current implementation is strongest for known patterns, PII formats, banned terms, basic injection phrases, toxicity keywords, and relevance checks.

## Scanners

Input-side examples include:

- Prompt injection detection
- PII anonymization
- Banned topics
- Banned substrings
- Toxicity

Output-side examples include:

- PII restoration or redaction workflow
- Sensitive-content detection
- Toxicity
- Relevance

## Prerequisites

Python and PyYAML are sufficient for local scanning. A provider credential is only needed when the demo uses a real target model instead of mock mode.

## Configuration

Edit `llm_guard/guard_config.yaml` to change test cases and scanner settings.

## Usage

```text
python llm_guard/run_guard.py
python llm_guard/run_guard.py --interactive
python run_security.py --guard-only
```

Interactive mode is useful for manually checking scanner behavior against a single prompt. The default demo exercises the configured test corpus.

## Outcomes

A scanner can pass, block, redact, anonymize, or assign a score depending on its type. Review the exact scanner, input, output, and reason. A pass means only that the configured heuristic did not trigger; it does not authorize a tool call or prove semantic safety.

## Outputs

Audit results are written to `results/llm_guard/`.

## Accuracy and deployment guidance

The current implementation uses regular expressions and word lists, not a trained semantic classifier. Its accuracy is therefore limited by pattern coverage and language variation. It should be treated as a baseline or defense-in-depth component. Production deployment should add authenticated tool authorization, structured parsing, rate limits, data-loss prevention, and tests against the exact application. Review the anonymization/deanonymization flow carefully: restoring masked values in output can reintroduce sensitive data unless the application explicitly authorizes it.

Do not treat a scanner pass as permission to execute a tool. Scanners should be one signal in a fail-closed policy pipeline.

## Execution model and CI guidance

The demo is local and inexpensive; it can run on every pull request without an API key when mock mode is used. Production integration requires a measured latency budget, scanner-failure behavior, and tests for false positives and false negatives. The regex and word-list implementation should not be presented as a semantic safety classifier.
