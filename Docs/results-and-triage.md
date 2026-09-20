# Results and Triage

## Outcome vocabulary

| Status | Meaning |
|---|---|
| `PASS` / `SAFE` | The model or control met the configured expectation |
| `FAIL` / `UNSAFE` | The model or control violated the configured expectation |
| `BREACHED` | An adaptive or human red-team objective succeeded |
| `BORDERLINE` | A human reviewer observed partial or ambiguous compliance |
| `UNKNOWN` | The evaluator did not return a reliable verdict |
| `ERROR` | The test infrastructure or request failed |
| `SKIPPED` | The test was intentionally not executed |

`UNKNOWN`, `ERROR`, and `SKIPPED` are not evidence of safety.

## Triage workflow

1. Confirm the exact command, active profile, model, commit, and configuration.
2. Determine whether the result is a model failure, policy failure, scanner failure, or evaluator failure.
3. Preserve the minimal prompt/response evidence needed for reproduction.
4. Re-run the smallest reproducer with verbose output.
5. Test the remediation against the original case and related variants.
6. Add a regression fixture before closing the finding.
7. Record severity, owner, remediation, and retest status.

## Severity guidance

- **Critical:** unauthorized tool action, credential/data exfiltration, cross-tenant memory access, or confirmed high-impact harmful output
- **High:** repeatable prompt injection, PII leakage, policy bypass, or trigger amplification
- **Medium:** borderline behavior, limited category bypass, or scanner gap with a safe model response
- **Low:** false positive, evaluator ambiguity, logging issue, or low-impact quality regression

## Evidence requirements

A finding should include:

- Layer and test ID
- Active profile and model roles
- Exact configuration revision
- Prompt or simulated context identifier
- Target response excerpt, protected as sensitive
- Evaluator verdict and whether it was independent
- Reproduction command
- Recommended control and regression test

## Common interpretation errors

- A clean scan is not a security certification.
- A scanner pass does not authorize a tool call.
- A high RAG faithfulness score does not prove retrieved content is trustworthy.
- A `SAFE` result from an evaluator does not prove the target never produced unsafe content.
- An `ERROR` should not be counted as a safe response.
