# Layer 14: Agent Security

## What it is

Agent security protects LLM applications that do more than return text. An agent may maintain conversation state, call tools, access external data, and write to memory. Those capabilities create security risks that are not covered by ordinary single-turn model safety tests.

This layer is a local security test harness. It does not connect to or execute real production tools. It validates the expected behavior of multi-turn handling, tool authorization policies, and agent memory rules before those controls are deployed.

## What it does

The runner loads `agent_security/agent_security_config.yaml`, executes the configured test cases, creates a JSON report, and returns a non-zero exit code when any configured test fails.

It has three independent sections:

1. **Multi-turn attack resistance** — sends scripted conversations to a chat-completions-compatible model and checks whether unsafe indicators or patterns appear in the combined responses.
2. **Tool authorization** — evaluates whether a role may use a requested tool under an explicit allowlist, denylist, and approval policy.
3. **Memory security** — tests namespace isolation, trusted-write requirements, and reset behavior using a small in-memory policy model.

## Coverage

### Multi-turn attack coverage

The configured cases can test:

- Authority or administrator impersonation
- Attempts to escalate instruction priority
- Persistent unsafe instructions across turns
- Unsafe behavior that only appears after context has accumulated
- Exact unsafe indicators and regular-expression patterns

The runner records every turn, the model output, whether the attack was blocked, and whether the case passed.

### Tool authorization coverage

The authorization evaluator verifies:

- Unknown roles are denied
- Explicitly denied tools are rejected
- Tools outside a role's `allowed_tools` list are rejected
- Missing or empty allowlists fail closed
- Approval-required tools are denied without approval
- Approved tools are allowed only when they are also allowlisted

Example policy shape:

```yaml
tool_policies:
  analyst:
    allowed_tools:
      - search_documents
      - get_report
    denied_tools:
      - delete_record
    approval_required:
      - export_report
```

The model is not trusted to make the final authorization decision. The policy evaluator must run independently of the model response.

### Memory security coverage

The memory tests cover:

- Isolation between scopes such as `user-a` and `user-b`
- Trusted writes
- Rejection of untrusted writes by default
- Expected absence of rejected values
- Resetting a scope and clearing stored values

The included `AgentMemoryStore` is a test model. It does not prove that a production database, vector store, cache, or agent framework provides equivalent isolation.

## Prerequisites

Python and PyYAML are required. Tool-authorization, memory, and dry-run tests are local; multi-turn tests additionally require provider credentials.

## Configuration

Edit `agent_security/agent_security_config.yaml` to configure:

- `model` and `max_tokens`
- `multi_turn_attacks`
- `system_prompt`, turns, unsafe indicators, and unsafe patterns
- `memory_policy.allow_untrusted_writes`
- Role policies with `allowed_tools`, `denied_tools`, and `approval_required`
- `tool_authorization_tests` and `memory_tests`

Keep authorization policies explicit. Do not use an empty or missing `allowed_tools` list to mean unrestricted access; the evaluator intentionally treats that state as deny-by-default.

## Usage

Run every agent-security section:

```text
python agent_security/run_agent_security.py
```

Run only one section:

```text
python agent_security/run_agent_security.py --multi-turn-only
python agent_security/run_agent_security.py --tool-auth-only
python agent_security/run_agent_security.py --memory-only
```

Preview the configured test counts without calling an LLM:

```text
python agent_security/run_agent_security.py --dry-run
```

Print every test result and failure detail:

```text
python agent_security/run_agent_security.py --verbose
```

Run it through the full pipeline:

```text
python run_security.py --agent-security-only
```

The multi-turn section requires credentials for the active provider. Tool authorization and memory tests run locally and do not require an LLM. The full runner requires the YAML dependency and the repository's normal Python environment.

## Outcomes

The report is written as a timestamped JSON file under `results/agent_security/`.

### Multi-turn result

A successful safety result generally contains:

```json
{
  "attack_blocked": true,
  "passed": true,
  "turns": []
}
```

`attack_blocked: false` or `passed: false` means the combined model output matched an unsafe indicator or pattern, or that the case encountered an error.

### Authorization result

Each authorization case includes:

- `role`
- `tool`
- `expected_allowed`
- `actual_allowed`
- `reason`
- `passed`

Typical denial reasons include `unknown_role`, `tool_denied_by_policy`, `tool_not_allowlisted`, and `approval_required`.

### Memory result

Each memory test includes operations with:

- Action: `write`, `read`, or `reset`
- Scope and key
- Actual result
- Expected result
- Per-operation `passed` value

A test passes only when all of its configured operations produce the expected result.

## How to interpret outcomes

| Outcome | Meaning | Recommended action |
|---|---|---|
| `passed: true` | The configured behavior matched the expected security policy | Keep the case as a regression test |
| `passed: false` in multi-turn testing | The model produced a configured unsafe indicator or the runner encountered an error | Review the response and strengthen the boundary or handling |
| `actual_allowed: true` unexpectedly | A role received a tool permission it should not have | Treat as an authorization vulnerability |
| `actual_allowed: false` unexpectedly | A valid workflow was blocked | Review the policy and approval configuration |
| Memory isolation failure | One scope could read another scope's value | Stop deployment until tenant/user isolation is fixed |
| `ERROR` or exception | The test did not produce a reliable security result | Fix the test or environment; do not count it as safe |

## What it does not cover

This layer does not prove:

- Real production tool implementations are safe
- Tool arguments are validated
- An external identity provider assigned the correct role
- A production database or vector store isolates tenants
- Retrieved documents are trustworthy
- Runtime scanners catch every attack
- The model cannot be manipulated outside the configured cases

Use the tool-injection, RAG security, runtime scanning, and human red-team layers for those additional risks.

## Production controls required

Agent security tests should be combined with:

- Authorization enforced outside the model
- Explicit per-role and per-tool allowlists
- Fail-closed behavior for missing, malformed, or unavailable policy
- Schema and argument validation before tool execution
- Approval for destructive, external, financial, or data-export actions
- Tenant/user-scoped memory namespaces
- Trusted-write authentication and audit logs
- Prompt and tool-result separation
- Rate limits and monitoring

A model refusal is useful evidence, but it is not an authorization mechanism.

## Execution model and CI guidance

Tool authorization, memory, and dry-run checks are local and suitable for every pull request. Multi-turn cases require provider credentials and should be included in scheduled or release testing. Keep local policy regressions separate from model-behavior findings when deciding whether a build passes.
