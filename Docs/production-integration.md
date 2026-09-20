# Production Integration

## Test harness versus control plane

The runners find weaknesses; they do not automatically protect a separate application. Production enforcement must be implemented in the application's request, tool, data, and response paths.

## Recommended request flow

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

## Tool authorization

Never use the model's claim that a tool is allowed as the authorization decision. Use an external policy evaluator with:

- Explicit role/tool allowlists
- Deny-by-default behavior
- Tenant and resource checks
- Schema and argument validation
- Approval for destructive, external, financial, or export actions
- Audit logging
- Fail-closed behavior when policy is missing or unavailable

The Agent Security layer provides local policy regression tests; production code must enforce the same policy at the actual tool boundary.

## Prompt and tool-result separation

Treat retrieved documents, web pages, files, emails, database rows, and tool results as untrusted data. Delimit them, label their trust level, and do not allow their contents to grant permissions or override system policy.

Use the Tool Injection and RAG Security modules to test this boundary.

## Runtime scanning

LLM Guard is a local scanner demonstration. A production integration should define what happens when each scanner triggers:

- Block the request
- Redact sensitive data
- Ask for confirmation
- Route to human review
- Log a privacy-preserving event

Benchmark latency, false positives, false negatives, Unicode behavior, multilingual behavior, and scanner failure handling before deployment.

## Memory and RAG

- Scope memory by authenticated tenant and user.
- Authenticate trusted writes.
- Apply data-layer ACLs before retrieval.
- Track document provenance.
- Never treat retrieved text as an instruction with higher priority than policy.
- Test deletion, reset, export, and cross-tenant access paths.

## Monitoring

Use LangFuse or another approved telemetry system to monitor production behavior, but mask secrets and unnecessary PII. Monitoring detects and helps investigate failures; it does not prevent unauthorized actions by itself.
