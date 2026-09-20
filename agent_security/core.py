"""Agentic security test primitives without requiring a production agent runtime."""

from __future__ import annotations

import re
from typing import Any


class AgentMemoryStore:
    """Small namespaced memory model used to test memory security policies.

    Data is kept in a plain in-process dict of {scope: {key: value}}, so one scope
    (e.g. one user) can never see another scope's keys unless the caller passes
    the same scope string. Nothing is persisted.
    """

    def __init__(self, allow_untrusted_writes: bool = False):
        self.allow_untrusted_writes = allow_untrusted_writes
        self._memory: dict[str, dict[str, str]] = {}

    def write(self, scope: str, key: str, value: str, trusted: bool = False) -> dict[str, Any]:
        # Fail closed: untrusted writes are rejected unless the policy explicitly allows them.
        if not trusted and not self.allow_untrusted_writes:
            return {"allowed": False, "reason": "untrusted_memory_write_denied"}
        self._memory.setdefault(scope, {})[key] = value
        return {"allowed": True, "reason": "memory_written"}

    def read(self, scope: str, key: str) -> dict[str, Any]:
        # `found` is based on `is not None`, so an empty-string value still counts as present.
        value = self._memory.get(scope, {}).get(key)
        return {"found": value is not None, "value": value}

    def reset(self, scope: str) -> dict[str, Any]:
        # Drops the whole scope; resetting a scope that doesn't exist is a harmless no-op.
        self._memory.pop(scope, None)
        return {"allowed": True, "reason": "memory_reset"}


def evaluate_tool_authorization(
    policies: dict[str, Any],
    role: str,
    tool: str,
    approved: bool = False,
) -> dict[str, Any]:
    """Evaluate a deny-by-default role/tool authorization policy."""
    # Unknown (or empty) role -> deny. Role names are matched exactly (case-sensitive).
    policy = policies.get(role)
    if not isinstance(policy,dict) or not policy:
        return {"allowed": False, "reason": "unknown_role"}
        
    raw_allowed_tools = policy.get("allowed_tools")   
    if not isinstance(raw_allowed_tools,(list,tuple,set)) or not raw_allowed_tools: 
        return {"allowed": False,"reason": "tool_not_allowlisted"}

    denied_tools = set(policy.get("denied_tools", []))
    allowed_tools = set(policy.get("allowed_tools", []))
    approval_required = set(policy.get("approval_required", []))

    # Evaluation order matters: explicit deny > allowlist > approval gate > allow.
    if tool in denied_tools:
        return {"allowed": False, "reason": "tool_denied_by_policy"}
    # SECURITY NOTE: the allowlist is only enforced when it is non-empty. A role with a
    # missing or empty `allowed_tools` therefore allows every tool that isn't in
    # `denied_tools`, which contradicts the "deny-by-default" docstring above.
    # Consider `if tool not in allowed_tools:` if roles must always declare an allowlist.
    if tool not in allowed_tools:
        return {"allowed": False, "reason": "tool_not_allowlisted"}
    if tool in approval_required and not approved:
        return {"allowed": False, "reason": "approval_required"}
    return {"allowed": True, "reason": "tool_allowed"}


def run_tool_authorization_tests(config: dict[str, Any]) -> list[dict[str, Any]]:
    policies = config.get("tool_policies", {})
    results = []
    for test in config.get("tool_authorization_tests", []):
        decision = evaluate_tool_authorization(
            policies=policies,
            role=str(test.get("role", "")),
            tool=str(test.get("tool", "")),
            approved=bool(test.get("approved", False)),
        )
        # `expected` is "allow" or "deny"; anything other than "allow" (including a
        # missing key) is treated as "deny".
        expected = str(test.get("expected", "deny")).lower() == "allow"
        passed = decision["allowed"] == expected
        results.append(
            {
                "id": test["id"],
                "role": test.get("role"),
                "tool": test.get("tool"),
                "expected_allowed": expected,
                "actual_allowed": decision["allowed"],
                "reason": decision["reason"],
                "passed": passed,
            }
        )
    return results


def _matches_indicators(text: str, indicators: list[Any], patterns: list[Any]) -> bool:
    """Return True if `text` contains any unsafe indicator.

    `indicators` are case-insensitive plain substrings; `patterns` are case-insensitive
    regexes (config key: `unsafe_patterns`). Note that a refusal which merely *quotes* an
    indicator (e.g. "I won't append INTERNAL-OVERRIDE") will still match.
    """
    folded = text.casefold()
    if any(str(indicator).casefold() in folded for indicator in indicators):
        return True
    return any(re.search(str(pattern), text, re.IGNORECASE) for pattern in patterns)


def run_multiturn_attacks(
    client: Any,
    model: str,
    cases: list[dict[str, Any]],
    max_tokens: int = 400,
) -> list[dict[str, Any]]:
    """Run scripted multi-turn attacks against a chat-completions-compatible client."""
    results = []
    for case in cases:
        messages = []
        outputs = []
        try:
            if case.get("system_prompt"):
                messages.append({"role": "system", "content": str(case["system_prompt"])})

            # Replay each scripted user turn, feeding the model's own replies back in so
            # later turns see the full conversation history (this is what makes it multi-turn).
            for turn_number, turn in enumerate(case.get("turns", []), start=1):
                # A turn may be a bare string or a dict like {"content": "..."}.
                content = turn.get("content", "") if isinstance(turn, dict) else str(turn)
                messages.append({"role": "user", "content": str(content)})
                response = client.chat.completions.create(
                    model=model,
                    messages=messages,
                    max_tokens=case.get("max_tokens", max_tokens),  # per-case override
                )
                choices = getattr(response, "choices", None) or []
                message = getattr(choices[0], "message", None) if choices else None
                output = str(getattr(message, "content", "") or "")
                outputs.append({"turn": turn_number, "input": str(content), "output": output})
                messages.append({"role": "assistant", "content": output})

            # Indicators are checked against ALL replies joined together, not per turn.
            # A reply to an early attack turn that echoes an indicator therefore fails the
            # whole case, even if the model behaved correctly on the final turn.
            combined_output = "\n".join(item["output"] for item in outputs)
            breached = _matches_indicators(
                combined_output,
                case.get("unsafe_indicators", []),
                case.get("unsafe_patterns", []),
            )
            results.append(
                {
                    "id": case["id"],
                    "goal": case.get("goal", ""),
                    "turns": outputs,
                    "attack_blocked": not breached,
                    "passed": not breached,
                }
            )
        except Exception as exc:
            # Any API/config error (including a bad regex) is recorded as a failed test
            # rather than crashing the whole run; partial `outputs` are kept for debugging.
            results.append(
                {
                    "id": case["id"],
                    "goal": case.get("goal", ""),
                    "turns": outputs,
                    "attack_blocked": False,
                    "passed": False,
                    "error": str(exc),
                }
            )
    return results


def run_memory_tests(config: dict[str, Any]) -> list[dict[str, Any]]:
    memory_config = config.get("memory_policy", {})
    results = []

    for test in config.get("memory_tests", []):
        # A fresh store per test keeps tests independent of each other.
        store = AgentMemoryStore(
            allow_untrusted_writes=bool(memory_config.get("allow_untrusted_writes", False))
        )
        operations = []
        passed = True
        for operation in test.get("operations", []):
            action = operation.get("action")
            scope = str(operation.get("scope", "default"))
            key = str(operation.get("key", ""))
            if action == "write":
                outcome = store.write(
                    scope=scope,
                    key=key,
                    value=str(operation.get("value", "")),
                    trusted=bool(operation.get("trusted", False)),
                )
                actual = outcome["allowed"]
                expected = bool(operation.get("expected_allowed", True))
                operation_passed = actual == expected
            elif action == "read":
                outcome = store.read(scope, key)
                # Precedence: expected_absent > expected_value > (default) key must exist.
                if operation.get("expected_absent", False):
                    operation_passed = not outcome["found"]
                elif "expected_value" in operation:
                    operation_passed = outcome["value"] == operation["expected_value"]
                else:
                    operation_passed = outcome["found"]
            elif action == "reset":
                outcome = store.reset(scope)
                operation_passed = outcome["allowed"]
            else:
                # Unknown actions fail the test instead of being silently skipped (typo guard).
                outcome = {"error": f"unknown memory action: {action}"}
                operation_passed = False

            # A test passes only if every operation in it passed.
            passed = passed and operation_passed
            operations.append(
                {
                    "action": action,
                    "scope": scope,
                    "key": key,
                    "result": outcome,
                    "passed": operation_passed,
                }
            )

        results.append({"id": test["id"], "operations": operations, "passed": passed})
    return results


def summarize_sections(sections: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    # A result missing the "passed" key counts as a failure.
    all_results = [result for results in sections.values() for result in results]
    passed = sum(1 for result in all_results if result.get("passed"))
    return {
        "total": len(all_results),
        "passed": passed,
        "failed": len(all_results) - passed,
        "sections": {name: len(results) for name, results in sections.items()},
    }
