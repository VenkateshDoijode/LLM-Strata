"""
run_agent_security.py — Agentic Security Testing
Tests multi-turn attack resistance, tool authorization, and agent memory isolation
without executing real production tools.

Author : Venkateshwara Doijode
Project: LLM Strata — End-to-End LLM Security & Safety Framework

WHAT IS AGENTIC SECURITY TESTING?
  Agentic systems can preserve state across turns, call tools on a user's behalf,
  and write information to memory. These capabilities create security risks that
  are not covered by single-turn prompt or model safety tests.

TEST AREAS:
  multi_turn_attacks       — Detect unsafe behavior across scripted conversations
  tool_authorization_tests — Verify deny-by-default role and tool policies
  memory_tests             — Verify namespace isolation and trusted-write rules

Usage:
    python agent_security/run_agent_security.py
    python agent_security/run_agent_security.py --multi-turn-only
    python agent_security/run_agent_security.py --tool-auth-only
    python agent_security/run_agent_security.py --memory-only
    python agent_security/run_agent_security.py --dry-run
    python agent_security/run_agent_security.py --verbose
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml
from client_factory import get_client
from env_loader import load_dotenv, require_provider_env
from profile_loader import active_profile_name, get_model

from agent_security.core import (
    run_memory_tests,
    run_multiturn_attacks,
    run_tool_authorization_tests,
    summarize_sections,
)

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "agent_security/agent_security_config.yaml"
OUTPUT_DIR = PROJECT_ROOT / "results/agent_security"


# ── Configuration and report output ─────────────────────────────────────────

def load_config() -> dict:
    """Load the agent security test configuration from YAML."""
    with open(CONFIG_PATH, encoding="utf-8") as config_file:
        return yaml.safe_load(config_file) or {}


def save_report(report: dict):
    """Write a timestamped JSON report and return its path."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = OUTPUT_DIR / f"agent_security_{timestamp}.json"
    with open(path, "w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=2, ensure_ascii=False)
    return path


# ── Main runner ─────────────────────────────────────────────────────────────

def main() -> int:
    """Run the selected agent security tests and save a JSON report."""
    parser = argparse.ArgumentParser(description="Agentic LLM Security Tester")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--multi-turn-only",
        action="store_true",
        help="Run multi-turn attack tests only",
    )
    group.add_argument(
        "--tool-auth-only",
        action="store_true",
        help="Run tool authorization tests only",
    )
    group.add_argument(
        "--memory-only",
        action="store_true",
        help="Run memory isolation tests only",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List configured tests without calling an LLM",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print the result of every test",
    )
    args = parser.parse_args()

    config = load_config()
    run_multi = not (args.tool_auth_only or args.memory_only)
    run_auth = not (args.multi_turn_only or args.memory_only)
    run_memory = not (args.multi_turn_only or args.tool_auth_only)

    if args.dry_run:
        print(f"Profile: {active_profile_name()}")
        print(f"Multi-turn attacks: {len(config.get('multi_turn_attacks', []))}")
        print(f"Tool authorization tests: {len(config.get('tool_authorization_tests', []))}")
        print(f"Memory tests: {len(config.get('memory_tests', []))}")
        return 0

    sections: dict[str, list[dict]] = {}
    model = get_model("model", config.get("model", "gpt-4o-mini"))
    client = None
    if run_multi:
        require_provider_env()
        client = get_client()
        sections["multi_turn"] = run_multiturn_attacks(
            client=client,
            model=model,
            cases=config.get("multi_turn_attacks", []),
            max_tokens=int(config.get("max_tokens", 400)),
        )
    if run_auth:
        sections["tool_authorization"] = run_tool_authorization_tests(config)
    if run_memory:
        sections["memory"] = run_memory_tests(config)

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "profile": active_profile_name(),
        "model": model,
        "summary": summarize_sections(sections),
        "results": sections,
    }
    report_path = save_report(report)

    print(f"Profile: {report['profile']}")
    print(f"Agentic security tests: {report['summary']['passed']}/{report['summary']['total']} passed")
    print(f"Report: {report_path}")
    if args.verbose:
        for section, results in sections.items():
            for result in results:
                status = "PASS" if result.get("passed") else "FAIL"
                print(f"  [{status}] {section}/{result['id']}")
                if result.get("error"):
                    print(f"    {result['error']}")

    return 0 if report["summary"]["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
