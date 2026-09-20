"""
run_security.py - Run full LLM security + safety pipeline
                  Garak + DeepEval + RAGAS + PyRIT + LLM Guard + LangFuse + Human Red Team
                  + Encoded & Obfuscated Attack Testing
                  + Many-Shot Jailbreak Testing
                  + Multilingual Attacks
                  + Agentic Tool-Call Injection
                  + Backdoor / Trojan Trigger Testing
                  + RAG / Vector Embedding Security (OWASP LLM08)
Cross-platform: Windows and Linux.

Author : Venkateshwara Doijode
Project: LLM Strata - End-to-End LLM Security & Safety Framework

Usage:
    python run_security.py                       # run all automated tools
    python run_security.py --garak-only          # Garak vulnerability scan only
    python run_security.py --deepeval-only       # DeepEval safety scan only
    python run_security.py --ragas-only          # RAGAS RAG safety scan only
    python run_security.py --pyrit-only          # PyRIT red team only
    python run_security.py --guard-only          # LLM Guard runtime demo only
    python run_security.py --langfuse-only       # LangFuse monitoring demo only
    python run_security.py --human-redteam       # launch human red team session
    python run_security.py --encoded-only        # encoded/obfuscated attack scan only
    python run_security.py --many-shot-only      # many-shot jailbreak scan only
    python run_security.py --multilingual-only   # multilingual attack scan only
    python run_security.py --tool-inject-only    # agentic tool-call injection only
    python run_security.py --backdoor-only       # backdoor trigger scan only
    python run_security.py --rag-security-only   # RAG/vector embedding security only
    python run_security.py --agent-security-only # agentic security tests only
    python run_security.py --garak-depth redteam  # red team Garak scan
    python run_security.py --garak-depth all      # deep Garak scan (slow)
    python run_security.py --skip-pyrit          # skip PyRIT (slow, agentic)
    python run_security.py --skip-ragas          # skip RAGAS (only if no RAG app)
    python run_security.py --skip-langfuse       # skip LangFuse (if keys not set)
    python run_security.py --skip-encoded        # skip encoded attack scan
    python run_security.py --skip-many-shot      # skip many-shot jailbreak scan
    python run_security.py --skip-multilingual   # skip multilingual attack scan
    python run_security.py --skip-tool-inject    # skip tool-call injection scan
    python run_security.py --skip-backdoor       # skip backdoor trigger scan
    python run_security.py --skip-rag-security   # skip RAG/vector security scan
    python run_security.py --dry-run             # print all steps without executing
    python run_security.py --ci                  # CI mode: skip interactive tools, exit 1 on any failure
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

from env_loader import load_dotenv
load_dotenv()

DRY_RUN = False


def run(cmd: list[str]) -> int:
    print(f"\n  > {' '.join(cmd)}\n")
    if DRY_RUN:
        print("  [DRY RUN] - command not executed")
        return 0
    result = subprocess.run(cmd, cwd=Path(__file__).resolve().parent)
    return result.returncode


def check_env():
    if not os.environ.get("OPENAI_API_KEY"):
        print("  WARNING: OPENAI_API_KEY not set.")
        print("     Garak and LLM Guard will use mock/offline mode.\n")


def print_header(title: str):
    print()
    print("=" * 55)
    print(f"  {title}")
    print("=" * 55)


def main():
    parser = argparse.ArgumentParser(description="LLM Strata - Security & Safety Pipeline Runner")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--garak-only", action="store_true", help="Run Garak only")
    group.add_argument("--deepeval-only", action="store_true", help="Run DeepEval only")
    group.add_argument("--ragas-only", action="store_true", help="Run RAGAS only")
    group.add_argument("--pyrit-only", action="store_true", help="Run PyRIT only")
    group.add_argument("--guard-only", action="store_true", help="Run LLM Guard only")
    group.add_argument("--langfuse-only", action="store_true", help="Run LangFuse only")
    group.add_argument("--human-redteam", action="store_true", help="Launch human red team session")
    group.add_argument("--encoded-only", action="store_true", help="Run encoded/obfuscated attack scan only")
    group.add_argument("--many-shot-only", action="store_true", help="Run many-shot jailbreak scan only")
    group.add_argument("--multilingual-only", action="store_true", help="Run multilingual attack scan only")
    group.add_argument("--tool-inject-only", action="store_true", help="Run agentic tool-call injection scan only")
    group.add_argument("--backdoor-only", action="store_true", help="Run backdoor trigger scan only")
    group.add_argument("--rag-security-only", action="store_true", help="Run RAG/vector security scan only")
    group.add_argument("--agent-security-only", action="store_true", help="Run agentic security tests only")
    parser.add_argument("--garak-depth", default="standard",
        choices=["quick", "standard", "all"],
        help="Garak probe depth (default: standard)")
    parser.add_argument("--skip-pyrit", action="store_true", help="Skip PyRIT (slow)")
    parser.add_argument("--skip-ragas", action="store_true", help="Skip RAGAS (if no RAG app)")
    parser.add_argument("--skip-langfuse", action="store_true", help="Skip LangFuse (if keys not set)")
    parser.add_argument("--skip-encoded", action="store_true", help="Skip encoded attack scan")
    parser.add_argument("--skip-many-shot", action="store_true", help="Skip many-shot jailbreak scan")
    parser.add_argument("--skip-multilingual", action="store_true", help="Skip multilingual attack scan")
    parser.add_argument("--skip-tool-inject", action="store_true", help="Skip tool-call injection scan")
    parser.add_argument("--skip-backdoor", action="store_true", help="Skip backdoor trigger scan")
    parser.add_argument("--skip-rag-security", action="store_true", help="Skip RAG/vector security scan")
    parser.add_argument("--skip-agent-security", action="store_true", help="Skip agentic security tests")
    parser.add_argument("--dry-run", action="store_true", help="Print all steps without executing")
    parser.add_argument("--ci", action="store_true", help="CI mode: skip interactive tools, exit 1 on any failure")
    args = parser.parse_args()

    global DRY_RUN
    DRY_RUN = args.dry_run

    print_header("LLM Strata - Security & Safety Pipeline")
    print(f"  Platform : {sys.platform}")
    if DRY_RUN:
        print("  Mode     : DRY RUN - no commands will be executed")
    check_env()

    only_one = any([args.garak_only, args.deepeval_only, args.ragas_only,
        args.pyrit_only, args.guard_only, args.langfuse_only, args.many_shot_only,
        args.human_redteam, args.encoded_only, args.tool_inject_only, args.backdoor_only,
        args.multilingual_only, args.tool_inject_only, args.backdoor_only,
        args.rag_security_only, args.agent_security_only])

    exit_codes: list[int] = []

    # --- Step 1: Garak --------------------------------------------
    if args.garak_only or not only_one:
        print_header("STEP 1 - Garak: Vulnerability Scan + Red Teaming (pre-deployment)")
        print("  Probing your LLM for vulnerabilities with adversarial inputs...")
        exit_codes.append(run([
            sys.executable, "garak/run_garak.py",
            "--probes", args.garak_depth,
        ]))
        print("\n  Garak results saved to: results/garak/")

    # --- Step 2: DeepEval --------------------------------------------
    if args.deepeval_only or not only_one:
        print_header("STEP 2 - DeepEval: Safety Testing (bias + toxicity + hallucination + PII)")
        print("  Testing for harmful output, bias, hallucination, PII leakage, prompt injection...")
        exit_codes.append(run([sys.executable, "deepeval/run_deepeval.py"]))
        print("\n  DeepEval results saved to: results/deepeval/")

    # --- Step 3: RAGAS --------------------------------------------
    if args.ragas_only or (not only_one and not args.skip_ragas):
        print_header("STEP 3 - RAGAS: RAG Pipeline Safety (context poisoning + faithfulness)")
        print("  Testing for poisoned context, hallucination, retrieval quality...")
        exit_codes.append(run([sys.executable, "ragas/run_ragas.py"]))
        print("\n  RAGAS results saved to: results/ragas/")
    elif not only_one and args.skip_ragas:
        print("\n  [SKIPPED] RAGAS - use --ragas-only to run separately")

    # --- Step 4: PyRIT --------------------------------------------
    if args.pyrit_only or (not only_one and not args.skip_pyrit):
        print_header("STEP 4 - PyRIT: Multi-turn Agentic Red Teaming")
        print("  Running goal-directed adaptive attacks across multiple turns...")
        exit_codes.append(run([sys.executable, "pyrit/run_pyrit.py"]))
        print("\n  PyRIT results saved to: results/pyrit/")
    elif not only_one and args.skip_pyrit:
        print("\n  [SKIPPED] PyRIT - use --pyrit-only to run separately")

    # --- Step 5: LLM Guard --------------------------------------------
    if args.guard_only or not only_one:
        print_header("STEP 5 - LLM Guard: Runtime Protection Demo")
        print("  Testing input/output scanners against sample attack prompts...")
        exit_codes.append(run([sys.executable, "llm_guard/run_guard.py"]))
        print("\n  LLM Guard logs saved to: results/llm_guard/")

    # --- Step 6: LangFuse --------------------------------------------
    if args.langfuse_only or (not only_one and not args.skip_langfuse):
        print_header("STEP 6 - LangFuse: Production Monitoring Demo")
        print("  Sending traced requests + scoring for safety in dashboard...")
        exit_codes.append(run([sys.executable, "langfuse/run_langfuse.py"]))
        print("\n  View traces at: https://cloud.langfuse.com")
    elif not only_one and args.skip_langfuse:
        print("\n  [SKIPPED] LangFuse - set LANGFUSE_PUBLIC_KEY + LANGFUSE_SECRET_KEY to enable")

    # --- Step 7: Human Red Team --------------------------------------------
    if args.human_redteam and not args.ci:
        print_header("STEP 7 - Human Red Team: Manual Attack Session")
        print("  Interactive session - a human tester probes the model...")
        run([sys.executable, "human_redteam/run_redteam.py"])
        print("\n  Human red team results saved to: results/human_redteam/")
    elif not only_one:
        print("\n  [INFO] Human red team not run automatically (interactive).")
        print("     Run manually: python run_security.py --human-redteam")

    # --- Step 8: Encoded & Obfuscated Attacks --------------------------------------------
    if args.encoded_only or (not only_one and not args.skip_encoded):
        print_header("STEP 8 - Encoded Attacks: Bypass & Obfuscation Testing")
        print("  Testing base64, rot13, hex, morse, leetspeak, homoglyphs and more...")
        exit_codes.append(run([sys.executable, "encoded_attacks/run_encoded_attacks.py"]))
        print("\n  Encoded attack results saved to: results/encoded_attacks/")
    elif not only_one and args.skip_encoded:
        print("\n  [SKIPPED] Encoded attacks - use --encoded-only to run separately")

    # --- Step 9: Many-Shot Jailbreak --------------------------------------------
    if args.many_shot_only or (not only_one and not args.skip_many_shot):
        print_header("STEP 9 - Many-Shot Jailbreaks: In-Context Conditioning Attacks")
        print("  Testing pure-harmful, gradual-escalation, and camouflaged strategies...")
        exit_codes.append(run([sys.executable, "many_shot/run_many_shot.py"]))
        print("\n  Many-shot results saved to: results/many_shot/")
    elif not only_one and args.skip_many_shot:
        print("\n  [SKIPPED] Many-shot jailbreaks - use --many-shot-only to run separately")

    # --- Step 10: Multilingual Attacks --------------------------------------------
    if args.multilingual_only or (not only_one and not args.skip_multilingual):
        print_header("STEP 10 - Multilingual Attacks: Cross-Language Safety Bypass")
        print("  Testing Arabic, Chinese, Russian, Hindi, Spanish, French, German...")
        exit_codes.append(run([sys.executable, "multilingual/run_multilingual.py"]))
        print("\n  Multilingual results saved to: results/multilingual/")
    elif not only_one and args.skip_multilingual:
        print("\n  [SKIPPED] Multilingual attacks - use --multilingual-only to run separately")

    # --- Step 11: Tool-Call Injection --------------------------------------------
    if args.tool_inject_only or (not only_one and not args.skip_tool_inject):
        print_header("STEP 11 - Tool-Call Injection: Agentic Indirect Prompt Injection")
        print("  Injecting malicious instructions via search, file, email, database results...")
        exit_codes.append(run([sys.executable, "tool_inject/run_tool_inject.py"]))
        print("\n  Tool injection results saved to: results/tool_inject/")
    elif not only_one and args.skip_tool_inject:
        print("\n  [SKIPPED] Tool-call injection - use --tool-inject-only to run separately")

    # --- Step 12: Backdoor / Trojan Triggers --------------------------------------------
    if args.backdoor_only or (not only_one and not args.skip_backdoor):
        print_header("STEP 12 - Backdoor Triggers: Trojan Phrase Amplification Testing")
        print("  Measuring compliance rate with / without DAN, authority, roleplay triggers...")
        exit_codes.append(run([sys.executable, "backdoor/run_backdoor.py"]))
        print("\n  Backdoor results saved to: results/backdoor/")
    elif not only_one and args.skip_backdoor:
        print("\n  [SKIPPED] Backdoor triggers - use --backdoor-only to run separately")

    # --- Step 13: RAG / Vector Security --------------------------------------------
    if args.rag_security_only or (not only_one and not args.skip_rag_security):
        print_header("STEP 13 - RAG Security: Vector / Embedding Weakness Testing (LLM08)")
        print("  Testing 9 attack vectors: injection, PII leak, embedding authority override, flooding...")
        exit_codes.append(run([sys.executable, "rag_security/run_rag_security.py"]))
        print("\n  RAG security results saved to: results/rag_security/")
    elif not only_one and args.skip_rag_security:
        print("\n  [SKIPPED] RAG security - use --rag-security-only to run separately")

    # --- Step 14: Agentic Security --------------------------------------------
    if args.agent_security_only or (not only_one and not args.skip_agent_security):
        print_header("STEP 14 - Agentic Security: Multi-turn, Tool Authorization, Memory")
        print("  Testing multi-turn attacks, tool permissions, and agent memory isolation...")
        exit_codes.append(run([sys.executable, "agent_security/run_agent_security.py"]))
        print("\n  Agent security results saved to: results/agent_security/")
    elif not only_one and args.skip_agent_security:
        print("\n  [SKIPPED] Agentic security - use --agent-security-only to run separately")

    # --- Summary --------------------------------------------
    print_header("Security + Safety Run Complete")
    print("  Results:")
    print("  results/garak/          - vulnerability scan (attack surface + red team)")
    print("  results/deepeval/       - safety scan (bias, toxicity, hallucination)")
    print("  results/ragas/          - RAG safety (context poisoning, faithfulness)")
    print("  results/pyrit/          - agentic red team (multi-turn attack results)")
    print("  results/llm_guard/      - runtime scanner audit log")
    print("  results/human_redteam/  - human red team session logs")
    print("  results/encoded_attacks/ - encoded/obfuscated bypass test results")
    print("  results/many_shot/      - many-shot jailbreak compliance matrix")
    print("  results/multilingual/   - cross-language safety bypass results")
    print("  results/tool_inject/    - agentic indirect prompt injection results")
    print("  results/backdoor/       - backdoor trigger amplification report")
    print("  results/rag_security/   - RAG/vector injection and PII leakage report")
    print("  results/agent_security/ - multi-turn, tool authorization, memory reports")
    print("  cloud.langfuse.com      - live production trace dashboard")
    print()
    print("  Next steps:")
    print("  1. Review Garak + PyRIT reports for security vulnerabilities")
    print("  2. Review DeepEval + RAGAS reports for safety gaps")
    print("  3. Integrate LLM Guard into your app for continuous monitoring")
    print("  4. Instrument your app with LangFuse SDK for continuous monitoring")
    print("  5. Run human red team: python run_security.py --human-redteam")
    print("  6. Review encoded attack report for scanner bypass gaps")
    print("  7. Review many-shot report for in-context conditioning compliance rate")
    print("  8. Review multilingual report for language-based safety gaps")
    print("  9. Review tool-inject report for agentic indirect prompt injection")
    print("  10. Review backdoor report for trigger amplification (delta compliance rate)")
    print("  11. Review RAG security report for vector/embedding injection vulnerabilities")
    print("  12. Review agent security report for multi-turn, authorization, and memory findings")
    print("  13. Re-run after fixes to verify they're resolved")
    print("=" * 55)

    if args.ci and any(code != 0 for code in exit_codes):
        failed = sum(1 for code in exit_codes if code != 0)
        print(f"\n  CI: {failed} tool(s) exited with errors - pipeline marked as failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
