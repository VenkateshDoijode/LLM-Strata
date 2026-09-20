"""
setup.py - One-time setup for LLM Security Framework
Cross-platform: Windows and Linux.

Author : Venkateshwara Doijode
Project: LLM Strata - End-to-End LLM Security & Safety Framework

Usage: python setup.py
"""

import subprocess
import sys
from pathlib import Path


def run(cmd: list[str], check: bool = True):
    print(f"  > {' '.join(cmd)}")
    return subprocess.run(cmd, check=check)


def main():
    print()
    print("=" * 55)
    print("  LLM Strata - Setup")
    print("=" * 55)

    # --- Check Python version ---------------------------------
    print("\n[1/4] Checking Python...")
    version = sys.version_info
    if version < (3, 10):
        print(f"  ERROR: Python 3.10+ required (found {version.major}.{version.minor})")
        sys.exit(1)
    print(f"  Python {version.major}.{version.minor}.{version.micro} OK")
    if version >= (3, 13):
        print(f"  WARNING: Python {version.major}.{version.minor} detected.")
        print("    Some dependencies (garak, ragas, pyrit) may not yet support Python 3.13+.")
        print("    Use Python 3.10-3.12 for best compatibility.")

    # --- Create virtual environment -----------------------------
    print("\n[2/4] Creating virtual environment...")
    if not Path(".venv").exists():
        run([sys.executable, "-m", "venv", ".venv"])
        print("  Virtual environment created at .venv/")
    else:
        print("  .venv already exists - skipping.")

    # --- Determine pip path -----------------------------
    if sys.platform == "win32":
        pip = str(Path(".venv/Scripts/pip.exe"))
        activate = ".venv\\Scripts\\activate"
    else:
        pip = str(Path(".venv/bin/pip"))
        activate = "source .venv/bin/activate"

    # --- Install dependencies -----------------------------
    print("\n[3/4] Installing dependencies...")
    run([pip, "install", "--upgrade", "pip"])
    run([pip, "install", "-r", "requirements.txt"])
    print("  All packages installed.")

    # --- Create results directories -----------------------------
    print("\n[4/4] Creating results directories...")
    Path("results/garak").mkdir(parents=True, exist_ok=True)
    Path("results/deepeval").mkdir(parents=True, exist_ok=True)
    Path("results/ragas").mkdir(parents=True, exist_ok=True)
    Path("results/pyrit").mkdir(parents=True, exist_ok=True)
    Path("results/llm_guard").mkdir(parents=True, exist_ok=True)
    Path("results/human_redteam").mkdir(parents=True, exist_ok=True)
    Path("results/encoded_attacks").mkdir(parents=True, exist_ok=True)
    Path("results/many_shot").mkdir(parents=True, exist_ok=True)
    Path("results/multilingual").mkdir(parents=True, exist_ok=True)
    Path("results/tool_inject").mkdir(parents=True, exist_ok=True)
    Path("results/backdoor").mkdir(parents=True, exist_ok=True)
    Path("results/rag_security").mkdir(parents=True, exist_ok=True)
    print("  results/garak/         - Garak scan reports")
    print("  results/deepeval/      - DeepEval safety reports")
    print("  results/ragas/         - RAGAS RAG safety reports")
    print("  results/pyrit/         - PyRIT audit logs")
    print("  results/llm_guard/     - LLM Guard audit logs")
    print("  results/human_redteam/ - Human red team session logs")
    print("  results/encoded_attacks/ - Encoded/obfuscated attack test results")
    print("  results/many_shot/     - Many-shot jailbreak compliance matrix")
    print("  results/multilingual/  - Cross-language safety bypass results")
    print("  results/tool_inject/   - Agentic indirect prompt injection results")
    print("  results/backdoor/      - Backdoor trigger amplification report")
    print("  results/rag_security/  - RAG/vector injection and PII leakage report")
    print("  (LangFuse results live at cloud.langfuse.com)")

    # --- Instructions -----------------------------
    print()
    print("=" * 55)
    print("  Setup complete!")
    print()
    print("  Activate environment:")
    print(f"    {activate}")
    print()
    print("  Set environment variables:")
    if sys.platform == "win32":
        print("    set OPENAI_API_KEY=sk-...")
    else:
        print("    export OPENAI_API_KEY=sk-...")
    print()
    print("  Then run:")
    print("    python run_security.py                 # run all automated tools")
    print("    python run_security.py --garak-only     # Garak only")
    print("    python run_security.py --deepeval-only  # DeepEval only")
    print("    python run_security.py --ragas-only     # RAGAS only")
    print("    python run_security.py --pyrit-only     # PyRIT only")
    print("    python run_security.py --guard-only     # LLM Guard only")
    print("    python run_security.py --langfuse-only  # LangFuse only")
    print("    python run_security.py --human-redteam  # Human red team session")
    print("=" * 55)


if __name__ == "__main__":
    main()