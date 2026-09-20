"""
run_garak.py - Run Garak LLM vulnerability scanner
Cross-platform: Windows and Linux.

Author : Venkateshwara Doijode
Project: LLM Strata - End-to-End LLM Security & Safety Framework

Garak produces 4 outputs per scan (source: docs.garak.ai):
  1. Screen output  - live scan progress (what's running, what's scheduled)
  2. Report log     - every prompt, every response, every evaluation result
  3. Hit log        - only the cases where garak found a vulnerability
  4. Debug log      - internal operations log for troubleshooting

All file logs are saved to results/garak/ using the --report_prefix flag.
Note: Garak v0.17+ uses --spec instead of the deprecated --probes flag (handled automatically).

Usage:
    python garak/run_garak.py                                             # scan with standard probes (default)
    python garak/run_garak.py --model gpt-4o                              # override OpenAI model name
    python garak/run_garak.py --target_type huggingface --model gpt2      # scan a HuggingFace model
    python garak/run_garak.py --target_type ollama --model llama2         # scan an Ollama model
    python garak/run_garak.py --probes quick                              # quick scan - 3 probes (fast)
    python garak/run_garak.py --probes standard                           # standard scan - 7 probes (default)
    python garak/run_garak.py --probes redteam                            # red team scan - 6 aggressive probes
    python garak/run_garak.py --probes all                                # full scan - every probe (slow)
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import yaml
from env_loader import load_dotenv, warn_env
from profile_loader import get_model, active_profile_name
load_dotenv()


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "garak/garak_config.yaml"


def load_config() -> dict:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            return yaml.safe_load(f)
    return {}


# ── Probe presets ──────────────────────────────────────────────────────────
# Curated subsets for different scan depths
QUICK_PROBES = [
    "probes.dan",              # DAN jailbreaks (fast, high signal)
    "probes.promptinject",     # prompt injection
    "probes.knownbadsignatures",# known attack signatures
]

STANDARD_PROBES = [
    "probes.dan",
    "probes.promptinject",
    "probes.grandma",
    "probes.leakreplay",
    "probes.knownbadsignatures",
    "probes.continuation",
    "probes.misleading",
]

REDTEAM_PROBES = [
    "probes.atkgen",           # AI-generated adaptive attack prompts
    "probes.encoding",         # encoding evasion (base64, rot13, hex)
    "probes.gcg",              # Greedy Coordinate Gradient adversarial suffix
    "probes.dan",              # DAN jailbreak family
    "probes.grandma",          # social engineering
    "probes.promptinject",     # prompt injection
]

ALL_PROBES = "all"  # runs every garak probe (slow, comprehensive)


def get_garak_python() -> str:
    """Return the interpreter for Garak's isolated environment."""
    configured = os.environ.get("GARAK_PYTHON")
    if configured:
        interpreter = Path(configured)
    elif sys.platform == "win32":
        interpreter = PROJECT_ROOT / ".venv-garak" / "Scripts" / "python.exe"
    else:
        interpreter = PROJECT_ROOT / ".venv-garak" / "bin" / "python"

    if not interpreter.exists():
        print("  ERROR: Garak environment not found.")
        print("  Run: python setup.py")
        print("  Or set GARAK_PYTHON to an installed Garak interpreter.")
        sys.exit(1)
    return str(interpreter)


def check_garak():
    """Check if garak is installed in its isolated environment."""
    garak_python = get_garak_python()
    result = subprocess.run(
        [garak_python, "-m", "garak", "--version"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print("  ERROR: garak is not installed in the Garak environment.")
        print("  Run: python setup.py")
        sys.exit(1)
    print(f"  garak: {result.stdout.strip()}")


def check_env():
    warn_env("OPENAI_API_KEY")


def run_scan(model: str, probes: list[str] | str, output_dir: Path, target_type: str = "openai") -> int:
    """Build and run the garak command."""
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        get_garak_python(), "-m", "garak",
        "--target_type", target_type,
        "--target_name", model,
        "--report_prefix", str(output_dir / "scan"),
    ]

    if probes == ALL_PROBES:
        # garak runs all probes by default when none specified
        print("  Running ALL probes (this will take a long time)...")
    else:
        # --spec replaces deprecated --probes (official CLI ref v0.17+)
        cmd += ["--spec", ",".join(probes)]

    print(f"\n  Command: {' '.join(cmd)}\n")
    result = subprocess.run(cmd, check=False)
    return result.returncode


def main():
    config = load_config()
    cfg_model = get_model("model", config.get("model_name", "gpt-4o-mini"))
    cfg_target_type = config.get("model_type", "openai")
    cfg_output_dir = config.get("reporting", {}).get("output_dir", "results/garak")

    parser = argparse.ArgumentParser(description="Garak LLM Security Scanner")
    parser.add_argument("--model",       default=cfg_model,
                        help="Model name (e.g. gpt-4o-mini, gpt2, llama2)")
    parser.add_argument("--target_type", default=cfg_target_type,
                        help="Model provider: openai | huggingface | ollama | rest | bedrock | litellm")
    parser.add_argument("--probes",      default="standard",
                        choices=["quick", "standard", "redteam", "all"],
                        help="Probe depth: quick | standard | redteam | all")
    args = parser.parse_args()

    print()
    print("=" * 55)
    print("  Garak - LLM Vulnerability Scanner")
    print(f"  Profile : {active_profile_name()}")
    print(f"  Target  : {args.target_type} / {args.model}")
    print(f"  Probes  : {args.probes}")
    print("=" * 55)

    check_garak()
    check_env()

    # Select probe set
    probe_set = {
        "quick":    QUICK_PROBES,
        "standard": STANDARD_PROBES,
        "redteam":  REDTEAM_PROBES,
        "all":      ALL_PROBES,
    }[args.probes]

    output_dir = Path(cfg_output_dir)
    if not output_dir.is_absolute():
        output_dir = PROJECT_ROOT / output_dir
    exit_code = run_scan(
        model=args.model,
        probes=probe_set,
        output_dir=output_dir,
        target_type=args.target_type,
    )

    if exit_code != 0:
        print(f"\n  Garak exited with status {exit_code}.")
        return exit_code

    print()
    print("=" * 55)
    print(f"  Scan complete! Results in: {output_dir}/")
    print("=" * 55)
    return 0


if __name__=="__main__":
    sys.exit(main())    