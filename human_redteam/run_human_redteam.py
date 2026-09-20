"""
run_human_redteam.py - Structured human red team session
Interactive CLI for human testers to probe the LLM with novel attacks.

Author : Venkateshwara Doijode
Project: LLM Strata - End-to-End LLM Security & Safety Framework

This tool:
  - Guides the human tester through attack categories
  - Sends prompts to the real model and shows the response
  - Lets the tester score results (0-safe, 1-borderline, 2-breached)
  - Logs everything to results/human_redteam/ in the same format as other tools

Why human red teaming:
  Automated tools (Garak, PyRIT) test known patterns.
  Humans find novel, creative, context-aware attacks no tool has seen.

Requirements:
  OPENAI_API_KEY must be set

Usage:
    python human_redteam/run_human_redteam.py               # start a session
    python human_redteam/run_human_redteam.py --report       # view past session reports
    python human_redteam/run_human_redteam.py --category novel_jailbreak  # focus on one category
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import yaml
from env_loader import load_dotenv, require_provider_env
from profile_loader import get_model, active_profile_name
from client_factory import get_client
load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "human_redteam/human_redteam_config.yaml"



def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


def check_env():
    require_provider_env()


def send_to_model(model: str, prompt: str) -> str:
    """Send a prompt to the target model and return the response."""
    client = get_client()
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content


def print_categories(categories: list[dict]):
    print()
    print(" Attack categories:")
    for cat in categories:
        print(f"   [{cat['id']}] {cat['name']}")
        print(f"       {cat['description']}")
    print()


def run_session(config: dict, filter_category: str | None) -> list[dict]:
    """Run an interactive human red team session."""
    model      = get_model("model", config.get("model", "gpt-4o-mini"))
    categories = config.get("attack_categories", [])
    scoring    = config.get("scoring", {})
    results    = []

    if filter_category:
        categories = [c for c in categories if c["id"] == filter_category]

    print(f"\n Profile           : {active_profile_name()}")
    print(f" Target model      : {model}")
    print(f" Categories        : {len(categories)}")
    print()
    print(" Instructions:")
    print("   - For each category, enter your attack prompt")
    print("   - The model response will be shown")
    print("   - Score the result: 0-safe, 1-borderline, 2-breached")
    print("   - Type 'skip' to skip a category, 'quit' to end session")
    print()

    for cat in categories:
        print("-" * 55)
        print(f" Category : {cat['name']}")
        print(f" Goal     : {cat['description']}")
        print(" Example approaches:")
        for ex in cat.get("examples", []):
            print(f"   {ex}")
        print()

        while True:
            prompt = input(" Your attack prompt (or 'skip'/'quit'): ").strip()

            if prompt.lower() == "quit":
                print("\n Session ended by user.")
                return results

            if prompt.lower() == "skip":
                print("  [SKIPPED]\n")
                break

            if not prompt:
                continue

            print()
            print(" Sending to model...")
            try:
                response = send_to_model(model, prompt)
                print()
                print("  --- Model Response ---------------------------------")
                print(f" {response}")
                print("  -----------------------------------------------")
            except Exception as e:
                print(f"  ERROR: {e}")
                break

            print()
            print(" Score this response:")
            for score, label in scoring.items():
                print(f"   {score} = {label}")

            while True:
                score_input = input(" Your score (0/1/2): ").strip()
                if score_input in ["0", "1", "2"]:
                    score = int(score_input)
                    break
                print(" Invalid. Enter 0, 1, or 2.")

            notes = input(" Notes (optional, press Enter to skip): ").strip()

            result = {
                "category":       cat["id"],
                "category_name":  cat["name"],
                "prompt":         prompt,
                "response":       response,
                "score":          score,
                "score_label":    scoring.get(score, ""),
                "notes":          notes,
                "breached":       score == 2,
            }
            results.append(result)

            status = {0: "HELD", 1: "BORDERLINE", 2: "BREACHED"}[score]
            print(f"\n Logged [{status}]\n")

            another = input(" Try another prompt for this category? (y/n): ").strip().lower()
            if another != "y":
                break

    return results


def print_summary(results: list[dict]):
    total     = len(results)
    breached  = sum(1 for r in results if r["breached"])
    border    = sum(1 for r in results if r["score"] == 1)
    held      = sum(1 for r in results if r["score"] == 0)

    print()
    print("-" * 55)
    print(" Human Red Team Session Summary")
    print("-" * 55)
    print(f" Total attempts : {total}")
    print(f" Model held     : {held}    (score=0, safe)")
    print(f" Borderline     : {border}    (score=1, review needed)")
    print(f" Breached       : {breached}    (score=2, vulnerability confirmed)")

    if breached > 0:
        print()
        print(" Confirmed vulnerabilities:")
        for r in results:
            if r["breached"]:
                print(f"   [{r['category_name']}]")
                print(f"       Prompt   : {r['prompt'][:80]}")
                print(f"       Response : {r['response'][:80]}")
                if r["notes"]:
                    print(f"       Notes    : {r['notes']}")


def save_results(results: list[dict], output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = output_dir / f"human_redteam_{timestamp}.json"

    report = {
        "timestamp": timestamp,
        "tester":    os.environ.get("USERNAME", "unknown"),
        "total":     len(results),
        "breached":  sum(1 for r in results if r["breached"]),
        "borderline": sum(1 for r in results if r["score"] == 1),
        "held":      sum(1 for r in results if r["score"] == 0),
        "results":   results,
    }

    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n Report saved: {report_path}")


def show_reports(output_dir: Path):
    """Show a summary of all past human red team sessions."""
    reports = sorted(output_dir.glob("human_redteam_*.json"), reverse=True)

    if not reports:
        print(f"  No reports found in {output_dir}/")
        print("  Run a session first: python human_redteam/run_human_redteam.py")
        return

    print(f"\n Past sessions ({len(reports)} found):\n")
    for rp in reports:
        with open(rp) as f:
            data = json.load(f)
        print(f"  {data['timestamp']}  |  breached={data['breached']}  borderline={data['borderline']}  held={data['held']}  |  {rp.name}")


def main():
    parser = argparse.ArgumentParser(description="Human Red Team Session Runner")
    parser.add_argument("--report", action="store_true", help="Show past session reports")
    parser.add_argument("--category", default=None, help="Focus on a single attack category ID")
    args = parser.parse_args()

    print()
    print("-" * 55)
    print(" Human Red Team - Manual Attack Session")
    print("-" * 55)

    config     = load_config()
    output_dir = Path(config.get("output_dir", "results/human_redteam"))
    if not output_dir.is_absolute():
        output_dir = PROJECT_ROOT / output_dir

    if args.report:
        show_reports(output_dir)
        return

    check_env()

    if args.category:
        valid_ids = [c["id"] for c in config.get("attack_categories", [])]
        if args.category not in valid_ids:
            print(f"  ERROR: Unknown category '{args.category}'")
            print(f"  Valid: {', '.join(valid_ids)}")
            sys.exit(1)

    print_categories(config.get("attack_categories", []))

    results = run_session(config, filter_category=args.category)

    if results:
        print_summary(results)
        save_results(results, output_dir)
    else:
        print("\n No attempts recorded.")

    print()
    print("-" * 55)
    print(" Session complete.")
    print("  View reports: python human_redteam/run_human_redteam.py --report")
    print("-" * 55)


if __name__ == "__main__":
    main()
