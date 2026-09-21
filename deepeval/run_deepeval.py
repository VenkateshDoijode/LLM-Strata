"""
run_deepeval.py - Run DeepEval LLM safety testing
100% Python, no Node.js required.

Author : Venkateshwara Doijode
Project: LLM Strata - End-to-End LLM Security & Safety Framework

DeepEval tests whether your LLM produces UNSAFE or HARMFUL content.
It complements Garak (which tests attack surface) by testing output safety.

Metrics:
    bias          - gender, racial, political bias
    toxicity      - hate speech, abusive language
    hallucination - fabricated / unsupported facts
    misuse        - jailbreaks, policy violations
    pii           - PII / privacy leakage (SSN, card numbers, passwords)

Requirements:
    pip install deepeval
    Credentials for the active provider must be set

Usage:
    python deepeval/run_deepeval.py                 # full safety scan
    python deepeval/run_deepeval.py --metric bias   # single metric only
    python deepeval/run_deepeval.py --metric pii    # PII leakage only
    python deepeval/run_deepeval.py --verbose       # show per-test details
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import yaml
from env_loader import load_dotenv, require_env
from profile_loader import get_model, active_profile_name
from client_factory import get_client
load_dotenv()


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "deepeval/deepeval_config.yaml"
OUTPUT_DIR = PROJECT_ROOT / "results/deepeval"


def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


def check_env():
    require_provider_env()


def check_deepeval():
    try:
        import deepeval  # noqa: F401
        _ = deepeval
    except ImportError:
        print("  ERROR: deepeval not installed.")
        print("         Run: pip install -r requirements.txt")
        sys.exit(1)


def create_deepeval_model(model_name: str):
    """Adapt the active provider client to DeepEval's custom model interface."""
    from deepeval.models.base_model import DeepEvalBaseLLM

    class ProviderModel(DeepEvalBaseLLM):
        def __init__(self):
            self.model_name = model_name
            self.client = get_client()
            self.model = self.load_model()

        def load_model(self):
            return self.client

        def _generate_text(self, prompt: str) -> str:
            response = self.load_model().chat.completions.create(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.choices[0].message.content or ""

        def generate(self, prompt: str, schema=None):
            text = self._generate_text(prompt)
            if schema is None:
                return text

            payload = text.strip()
            if payload.startswith("```"):
                payload = payload.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                start, end = payload.find("{"), payload.rfind("}")
                if start < 0 or end <= start:
                    raise ValueError("Evaluator returned invalid structured output.") from None
                data = json.loads(payload[start:end + 1])

            if hasattr(schema, "model_validate"):
                return schema.model_validate(data)
            return schema.parse_obj(data)

        async def a_generate(self, prompt: str, schema=None):
            return await asyncio.to_thread(self.generate, prompt, schema)

        def get_model_name(self):
            return self.model_name

    return ProviderModel()


def run_bias_test(model_name: str, test_input: str, verbose: bool,
                  evaluator_model: str = "gpt-4o-mini", threshold: float = 0.5) -> dict:
    from deepeval.metrics import BiasMetric
    from deepeval.test_case import LLMTestCase

    client = get_client()
    response = client.chat.completions.create(
        model=model_name,
        messages=[{"role": "user", "content": test_input}]
    )
    actual_output = response.choices[0].message.content

    metric = BiasMetric(threshold=threshold, model=evaluator_model)
    test_case = LLMTestCase(input=test_input, actual_output=actual_output)
    metric.measure(test_case)

    result = {
        "metric": "bias",
        "input": test_input,
        "score": metric.score,
        "passed": metric.success,  # set by metric.is_successful() - authoritative
        "reason": metric.reason,
    }
    if verbose:
        status = "PASS" if result["passed"] else "FAIL"
        print(f"    [{status}] bias score={metric.score:.2f} | {test_input[:60]}...")
    return result


def run_toxicity_test(model_name: str, test_input: str, verbose: bool,
                      evaluator_model: str = "gpt-4o-mini", threshold: float = 0.5) -> dict:
    from deepeval.metrics import ToxicityMetric
    from deepeval.test_case import LLMTestCase

    client = get_client()
    response = client.chat.completions.create(
        model=model_name,
        messages=[{"role": "user", "content": test_input}]
    )
    actual_output = response.choices[0].message.content

    metric = ToxicityMetric(threshold=threshold, model=evaluator_model)
    test_case = LLMTestCase(input=test_input, actual_output=actual_output)
    metric.measure(test_case)

    result = {
        "metric": "toxicity",
        "input": test_input,
        "score": metric.score,
        "passed": metric.success,  # set by metric.is_successful() - authoritative
        "reason": metric.reason,
    }
    if verbose:
        status = "PASS" if result["passed"] else "FAIL"
        print(f"    [{status}] toxicity score={metric.score:.2f} | {test_input[:60]}...")
    return result


def run_hallucination_test(model_name: str, test_input: str, verbose: bool,
                           evaluator_model: str = "gpt-4o-mini", threshold: float = 0.5) -> dict:
    from deepeval.metrics import HallucinationMetric
    from deepeval.test_case import LLMTestCase

    client = get_client()
    response = client.chat.completions.create(
        model=model_name,
        messages=[{"role": "user", "content": test_input}]
    )
    actual_output = response.choices[0].message.content

    metric = HallucinationMetric(threshold=threshold, model=evaluator_model)
    test_case = LLMTestCase(
        input=test_input,
        actual_output=actual_output,
        context=[test_input],  # use the question itself as the only context - model must not hallucinate beyond it
    )
    metric.measure(test_case)

    result = {
        "metric": "hallucination",
        "input": test_input,
        "score": metric.score,
        "passed": metric.success,  # set by metric.is_successful() - authoritative
        "reason": metric.reason,
    }
    if verbose:
        status = "PASS" if result["passed"] else "FAIL"
        print(f"    [{status}] hallucination score={metric.score:.2f} | {test_input[:60]}...")
    return result


def run_misuse_test(model_name: str, test_input: str, verbose: bool,
                    evaluator_model: str = "gpt-4o-mini", threshold: float = 0.5) -> dict:
    from deepeval.metrics import MisuseMetric
    from deepeval.test_case import LLMTestCase

    client = get_client()
    response = client.chat.completions.create(
        model=model_name,
        messages=[{"role": "user", "content": test_input}]
    )
    actual_output = response.choices[0].message.content

    metric = MisuseMetric(domain="general AI assistant", threshold=threshold, model=evaluator_model)
    test_case = LLMTestCase(input=test_input, actual_output=actual_output)
    metric.measure(test_case)

    result = {
        "metric": "misuse",
        "input": test_input,
        "score": metric.score,
        "passed": metric.success,  # set by metric.is_successful() - authoritative
        "reason": metric.reason,
    }
    if verbose:
        status = "PASS" if result["passed"] else "FAIL"
        print(f"    [{status}] misuse score={metric.score:.2f} | {test_input[:60]}...")
    return result


def run_pii_test(model_name: str, test_input: str, verbose: bool,
                 evaluator_model: str = "gpt-4o-mini", threshold: float = 0.5) -> dict:
    from deepeval.metrics import PIILeakageMetric
    from deepeval.test_case import LLMTestCase

    client = get_client()
    response = client.chat.completions.create(
        model=model_name,
        messages=[{"role": "user", "content": test_input}]
    )
    actual_output = response.choices[0].message.content

    metric = PIILeakageMetric(threshold=threshold, model=evaluator_model)
    test_case = LLMTestCase(input=test_input, actual_output=actual_output)
    metric.measure(test_case)

    result = {
        "metric": "pii",
        "input": test_input,
        "score": metric.score,
        "passed": metric.success,
        "reason": metric.reason,
    }
    if verbose:
        status = "PASS" if result["passed"] else "FAIL"
        print(f"    [{status}] pii score={metric.score:.2f} | {test_input[:60]}...")
    return result


METRIC_RUNNERS = {
    "bias":          run_bias_test,
    "toxicity":      run_toxicity_test,
    "hallucination": run_hallucination_test,
    "misuse":        run_misuse_test,
    "pii":           run_pii_test,
}


def run_all_tests(config: dict, filter_metric: str | None, verbose: bool) -> list[dict]:
    model_name      = get_model("model",           config.get("model",           "gpt-4o-mini"))
    evaluator_model = get_model("evaluator_model", config.get("evaluator_model", "gpt-4o-mini"))
    evaluator       = create_deepeval_model(evaluator_model)
    test_cases      = config.get("test_cases", [])
    metric_thresholds = {
        metric["name"]: metric.get("threshold", 0.5)
        for metric in config.get("metrics", [])
        if isinstance(metric, dict) and metric.get("name")
    }
    results = []

    for tc in test_cases:
        category = tc.get("category")
        test_input = tc.get("input")

        if filter_metric and category != filter_metric:
            continue

        runner = METRIC_RUNNERS.get(category)
        if not runner:
            print(f"    SKIP: unknown category '{category}'")
            continue

        try:
            threshold = metric_thresholds.get(category, 0.5)
            result = runner(model_name, test_input, verbose, evaluator, threshold)
            results.append(result)
        except Exception as e:
            print(f"    ERROR on '{test_input[:50]}...': {e}")
            results.append({
                "metric": category,
                "input": test_input,
                "score": None,
                "passed": False,
                "reason": str(e),
            })

    return results


def print_summary(results: list[dict]):
    total  = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed

    print()
    print("  Safety Test Summary:")
    print(f"    Total  : {total}")
    print(f"    Passed : {passed}  (model refused / responded safely)")
    print(f"    Failed : {failed}  (model produced unsafe content)")

    if failed > 0:
        print()
        print("  Failed tests (model produced unsafe output):")
        for r in results:
            if not r["passed"]:
                score_str = f"{r['score']:.2f}" if r["score"] is not None else "N/A"
                print(f"    [{r['metric'].upper()}] score={score_str}")
                print(f"      Input  : {r['input'][:80]}")
                print(f"      Reason : {r['reason']}")


def save_results(results: list[dict], output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = output_dir / f"safety_report_{timestamp}.json"

    report = {
        "timestamp": timestamp,
        "total": len(results),
        "passed": sum(1 for r in results if r["passed"]),
        "failed": sum(1 for r in results if not r["passed"]),
        "results": results,
    }

    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n  Report saved: {report_path}")


def main():
    parser = argparse.ArgumentParser(description="DeepEval LLM Safety Tester")
    parser.add_argument("--metric", default=None,
                        choices=list(METRIC_RUNNERS.keys()),
                        help="Run a single metric only")
    parser.add_argument("--verbose", action="store_true",
                        help="Show per-test details")
    args = parser.parse_args()

    print()
    print("=" * 55)
    print("  DeepEval - LLM Safety Testing")
    print("=" * 55)

    check_env()
    check_deepeval()

    config = load_config()
    model_name      = get_model("model",           config.get("model", "gpt-4o-mini"))
    evaluator_model = get_model("evaluator_model", config.get("evaluator_model", "gpt-4o-mini"))
    output_dir      = Path(config.get("output_dir", "results/deepeval"))
    if not output_dir.is_absolute():
        output_dir = PROJECT_ROOT / output_dir

    print(f"  Profile         : {active_profile_name()}")
    print(f"  Model under test: {model_name}")
    print(f"  Evaluator model : {evaluator_model}")
    print(f"  Config          : {CONFIG_PATH}")
    print(f"  Metrics         : {args.metric or 'all'}")
    print()
    print("  Running safety tests...")
    print()

    results = run_all_tests(config, filter_metric=args.metric, verbose=args.verbose)
    print_summary(results)
    save_results(results, output_dir)

    print()
    print("=" * 55)
    print(f"  Safety scan complete! Results in: {output_dir}/")
    print("=" * 55)


if __name__ == "__main__":
    main()
