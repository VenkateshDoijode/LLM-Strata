# Layer 2: DeepEval Safety Evaluation

## What it is

DeepEval evaluates the safety and quality of model outputs rather than only testing whether an attack can reach the model. It is useful for measuring harmful behavior, bias, toxicity, hallucination, misuse, and privacy leakage.

## What it does

It sends each configured test input to the target model, evaluates the resulting output with one or more safety metrics, and records a score, pass/fail decision, and evaluator reason.

## Coverage

Coverage is determined by the configured metric list and test cases. The default metric families are bias, toxicity, hallucination, misuse, and PII leakage.

## Prerequisites

Install the pinned DeepEval dependencies and configure credentials for the active provider. The runner uses `client_factory.py` for both the target and evaluator models, so it supports OpenAI, Azure OpenAI, Ollama, Google Gemini, Hugging Face, Anthropic through LiteLLM, AWS Bedrock through LiteLLM, and private OpenAI-compatible endpoints.

## Metrics

The runner supports the configured metric set, including:

- `bias`: demographic, political, or other unfair bias
- `toxicity`: abusive, hateful, or unsafe language
- `hallucination`: unsupported or fabricated claims
- `misuse`: jailbreak and policy-violation behavior
- `pii`: exposure of personal or sensitive information

The exact cases, thresholds, evaluator model, and enabled metrics are in `deepeval/deepeval_config.yaml`.

## How it works

For each configured input, the runner sends the input to the target model, evaluates the output with the selected DeepEval metric, and records the metric score, pass/fail decision, and reason. The evaluator model and thresholds must be treated as part of the test configuration because changing them changes the result.

## Usage

```text
python deepeval/run_deepeval.py
python deepeval/run_deepeval.py --metric bias
python deepeval/run_deepeval.py --metric pii
python deepeval/run_deepeval.py --verbose
python run_security.py --deepeval-only
```

Requirements include the DeepEval package and credentials required by the active provider profile. Provider/model selection is controlled by `profiles.yaml` or `ACTIVE_PROFILE`; Anthropic and Bedrock also require LiteLLM, and Bedrock requires `boto3`.

## Outcomes

Each case produces a metric score, a pass/fail result, and an evaluator reason. A failed threshold identifies a safety or quality gap for that metric; an evaluator error or missing score is not evidence that the model passed.

## Outputs

JSON safety reports are written to `results/deepeval/`. Keep reports protected because they can contain prompts, model responses, and potentially sensitive test data.

## Interpretation and limitations

A threshold pass means the output met the configured metric threshold for that case; it is not a universal safety certification. LLM-as-judge metrics can be inconsistent, and a single prompt per category is weak evidence. Use representative datasets, repeat important cases, review borderline scores, and combine DeepEval with adversarial testing and runtime controls.

## Execution model and CI guidance

Each test calls the target model and evaluates the response with the configured DeepEval metric, so cost grows with test cases and enabled metrics. Use one metric or a small corpus for pull requests, the full corpus nightly, and a stronger independent evaluator before release. Treat missing scores and evaluator errors as inconclusive.
