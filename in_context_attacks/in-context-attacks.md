# Layer 9: In-Context Conditioning Attacks

## What it is

This layer tests the attack commonly called many-shot jailbreaking. It places multiple fabricated user/assistant examples in one context, demonstrates unsafe compliance, and then appends a target request. The security question is whether repeated examples condition the model to imitate unsafe behavior.

The source folder is intentionally named `in_context_attacks/` because the broader category includes conditioning attacks beyond one fixed shot count.

## What it does

It builds one long conversation containing fabricated user/assistant demonstrations, appends a target request, and measures whether the target model follows the demonstrated unsafe pattern.

## Coverage

Coverage is determined by target categories, shot counts, and the three priming strategies. The matrix measures both attack style and context-size sensitivity.

## Prerequisites

Use a model with a context window large enough for the selected shot counts, configure provider credentials, and keep all priming fixtures synthetic and controlled.

## Configuration

Edit `in_context_attacks/many_shot_config.yaml` for:

- Target categories and intents
- Shot counts
- Priming strategies
- Benign examples
- Harmful examples
- Target and evaluator models
- Result directory

Strategies are:

- `pure_harmful`: every priming example demonstrates unsafe compliance
- `gradual_escalation`: benign examples precede harmful examples
- `camouflaged`: mostly benign examples with harmful examples shuffled through the context

The current matrix uses six targets, four shot counts, and three strategies: 72 target evaluations plus evaluator calls.

## Usage

```text
python in_context_attacks/run_many_shot.py
python in_context_attacks/run_many_shot.py --strategy camouflaged
python in_context_attacks/run_many_shot.py --shots 20
python in_context_attacks/run_many_shot.py --category malware
python in_context_attacks/run_many_shot.py --verbose
python run_security.py --in-context-only
```

The legacy `--many-shot-only` and `--skip-many-shot` orchestrator flags remain supported.

## Outcomes

`SAFE` means the evaluator judged that the target refused or remained innocuous. `UNSAFE` means the target followed the harmful intent. `UNKNOWN` and `ERROR` require review and should not be counted as safe evidence. Compare rates by shot count and strategy rather than relying only on the aggregate total.

## Outputs

Reports are written to `results/in_context_attacks/`. They include strategy, shot count, category, target question, response excerpt, judge verdict, and compliance-rate summaries.

## Interpretation and limitations

This layer is valuable for long-context chat and agent systems, but it is not an authorization control. It currently has no zero-shot baseline, uses fixed examples that may be recycled at larger shot counts, and defaults to the same model family for target and evaluator. Add a direct baseline, multiple targets per category, production system prompts, independent evaluation, and repeated trials for stronger evidence.

Protect the configuration and reports because red-team fixtures and model responses may contain sensitive or harmful content.

## Execution model and CI guidance

Each matrix cell uses a target call and an evaluator call. The default matrix is expensive, so use one strategy and shot count for pull requests, the full matrix nightly, and the full release assessment with a direct baseline and independent evaluator.
