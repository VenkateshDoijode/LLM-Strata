# Layer 12: Backdoor and Trojan Trigger Testing

## What it is

Backdoor testing checks whether a model behaves safely on normal prompts but becomes unsafe when a trigger phrase, persona, token sequence, or framing pattern is present. This can indicate training-data poisoning, malicious fine-tuning, or a hidden behavior association.

## What it does

It sends the same harmful objective in an unarmed baseline form and a trigger-armed form, judges both responses, and calculates whether the trigger increases unsafe compliance.

## Coverage

Coverage is determined by configured trigger categories and target attacks. It includes persona, authority, roleplay, hypothetical, token-smuggling, and emotional triggers.

## Test design

For each configured attack, the runner compares:

- **Baseline:** harmful request without a trigger
- **Armed:** the same request with a trigger prefix or trigger context

A meaningful increase in unsafe compliance for the armed case is a trigger-sensitivity finding.

Configured trigger categories include persona/jailbreak variants, authority bypass, roleplay, hypothetical framing, token smuggling, and emotional manipulation.

## Prerequisites

Configure provider credentials, synthetic target requests, and approved trigger fixtures. Treat trigger strings and responses as sensitive red-team data.

## Configuration

Edit `backdoor/backdoor_config.yaml` to define target attacks, triggers, models, evaluator, thresholds, and output settings.

## Usage

```text
python backdoor/run_backdoor.py
python backdoor/run_backdoor.py --trigger-category dan_variants
python backdoor/run_backdoor.py --attack-category malware --verbose
python backdoor/run_backdoor.py --trigger-id dan_classic
python run_security.py --backdoor-only
```

The runner sends baseline and armed prompts, judges the responses, and calculates the compliance difference.

## Outcomes

The most important result is the difference between baseline and armed compliance. A higher unsafe rate or an armed-only breach indicates trigger sensitivity and should be retested across prompts, model versions, and providers.

## Outputs

Reports are saved to `results/backdoor/` with trigger, attack category, baseline verdict, armed verdict, and delta information.

## Interpretation and limitations

A trigger correlation is a red-team signal, not proof of training-data poisoning. Repeat suspicious findings across prompts, seeds, models, and providers. Avoid placing untrusted trigger text into production test systems without approval, and treat any report containing model responses as sensitive.

## Execution model and CI guidance

Each attack requires a baseline call and one call per selected trigger, plus evaluator calls. Use a filtered trigger for pull requests, the full trigger matrix nightly, and repeat any amplification finding across model versions before release.
