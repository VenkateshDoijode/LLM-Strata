# Layer 8: Encoded and Obfuscated Attacks

## What it is

Encoded attacks test whether surface-level filters can be bypassed when harmful intent is transformed. A scanner may miss an encoded string even when the target model can decode it and comply.

## What it does

It transforms configured prompts, checks whether a surface scanner catches each transformed input, sends the result to the target model, and records scanner bypass and model-compliance outcomes.

## Coverage

The runner supports 12 transformations:

- Base64
- ROT13
- Hex
- URL encoding
- Leetspeak
- Homoglyphs
- Reversed text
- Zero-width characters
- Spaced characters
- Binary
- Morse
- Combined Base64 and ROT13

The module measures both scanner bypass and target-model compliance.

## How it works

The runner transforms configured attack prompts, checks whether its surface scanner catches the transformed text, sends the transformed prompt to the target, and judges whether the model complied. The local scanner mirrors the basic LLM Guard regex/keyword approach so bypasses can be compared directly.

## Prerequisites

Configure provider credentials, a synthetic attack corpus, and the encoding methods relevant to the application. The runner requires the shared YAML and client dependencies.

## Configuration

Edit `encoded_attacks/encoded_attacks_config.yaml` to add categories, prompts, encoders, models, and output settings.

## Usage

```text
python encoded_attacks/run_encoded_attacks.py
python encoded_attacks/run_encoded_attacks.py --verbose
python encoded_attacks/run_encoded_attacks.py --encoding base64
python encoded_attacks/run_encoded_attacks.py --category jailbreak
python encoded_attacks/run_encoded_attacks.py --list-encodings
python run_security.py --encoded-only
```

## Outcomes

Each case distinguishes scanner detection from model behavior. A scanner bypass with a `SAFE` model response is a filtering gap; an `UNSAFE` response is a model safety gap; both together indicate a higher-priority defense-in-depth failure.

## Outputs

Reports are saved under `results/encoded_attacks/` with the encoding, category, scanner result, model response, judge verdict, and bypass/compliance measurements.

## Interpretation and limitations

A scanner bypass is not automatically a model breach; both values must be reviewed. The set of transformations is finite and does not cover every Unicode, serialization, compression, or application-specific decoding path. Add tests for transformations accepted by the real product and ensure downstream components do not decode untrusted content and execute it without policy checks.

## Execution model and CI guidance

Each base attack is paired with each selected encoding and usually requires a target call plus an evaluator call. Use one encoding and one category for pull requests, the full matrix nightly, and review scanner bypasses separately from `UNSAFE` model responses.
