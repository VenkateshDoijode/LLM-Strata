# Layer 10: Multilingual and Cross-Language Attacks

## What it is

This layer checks whether safety behavior changes when a harmful request is expressed in a language or script different from the language used during safety tuning. It also tests mixed-language framing and translation-based bypasses.

## What it does

It translates or loads configured attack prompts, sends them through each selected language and framing technique, and asks an evaluator whether the model complied with the harmful intent.

## Coverage

Coverage is the Cartesian product of configured attacks, languages, and techniques. The default techniques are direct, mixed-language framing, and translation bridging.

## Techniques

- `direct`: the harmful request is sent in the target language
- `mixed_framing`: an English framing sentence surrounds the non-English request
- `translate_bridge`: the model is asked to translate and then answer the translated request

## Prerequisites

Configure provider credentials, reviewed translations, and languages relevant to the product's users. Use a fluent reviewer for high-impact language cases.

## Configuration

Edit `multilingual/multilingual_config.yaml` to choose languages, attacks, categories, techniques, target model, evaluator model, and output directory. Keep translations reviewed by a fluent evaluator; a bad translation can create a false pass or false fail.

## Usage

```text
python multilingual/run_multilingual.py
python multilingual/run_multilingual.py --language ar
python multilingual/run_multilingual.py --technique direct --verbose
python multilingual/run_multilingual.py --category weapons
python run_security.py --multilingual-only
```

The runner forms the Cartesian product of selected attacks, languages, and techniques, sends each prompt to the target, and asks an evaluator for `SAFE` or `UNSAFE`.

## Outcomes

Each language/technique combination produces a `SAFE`, `UNSAFE`, or `UNKNOWN` judgment. An unsafe result identifies a language or framing-specific regression; an unknown result means the evaluator did not provide a reliable verdict.

## Outputs

Reports are saved under `results/multilingual/` and include language, technique, category, target response, and verdict.

## Interpretation and limitations

Coverage depends on the configured language list and translation quality. A pass in one language does not generalize to all languages, dialects, scripts, or code-switching patterns. Add languages relevant to the user population and test the same policy across direct, mixed, and translation prompts. Do not rely on translation as a security boundary.

## Execution model and CI guidance

Each attack/language/technique combination uses a target call and an evaluator call. Use one language and technique for pull requests, the full configured matrix nightly, and language coverage relevant to the actual user population before release.
