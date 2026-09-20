# Layer 1: Garak Vulnerability Scanning

## What it is

Garak is the broad pre-deployment vulnerability scanner. It sends curated probe families to the target model and looks for known failure patterns such as jailbreaks, prompt injection, leakage, misleading instructions, and unsafe continuations.

Garak is best used for breadth and regression discovery. It is not an authorization layer and it does not enforce runtime policy.

## What it does

It runs a selected Garak probe preset against the target model, collects scanner findings, and produces artifacts that can be triaged and reproduced. It is the broadest pre-deployment discovery layer in the pipeline.

## Coverage

Coverage depends on the selected preset and installed Garak version. The repository presets include jailbreak, prompt-injection, leakage, encoding, social-engineering, continuation, and misleading-input probes.

## How it works

`garak/run_garak.py` selects a probe preset, resolves the target model and provider, and invokes Garak in the isolated `.venv-garak` environment. The wrapper uses the current Garak CLI convention (`--spec`) while maintaining the repository's preset names.

Presets are:

- `quick`: a small, fast signal set
- `standard`: the default pre-deployment scan
- `redteam`: more aggressive probes, including encoding and generated attacks
- `all`: every available probe; expect substantially higher cost and runtime

## Prerequisites

Python 3.10-3.12 is recommended, Garak must be installed in `.venv-garak`, and the selected target/provider must be configured.

## Configuration

Edit `garak/garak_config.yaml` for the default model, model type, and report directory. Command-line values such as `--model`, `--target_type`, and `--probes` override the corresponding defaults.

## Usage

```text
python setup.py
python garak/run_garak.py
python garak/run_garak.py --probes quick
python garak/run_garak.py --probes redteam
python garak/run_garak.py --probes all
python garak/run_garak.py --target_type ollama --model llama2
python run_security.py --garak-depth standard
```

The isolated environment must contain Garak. `python setup.py` creates or prepares it. `GARAK_PYTHON` can point to a different Garak interpreter when required.

## Outcomes

A useful outcome is a reproducible probe result showing which input caused a failure and whether it was a confirmed hit. Treat hit records as findings to triage; an empty hit log means no configured probe confirmed a vulnerability, not that the application is safe.

## Outputs

Reports use `results/garak/` as the report prefix. A scan can produce screen progress, a report log, a hit log containing confirmed findings, and a debug log.

## Interpretation and limitations

Prioritize hit logs and reproduce important findings against the actual application wrapper. Probe coverage is model- and version-dependent. A clean Garak scan does not validate application authorization, RAG access controls, memory isolation, or runtime monitoring.

## Execution model and CI guidance

Garak runs in `.venv-garak` and invokes the external scanner. It may generate substantial traffic and multiple log files. Use `quick` for pull requests, `standard` for scheduled scans, and `redteam` or `all` before releases. CI should preserve artifacts and distinguish Garak execution errors from a clean vulnerability result.
