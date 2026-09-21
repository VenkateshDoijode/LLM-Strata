# Layer 6: LangFuse Production Monitoring

## What it is

LangFuse is the post-deployment observability layer. Unlike the pre-deployment scanners, it records traces of model requests and responses, attaches safety scores, and supports trend and drift analysis over time.

Use it to answer operational questions such as:

- Are unsafe scores increasing after a model or prompt change?
- Which request classes generate the most borderline results?
- Which model/provider profile has the highest failure rate?
- Can an incident be correlated with a specific trace?

## What it does

It records model requests and responses as traces, attaches safety or quality scores, and makes the data available for operational investigation and trend analysis.

## Coverage

Coverage is determined by the requests that are traced, the configured scores and tags, and the production traffic that is instrumented. It supports monitoring of toxicity, relevance, suspicious conversations, and safety drift rather than exhaustive attack discovery.

## Prerequisites

Install the LangFuse v4 SDK, configure `LANGFUSE_PUBLIC_KEY` and `LANGFUSE_SECRET_KEY`, and provide credentials for the active target/scorer provider.

## Configuration

Configure `langfuse/langfuse_config.yaml` and set:

- `LANGFUSE_PUBLIC_KEY`
- `LANGFUSE_SECRET_KEY`
- `LANGFUSE_BASE_URL` (optional)
- Credentials for the active LLM provider

The runner targets the LangFuse v4 API. Keep keys in environment variables and never place them in configuration files or reports.

## Usage

```text
python langfuse/run_langfuse.py
python langfuse/run_langfuse.py --verify
python run_security.py --langfuse-only
```

`--verify` checks connectivity without sending the normal demo traces. The normal command sends configured demo requests and scores them for safety and relevance.

## Outcomes

A successful run creates trace and score data that can be queried in the dashboard. A failed verification means that telemetry is unavailable or misconfigured; it should be treated as an observability incident rather than as a safe-model result.

## Outputs

Primary results are stored in the LangFuse dashboard rather than in a local JSON directory. The runner prints the host and trace status.

## Interpretation and limitations

Monitoring is not prevention. A trace can reveal a failure after it has occurred, but monitoring does not replace input scanning, output filtering, tool authorization, or incident response. Configure data retention and masking carefully, because traces can contain prompts, responses, personal data, or secrets. Use tags and stable names so that dashboards can support release-to-release comparison.

## Execution model and CI guidance

The runner sends demo requests and scorer requests, and writes telemetry to the external LangFuse service. Use `--verify` for connectivity checks, and keep the demo out of ordinary pull-request gates unless the required keys and a data policy are available. Production integration should instrument real application requests with masking and explicit retention settings.
