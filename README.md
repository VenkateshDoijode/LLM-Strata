# results/ — Dummy Test Evidence

Generated: 2026-09-20T08:03:24.907321+00:00

This folder contains SAMPLE / DUMMY test-evidence JSON reports for every
LLM Strata testing module, matching the exact output schema each
`run_*.py` script writes via its own `save_results()` / `save_report()`
function. All prompts, responses, and scores are placeholder values
(prefixed `[DUMMY]` where applicable) — none of this was produced by an
actual model run. Replace it by simply running the real scripts, e.g.:

    python run_security.py

which will overwrite these files with genuine, timestamped reports in
the same locations.

Folders:
- garak/                 dummy Garak-style JSONL scan report
- deepeval/               dummy DeepEval safety_report_*.json
- ragas/                  dummy RAGAS rag_safety_report_*.json
- pyrit/                  dummy PyRIT redteam_report_*.json
- llm_guard/              dummy LLM Guard guard_report_*.json
- human_redteam/          dummy human_redteam_*.json
- encoded_attacks/        dummy encoded_attacks_*.json
- in_context_attacks/     dummy many_shot_*.json
- multilingual/           dummy multilingual_*.json
- tool_inject/            dummy tool_inject_*.json
- backdoor/               dummy backdoor_*.json
- rag_security/           dummy rag_security_*.json
- agent_security/         dummy agent_security_*.json
