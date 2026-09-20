# Layer 3: RAGAS Retrieval-Augmented Generation Safety

## What it is

RAGAS tests a simulated RAG pipeline for both answer quality and safety. It is focused on whether the model uses retrieved context correctly and whether poisoned or irrelevant context changes the answer.

This layer is different from `rag_security`: RAGAS emphasizes quality and groundedness, while RAG Security focuses on adversarial retrieval and access-control consequences.

## What it does

It simulates retrieval by placing configured context beside a user question, obtains an answer, and scores grounding, relevance, precision, recall, and poisoning behavior.

## Coverage

The configured cases can exercise:

- Context poisoning
- Faithfulness and hallucination
- Answer relevancy
- Context precision and recall
- Retrieval-based jailbreaks
- PII over-exposure
- Authority overrides embedded in documents
- Context flooding and semantic reframing

The runner places a system instruction and retrieved context into a simulated request, obtains an answer, and scores it with RAGAS metrics.

## Prerequisites

Install the repository's RAGAS-compatible dependencies, configure provider credentials, and prepare synthetic questions, contexts, and references.

## Configuration

Edit `ragas/ragas_config.yaml` to add questions, retrieved contexts, ground truth, poisoned flags, models, and thresholds. Mark adversarial cases with `poisoned: true` so the report can distinguish normal and poisoned retrieval tests.

## Usage

```text
python ragas/run_ragas.py
python ragas/run_ragas.py --verbose
python ragas/run_ragas.py --poisoned-only
python run_security.py --ragas-only
```

The repository expects the RAGAS API used by the installed version and requires the RAGAS/OpenAI dependencies plus provider credentials.

## Outcomes

Each case reports faithfulness, answer relevancy, context precision, and context recall. Poisoned cases also report whether poisoning was detected. A good quality score does not override an access-control or provenance failure.

## Outputs

Reports are written under `results/ragas/` and include answer quality scores, poisoning detection, and per-case details.

## Interpretation and limitations

A high faithfulness score does not prove that retrieved content is trustworthy; a model can faithfully follow malicious text. Review poisoned cases separately and enforce document provenance, tenant isolation, retrieval filtering, and output authorization in the real application. The simulated pipeline is not a substitute for testing the production retriever and prompt assembly code.

## Execution model and CI guidance

Each case calls the target model and several RAGAS scoring components, so it is more expensive than a simple prompt test. Use a small smoke set for pull requests, poisoned-only or targeted cases for development, and the complete corpus nightly or before release. RAGAS failures should be triaged separately from retrieval-security failures.
