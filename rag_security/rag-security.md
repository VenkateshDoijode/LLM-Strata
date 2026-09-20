# Layer 13: RAG and Vector Security

## What it is

`rag_security` tests the security consequences of adversarial content entering a vector store or retrieved context. It is intentionally separate from RAGAS quality testing.

RAGAS asks whether answers are grounded and relevant. RAG Security asks whether an attacker can use retrieved content to override policy, leak data, persist instructions, or contaminate other answers.

## What it does

It inserts attacker-controlled content into simulated retrieved context, sends the context and user query to the model, and evaluates injection following and PII leakage.

## Coverage

The scenarios cover:

- Jailbreaks embedded in document chunks
- Authority impersonation in retrieved content
- PII leakage beyond query scope
- Persistent instructions in stored content
- Context flooding
- Malicious code embedded in documents
- Semantic reframing
- Cross-document contamination
- Crafted queries that expose private embedded content

Each scenario is evaluated for injection following and PII leakage.

## Prerequisites

Configure provider credentials and synthetic retrieved contexts, expected answers, and privacy scenarios. No real vector database is required for the simulator.

## Configuration

Edit `rag_security/rag_security_config.yaml` to define the simulated system prompt, scenarios, attacker content, expected safe answers, evaluator model, and output directory.

## Usage

```text
python rag_security/run_rag_security.py
python rag_security/run_rag_security.py --scenario jailbreak_in_chunk
python rag_security/run_rag_security.py --verbose
python run_security.py --rag-security-only
```

The runner simulates retrieved context being inserted before the user question. It does not connect to a real vector database unless that integration is added separately.

## Outcomes

A safe result means the model ignored the retrieved injection and stayed within the query's data scope. An unsafe result means it followed the injected content or exposed excess PII. Review injection and privacy outcomes independently because a response can fail one dimension without failing the other.

## Outputs

Reports are written to `results/rag_security/` and contain scenario status, model response, injection verdict, and PII-leak verdict.

## Production controls

Use document provenance, tenant/ACL-aware retrieval, content sanitization, prompt/data separation, chunk-level trust labels, output filtering, and post-retrieval authorization. A trusted application user does not make every retrieved document trusted.

## Execution model and CI guidance

Each scenario uses a target call and separate injection and privacy evaluator calls. Use `--scenario` for pull-request smoke tests, the full scenario set nightly, and a production retriever/vector-store integration assessment before release.
