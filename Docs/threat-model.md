# Threat Model

## Scope

This framework evaluates LLM-powered applications before and after deployment. It focuses on model behavior, prompt handling, RAG context, agent tools, memory policies, runtime scanning, and operational monitoring.

It is not a replacement for infrastructure security, identity-provider configuration, database security, network security, software supply-chain scanning, or application penetration testing.

## Protected assets

- System and developer instructions
- User prompts and conversation history
- Personal, financial, health, and confidential business data
- Tool permissions and side-effecting actions
- Agent memory and tenant boundaries
- RAG documents, embeddings, and retrieval metadata
- Model/provider credentials
- Security reports and LangFuse traces
- Application availability and cost budget

## Threat actors

- A malicious or compromised end user
- An attacker who controls a document, email, web page, database row, or calendar entry
- A user attempting privilege escalation or authority impersonation
- A malicious fine-tuning or training-data contributor
- A prompt-injection payload in retrieved context
- A compromised or misconfigured provider endpoint
- An evaluator or scanner failure that causes a team to misread results

## Trust assumptions

The following are untrusted unless explicitly validated:

- User prompts
- Model outputs
- Retrieved documents
- Tool results
- Assistant-generated tool arguments
- Human-entered red-team prompts
- Test configuration values supplied from outside source control

The following should be protected:

- API keys and provider endpoints
- Role and tool policies
- System prompts
- Tenant identifiers
- Report storage
- LangFuse credentials

## Threat coverage mapping

| Threat | Primary layers |
|---|---|
| Direct jailbreak and unsafe output | Garak, DeepEval, PyRIT |
| Prompt injection | Garak, LLM Guard, Tool Injection, RAG Security |
| Multi-turn escalation | PyRIT, Agent Security, Human Red Team |
| In-context conditioning | In-Context Attacks |
| Encoding and obfuscation | Encoded Attacks, Garak red-team probes |
| Cross-language evasion | Multilingual Attacks |
| Trigger sensitivity | Backdoor Triggers |
| PII output leakage | DeepEval, RAGAS, LLM Guard, RAG Security |
| Tool privilege misuse | Agent Security, Tool Injection |
| Memory isolation | Agent Security |
| Production drift | LangFuse |

## Out of scope

The framework does not prove that:

- A real database enforces tenant isolation
- A real tool implementation validates arguments safely
- A model cannot leak secrets outside the configured prompts
- A provider retains or processes data according to your policy
- A vector index is free of unauthorized writes
- A scanner catches semantic or novel attacks
- A human review process is complete

Use the results to drive remediation and further testing, not as a security certification.
