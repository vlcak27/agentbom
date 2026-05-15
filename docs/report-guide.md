# Report Guide

AgentBOM reports are designed for mixed engineering, security, and governance
reviews. The scanner does not execute code and does not claim exploitability.
It records static evidence, source paths, confidence, and rationale.

## Read order

1. Repository risk: a compact severity and score with rationale.
2. Review priorities: the shortest queue of findings to triage first.
3. Reachable capabilities: AI actors connected to sensitive actions.
4. Policy findings: controls that appear missing or violated.
5. Component sections: providers, models, frameworks, MCP config, prompts,
   dependencies, and secret references.

## Terms

- Provider: AI service or runtime vendor such as OpenAI, Anthropic, or Gemini.
- Model: concrete model identifier found by static pattern matching, such as
  `gpt-5.5`, `claude-opus-4.7`, `gemini-2.5-pro`, or
  `openrouter/openai/gpt-5.5`.
- Framework: agent orchestration library such as LangChain or CrewAI.
- Capability: static evidence of a sensitive action, such as shell or network.
- Reachable capability: an inferred relationship from an AI actor to a
  capability.
- Policy finding: a missing control or custom policy violation.

## Model evidence

Model findings separate the normalized model name from the source evidence. For
example, `openrouter/openai/gpt-5.5` is stored as the model name `gpt-5.5`, while
the evidence field keeps the provider-prefixed string seen in the scanned file.
This keeps graphs and summaries grouped by model while preserving the exact text
reviewers need to inspect.

Provider-prefixed strings are common in router and proxy configurations. A value
such as `openrouter/anthropic/claude-opus-4.7` is static evidence of the model
identifier and route style; it is not proof that the repository can reach that
provider at runtime.

## What to do with findings

For expected capabilities, document the control in policy files and keep the
source path easy to review. For unexpected capabilities, remove the code path,
isolate it behind a sandbox or approval boundary, or make the repository policy
explicit about why it exists.

Secret reference findings require credential hygiene review only. AgentBOM
records names such as `OPENAI_API_KEY`; it must not store or print secret values.
