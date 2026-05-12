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
- Model: concrete model identifier such as `gpt-4o` or `claude-3-sonnet`.
- Framework: agent orchestration library such as LangChain or CrewAI.
- Capability: static evidence of a sensitive action, such as shell or network.
- Reachable capability: an inferred relationship from an AI actor to a
  capability.
- Policy finding: a missing control or custom policy violation.

## What to do with findings

For expected capabilities, document the control in policy files and keep the
source path easy to review. For unexpected capabilities, remove the code path,
isolate it behind a sandbox or approval boundary, or make the repository policy
explicit about why it exists.

Secret reference findings require credential hygiene review only. AgentBOM
records names such as `OPENAI_API_KEY`; it must not store or print secret values.
