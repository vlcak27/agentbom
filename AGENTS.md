# AGENTS.md

## Project

AgentBOM is a minimal open-source CLI that generates a bill of materials for AI agents.

## Role of coding agents

When working on this repository, act as a careful open-source maintainer.

Prefer small, reviewable changes.

Do not add unnecessary abstractions.

Do not add runtime dependencies unless explicitly requested.

## Engineering rules

- Keep code simple and readable.
- Prefer explicit pattern matching over complex static analysis for v0.1.
- Every scanner finding must include:
  - type
  - name
  - source_file
  - confidence
- Evidence must be short and must never contain secret values.
- Never store real secret values.
- Never print real secret values.
- Never commit `.env` files.
- Add or update tests for every detector change.
- Keep JSON output stable and easy to extend.
- Do not implement CycloneDX or SPDX in v0.1.
- Do not implement signing in v0.1.
- Do not implement network calls in v0.1.
- The scanner must work offline.

## Security rules

Do not read files larger than 1 MB.

Do not scan binary files.

Do not follow symlink loops.

Do not execute code from scanned repositories.

Do not import scanned repository code.

Do not evaluate scanned files.

The scanner must only inspect files as text.

## Commands

Install locally:

```bash
pip install -e ".[dev]"
