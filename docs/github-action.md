# GitHub Action

The action runs AgentBOM in GitHub Actions. It writes report artifacts. It can
also upload SARIF to GitHub code scanning or fail the workflow when repository
risk meets a chosen threshold.

For demos, initial adoption, and repositories with intentional examples, start
with informational mode. This writes JSON/Markdown/HTML reports without failing
CI or creating code scanning alerts. The action defaults are stricter, so set
`fail-on: none` and `sarif-upload: false` explicitly for a non-blocking first
run.

```yaml
name: AgentBOM

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run AgentBOM
        uses: vlcak27/agentbom@v0.6.0
        with:
          path: .
          # Informational mode:
          # publish reports without blocking CI or creating code scanning alerts.
          fail-on: none
          sarif-upload: false
          html: true
          output-dir: agentbom-report

      - name: Upload AgentBOM reports
        uses: actions/upload-artifact@v4
        with:
          name: agentbom-report
          path: agentbom-report/
```

SARIF upload is optional. Enable it only when you want AgentBOM findings to
appear in GitHub code scanning:

```yaml
permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run AgentBOM
        uses: vlcak27/agentbom@v0.6.0
        with:
          path: .
          fail-on: none
          sarif-upload: true
          html: true
          output-dir: agentbom-report
```

## Modes

Informational mode:

- Set `fail-on: none`.
- Set `sarif-upload: false`.
- Keep `html: true` and upload `agentbom-report/` as an artifact.
- Use this mode to inspect a baseline without failing CI.

SARIF review mode:

- Set `sarif-upload: true`.
- Grant `security-events: write`.
- Keep `fail-on: none` if you want code scanning alerts without blocking CI.

Enforcement mode:

- Set `fail-on: high` or `fail-on: critical` after expected capabilities are
  documented.
- Keep report artifacts enabled so reviewers can inspect the reason for a
  failure.
- Make the workflow a required branch protection check only after the threshold
  matches the repository policy.
