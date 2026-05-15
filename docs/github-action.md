# GitHub Action

The bundled action runs AgentBOM, preserves report artifacts, and can optionally
upload SARIF to GitHub code scanning or fail a workflow when repository risk
meets a chosen threshold.

For demos, first-time rollout, and public repositories with intentional examples,
start with informational artifact mode. This keeps CI green and makes the
JSON/Markdown/HTML reports available without creating GitHub code scanning
alerts.

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
        uses: vlcak27/agentbom@v0.5.1
        with:
          path: .
          # Informational artifact mode for demos and first-time rollout:
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

SARIF upload is optional. Enable it when you want AgentBOM findings to appear in
GitHub code scanning:

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
        uses: vlcak27/agentbom@v0.5.1
        with:
          path: .
          fail-on: none
          sarif-upload: true
          html: true
          output-dir: agentbom-report
```

Use `fail-on: none` for informational mode when introducing AgentBOM to an
existing repository and collecting a baseline. Enforcement mode is optional: set
`fail-on: high` or `fail-on: critical` after expected capabilities are
documented. For CI blocking mode, make the workflow a required branch protection
check so the configured threshold blocks merges while report artifacts, and
optionally SARIF, remain available for review.
