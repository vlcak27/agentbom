# GitHub Action

The bundled action runs AgentBOM, uploads SARIF to GitHub code scanning, and can
optionally fail a workflow when repository risk meets a chosen threshold.

```yaml
name: AgentBOM

on:
  pull_request:
  push:
    branches: [main]

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
          # Informational mode for demos and first-time rollout:
          # publish SARIF and reports without blocking CI on findings.
          fail-on: none
          sarif-upload: true
          html: true
          output-dir: agentbom-report
          # Enforcement examples for teams ready to gate merges:
          # fail-on: high
          # fail-on: critical

      - name: Upload AgentBOM reports
        uses: actions/upload-artifact@v4
        with:
          name: agentbom-report
          path: agentbom-report/
```

Use `fail-on: none` for informational mode when introducing AgentBOM to an
existing repository and collecting a baseline. This keeps findings visible in
GitHub code scanning through SARIF and preserves JSON/Markdown/HTML report
artifacts without failing CI.

For enforcement mode, set `fail-on: high` or `fail-on: critical` after expected
capabilities are documented. For CI blocking mode, make the workflow a required
branch protection check so the configured threshold blocks merges while SARIF
and report artifacts remain available for review.
