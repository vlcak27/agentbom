# GitHub Action

The bundled action runs AgentBOM, uploads SARIF to GitHub code scanning, and can
fail a workflow when repository risk meets a chosen threshold.

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
        uses: vlcak27/agentbom@v0.5.0
        with:
          path: .
          fail-on: high
          sarif-upload: true
          html: true
          output-dir: agentbom-report

      - name: Upload AgentBOM reports
        uses: actions/upload-artifact@v4
        with:
          name: agentbom-report
          path: agentbom-report/
```

Use `fail-on: none` when introducing AgentBOM to an existing repository and
collecting a baseline. Raise the threshold after expected capabilities are
documented.
