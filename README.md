# ScanHive SARIF Upload Action

Upload SARIF security scan results from GitHub Actions to a ScanHive project.

## Inputs

| Input | Required | Description |
| --- | --- | --- |
| `server-url` | Yes | ScanHive backend URL, including its port when required. |
| `api-key` | Yes | ScanHive API key supplied through a GitHub Actions secret. |
| `project` | Yes | ScanHive project name or UUID. |
| `scan-type` | Yes | `SAST`, `SCA`, `Secrets`, `Container Security`, `IaC`, or `DAST`. |
| `sarif-file` | Yes | Path to the SARIF report. |

## Outputs

| Output | Description |
| --- | --- |
| `scan-id` | UUID of the scan created in ScanHive. |
| `findings` | Number of imported findings. |

## Usage

Create a repository or organization Actions secret named `SCANHIVE_API_KEY`, then add the action after the scanner generates its SARIF report:

```yaml
name: Security scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4

      - name: Run scanner
        run: your-scanner-command --output results.sarif

      - name: Upload SARIF to ScanHive
        id: scanhive
        uses: sechive-labs/scanhive-github-action@1.0.0
        with:
          server-url: "http://127.0.0.1:8000"
          api-key: ${{ secrets.SCANHIVE_API_KEY }}
          project: "00000000-0000-0000-0000-000000000000" # or a project name, e.g. "my-project"
          scan-type: "IaC"
          sarif-file: "results.sarif"

      - name: Show upload summary
        run: echo "ScanHive imported ${{ steps.scanhive.outputs.findings }} findings"
```

Use `127.0.0.1` only when the self-hosted runner and ScanHive backend run on the same machine. Otherwise use a reachable DNS name or LAN address.


