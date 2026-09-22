---
name: cloud-security-testing
description: Discover internet-facing cloud assets and audit cloud account configuration with Sentari. Lists exposed assets in your own AWS, Azure, or GCP account, and runs a Prowler misconfiguration audit mapped to evidence-backed findings. Use when the user wants to check cloud security posture, find exposed cloud assets, or audit an AWS/Azure/GCP/Kubernetes account they control.
license: Proprietary
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# Cloud security testing with Sentari

These use your own cloud credentials against your own account. They enumerate and audit configuration; they do not attack anything.

## Discover internet-facing assets

```bash
sentari --cloud aws        # also: azure, gcp
```

Lists internet-facing assets from your account so you can bring the ones you own into scope, then scan those endpoints with `--scope`. AWS uses boto3; Azure needs `AZURE_SUBSCRIPTION_ID`; GCP needs `GOOGLE_CLOUD_PROJECT`. Install with `pip install ".[cloud]"`. Enumerate only, never scanned automatically.

## Audit account configuration (Prowler)

```bash
sentari <account-or-host> --scope <scope> --authorized --cloud-audit aws
```

Runs Prowler (`pip install prowler`) against your account and maps its failed checks (severity, resource, region, service) to findings. Supports `aws`, `azure`, `gcp`, `kubernetes`. Graceful when Prowler is not installed.

## Bring discovered endpoints into a normal scan

Take an endpoint you own from the discovery step and assess it like any web target:

```bash
sentari https://my-service.example.com --scope my-service.example.com --authorized --browser --html cloud-report.html
```
