---
name: cloud-security-testing
description: Discover internet-facing cloud assets and audit cloud account configuration with Sentari. Lists exposed assets in your own AWS, Azure, or GCP account, and runs a Prowler misconfiguration audit mapped to evidence-backed findings. Use when the user wants to check cloud security posture, find exposed cloud assets, or audit an AWS/Azure/GCP/Kubernetes account they control.
license: AGPL-3.0-or-later
metadata:
  author: Ahmad
  homepage: https://github.com/ahmadoqsrawi/sentari
---

# Cloud security testing with Sentari

These use your own cloud credentials against your own account. They enumerate and audit configuration; they do not attack anything. Install and the full flag set are in the **penetration-testing-with-sentari** skill.

## 1. Confirm scope and credentials

- The account is the user's or they are authorized to audit it.
- Standard cloud credentials must be available in the environment: AWS via the usual chain (boto3); Azure needs `AZURE_SUBSCRIPTION_ID`; GCP needs `GOOGLE_CLOUD_PROJECT`.

## 2. Prerequisites

```bash
pip install ".[cloud]"    # boto3 + azure + google-cloud for discovery
pip install prowler       # for the configuration audit
```

Both paths are graceful: without the SDK or Prowler installed, Sentari reports that and adds nothing.

## 3. Discover internet-facing assets

```bash
sentari --cloud aws        # also: azure, gcp
```

Lists internet-facing assets from the account so the user can decide what to bring into scope. Enumerate only, never scanned automatically.

## 4. Audit account configuration (Prowler)

```bash
sentari <account-or-host> --scope <scope> --authorized --cloud-audit aws
```

Runs Prowler against the account and maps its failed checks (severity, resource, region, service) to findings. Supports `aws`, `azure`, `gcp`, `kubernetes`.

## 5. Bring discovered endpoints into a normal scan

Take an endpoint the user owns from step 3 and assess it like any web target:

```bash
sentari https://my-service.example.com --scope my-service.example.com --authorized --browser --html cloud-report.html
```

## 6. Review and fix

Each Prowler finding cites its evidence; review the failed check before reporting. Remediate with **fix-security-vulnerabilities-with-sentari** and track posture over time with **retest-and-monitor**. See **risk-prioritization** to rank the misconfigurations.
