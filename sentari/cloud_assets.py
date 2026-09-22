"""Cloud asset discovery.

Lists internet-facing assets in your own cloud account so you can decide what to
bring into scope. It reads from the provider SDKs (boto3 for AWS, and the Azure
and Google SDKs when present) using your normal credentials. SDKs are optional:
a provider whose SDK is missing is reported and skipped.

This only enumerates. It does not scan anything; feed the endpoints it returns
into a normal authorized Sentari run.
"""
from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Asset:
    kind: str
    identifier: str
    endpoint: Optional[str] = None
    detail: str = ""


@dataclass
class CloudResult:
    provider: str
    assets: list[Asset] = field(default_factory=list)
    error: Optional[str] = None


def _imp(mod: str):
    try:
        return importlib.import_module(mod)
    except Exception:
        return None


def discover_aws() -> CloudResult:
    out = CloudResult(provider="aws")
    boto3 = _imp("boto3")
    if boto3 is None:
        out.error = "boto3 not installed (pip install boto3)"
        return out
    try:
        ec2 = boto3.client("ec2")
        for r in ec2.describe_instances().get("Reservations", []):
            for inst in r.get("Instances", []):
                ip = inst.get("PublicIpAddress")
                if ip:
                    out.assets.append(Asset("ec2-instance", inst["InstanceId"], ip,
                                            inst.get("PublicDnsName", "")))
        s3 = boto3.client("s3")
        for b in s3.list_buckets().get("Buckets", []):
            out.assets.append(Asset("s3-bucket", b["Name"],
                                    f"{b['Name']}.s3.amazonaws.com"))
        try:
            r53 = boto3.client("route53")
            for zone in r53.list_hosted_zones().get("HostedZones", []):
                recs = r53.list_resource_record_sets(HostedZoneId=zone["Id"])
                for rr in recs.get("ResourceRecordSets", []):
                    if rr.get("Type") in ("A", "AAAA", "CNAME"):
                        out.assets.append(Asset("dns-record", rr["Name"].rstrip("."),
                                                rr["Name"].rstrip(".")))
        except Exception:
            pass  # route53 may be denied; keep what we have
    except Exception as e:
        out.error = f"AWS discovery failed: {type(e).__name__}: {e}"
    return out


def discover_azure() -> CloudResult:
    import os
    out = CloudResult(provider="azure")
    net = _imp("azure.mgmt.network")
    ident = _imp("azure.identity")
    if net is None or ident is None:
        out.error = "azure SDK not installed (pip install azure-mgmt-network azure-identity)"
        return out
    sub = os.getenv("AZURE_SUBSCRIPTION_ID")
    if not sub:
        out.error = "set AZURE_SUBSCRIPTION_ID"
        return out
    try:
        cred = ident.DefaultAzureCredential()
        client = net.NetworkManagementClient(cred, sub)
        for ip in client.public_ip_addresses.list_all():
            if getattr(ip, "ip_address", None):
                out.assets.append(Asset("public-ip", ip.name, ip.ip_address))
    except Exception as e:
        out.error = f"Azure discovery failed: {type(e).__name__}: {e}"
    return out


def discover_gcp() -> CloudResult:
    import os
    out = CloudResult(provider="gcp")
    compute = _imp("google.cloud.compute_v1")
    if compute is None:
        out.error = "google-cloud-compute not installed (pip install google-cloud-compute)"
        return out
    project = os.getenv("GOOGLE_CLOUD_PROJECT")
    if not project:
        out.error = "set GOOGLE_CLOUD_PROJECT"
        return out
    try:
        client = compute.InstancesClient()
        for zone, scoped in client.aggregated_list(project=project):
            for inst in getattr(scoped, "instances", []) or []:
                for nic in inst.network_interfaces:
                    for ac in getattr(nic, "access_configs", []) or []:
                        if getattr(ac, "nat_i_p", None):
                            out.assets.append(Asset("gce-instance", inst.name, ac.nat_i_p, zone))
    except Exception as e:
        out.error = f"GCP discovery failed: {type(e).__name__}: {e}"
    return out


def discover(provider: str) -> CloudResult:
    return {"aws": discover_aws, "azure": discover_azure,
            "gcp": discover_gcp}.get(provider, lambda: CloudResult(provider,
                                     error=f"unknown provider {provider}"))()
