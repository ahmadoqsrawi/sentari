# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Multi-tenant platform: user accounts, API tokens, and tenant-isolated scans.

The self-hosted control plane for Sentari as a service. A small SQLite-backed
store holds users and their scans; a stdlib HTTP API lets a user submit and read
only their own scans (tenant isolation), authenticated by a per-user API token.
The scans run through the same evidence-first engine, so nothing about the
platform loosens the authorization or evidence rules.
"""
from .store import PlatformStore, hash_token

__all__ = ["PlatformStore", "hash_token"]
