# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Ahmad <contact@ahmadoqsrawi.com>
"""Lightweight parallelism (standard library).

Independent network probes (port connects, path fetches) spend almost all their
time waiting on I/O, so running them on a small thread pool is a large, free
speedup with no broker or workers. For distributed/queued execution across
machines, see the optional Celery module (sentari.tasks).
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Iterable, TypeVar

T = TypeVar("T")
R = TypeVar("R")


def pmap(fn: Callable[[T], R], items: Iterable[T], workers: int = 16) -> list[R]:
    """Map fn over items concurrently, preserving input order. Results are
    collected in the caller's thread, so callers can record evidence/findings
    sequentially and avoid shared-state races."""
    items = list(items)
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=min(workers, len(items))) as ex:
        return list(ex.map(fn, items))
