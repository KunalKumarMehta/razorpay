"""Adapters package."""

from payoutproof.adapters.fake_adapter import (
    FakeApprovalRailAdapter,
    PendingApprovalItem,
)

__all__ = [
    "FakeApprovalRailAdapter",
    "PendingApprovalItem",
]
