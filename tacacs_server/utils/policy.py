"""Shared authorization policy helpers for TACACS+ and RADIUS."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional


def normalize_groups(groups: Optional[Iterable[str]]) -> List[str]:
    if not groups:
        return []
    normalized: List[str] = []
    for value in groups:
        if not isinstance(value, str):
            continue
        token = value.strip()
        if token and token not in normalized:
            normalized.append(token)
    return normalized


@dataclass
class PolicyContext:
    """Input data needed to evaluate device/user group policy."""

    device_group_name: Optional[str]
    allowed_user_groups: List[str]
    user_groups: List[str]
    fallback_privilege: int


@dataclass
class PolicyResult:
    """Outcome from policy evaluation used by TACACS+/RADIUS handlers."""

    allowed: bool
    privilege_level: int
    denial_message: str = ""


def evaluate_policy(
    context: PolicyContext,
    privilege_lookup,
) -> PolicyResult:
    """Evaluate whether the user may access the device and derive privilege level.

    Args:
        context: PolicyContext with device group settings and user groups.
        privilege_lookup: Callable taking a group name and returning its privilege level.
    """
    allowed_groups = normalize_groups(context.allowed_user_groups)
    user_groups = normalize_groups(context.user_groups)

    if allowed_groups:
        matched_groups = [group for group in user_groups if group in allowed_groups]
        if not matched_groups:
            name = context.device_group_name or "device"
            return PolicyResult(False, context.fallback_privilege, f"User not permitted for device group {name}")
    else:
        matched_groups = user_groups

    privilege_candidates: List[int] = []
    for group in matched_groups:
        try:
            privilege = privilege_lookup(group)
        except Exception:
            continue
        if privilege is not None:
            privilege_candidates.append(int(privilege))

    if privilege_candidates:
        return PolicyResult(True, max(privilege_candidates))

    try:
        fallback = int(context.fallback_privilege)
    except (TypeError, ValueError):
        fallback = 1
    return PolicyResult(True, fallback)
