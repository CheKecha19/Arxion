"""Immutable canonical analysis settings, independent of Qt and storage."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from firewall_compliance.domain.management import ManagementProfile
from firewall_compliance.domain.policy_exposure import PolicyExposureProfile
from firewall_compliance.domain.policy_scope import PolicyScopeProfile

ANALYSIS_SETTING_KEYS = frozenset(
    {
        "require_logging",
        "require_comments",
        "management_profile",
        "policy_exposure_profile",
        "policy_scope_profile",
        "enabled_check_ids",
    }
)


def analysis_settings(settings: Mapping[str, Any]) -> dict[str, Any]:
    """Project legacy settings; connection/report settings never enter history."""
    if not isinstance(settings, Mapping):
        raise TypeError("settings must be a mapping")
    return {key: value for key, value in settings.items() if key in ANALYSIS_SETTING_KEYS}


@dataclass(frozen=True, slots=True)
class ProfileVersion:
    """Canonical JSON is the immutable boundary; settings returns a fresh copy.

    This is a legacy-origin profile version, not an organization profile ID.
    Callers must pass validated analysis settings, never connection credentials.
    """

    origin_project_id: str
    version: int
    settings_json: str
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.origin_project_id, str) or not self.origin_project_id.strip():
            raise ValueError("origin_project_id is required")
        if type(self.version) is not int or self.version < 1:
            raise ValueError("version must be a positive integer")
        values = json.loads(self.settings_json)
        if not isinstance(values, dict) or set(values) - ANALYSIS_SETTING_KEYS:
            raise ValueError("profile must contain only analysis settings")
        for key in ("require_logging", "require_comments"):
            if key in values and type(values[key]) is not bool:
                raise ValueError(f"{key} must be boolean")
        if "enabled_check_ids" in values and values["enabled_check_ids"] is not None:
            checks = values["enabled_check_ids"]
            if not isinstance(checks, list) or any(not isinstance(v, str) or not v for v in checks):
                raise ValueError("enabled_check_ids must contain nonempty strings")
        for key, model in (
            ("management_profile", ManagementProfile),
            ("policy_exposure_profile", PolicyExposureProfile),
            ("policy_scope_profile", PolicyScopeProfile),
        ):
            if key in values and values[key] is not None:
                values[key] = model.model_validate(values[key]).model_dump(mode="json")
        canonical = json.dumps(
            values,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        )
        object.__setattr__(self, "settings_json", canonical)
        object.__setattr__(self, "fingerprint", hashlib.sha256(canonical.encode()).hexdigest())

    @classmethod
    def from_settings(
        cls, origin_project_id: str, version: int, settings: Mapping[str, Any]
    ) -> ProfileVersion:
        if not isinstance(settings, Mapping):
            raise TypeError("settings must be a mapping")
        if set(settings) - ANALYSIS_SETTING_KEYS:
            raise ValueError("connection and unknown settings cannot enter an analysis profile")
        return cls(
            origin_project_id,
            version,
            json.dumps(dict(settings), ensure_ascii=False, allow_nan=False),
        )

    def settings(self) -> dict[str, Any]:
        return json.loads(self.settings_json)
