"""Conservative, reversible limitation projections shared by Qt and offline HTML.

The current contracts have no semantic message-template registry. Consequently only
equal messages (apart from outer whitespace and line endings) in the same explicit
scope are grouped. This module neither edits nor upgrades backend results.
"""

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

Record = Mapping[str, Any]


@dataclass(frozen=True)
class RawLimitationRef:
    """An exact input occurrence with an unambiguous JSON-pointer-like path."""

    path: str
    origin: str
    check_id: str | None
    finding_id: str | None
    raw: object


@dataclass(frozen=True)
class LimitationGroup:
    """A display group retaining every raw occurrence and its explicit scope."""

    key: str
    code: str
    message: str
    origin: str
    rule_ids: tuple[str, ...]
    check_ids: tuple[str, ...]
    raw_refs: tuple[RawLimitationRef, ...]

    @property
    def occurrence_count(self) -> int:
        """Count original records, independently of affected rule/check counts."""
        return len(self.raw_refs)


@dataclass(frozen=True)
class LimitationSelection:
    """Finding-local reasons, source/check-wide caveats and excluded local groups."""

    local: tuple[LimitationGroup, ...]
    common: tuple[LimitationGroup, ...]
    unrelated_count: int


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _message(value: object) -> str:
    return str(value).replace("\r\n", "\n").replace("\r", "\n").strip()


def _strings(values: Any) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        return ()
    return tuple(sorted({str(value) for value in values if isinstance(value, str) and value}))


def project_item_limitations(item: Record) -> tuple[LimitationGroup, ...]:
    """Group explicit equal scopes while preserving all raw diagnostics and evidence.

    Accept both stored item ``report`` and exported item ``result``. Group keys
    include item/device/revision identity and do not depend on check ordering.
    Missing rule references remain unbound, never inferred from message text.
    """
    result = item.get("report") or item.get("result") or {}
    result_path = "/report" if item.get("report") else "/result"
    identity = (
        str(item.get("id") or item.get("item_id") or ""),
        str(item.get("content_sha256") or ""),
        str(item.get("source_name") or ""),
        str(result.get("device_id") or ""),
        str(result.get("revision_id") or ""),
    )
    groups: dict[str, LimitationGroup] = {}
    parse_fields = ("parse_warnings", "parse_errors", "unsupported_constructs")
    parse_origins: dict[str, set[str]] = {}
    for field in parse_fields:
        for raw in result.get(field, ()):
            if isinstance(raw, Mapping) and raw.get("message"):
                parse_origins.setdefault(_canonical(raw), set()).add(field)

    def add(
        raw: object,
        path: str,
        origin: str,
        *,
        check_id: str | None = None,
        finding_id: str | None = None,
        evidence_rules: tuple[str, ...] = (),
        group_origin: str | None = None,
    ) -> None:
        canonical_origin = group_origin or origin
        record = raw if isinstance(raw, Mapping) else {}
        code = str(
            record.get("code")
            or record.get("construct_type")
            or ("EVIDENCE_LIMITATION" if origin == "evidence" else "RAW_DIAGNOSTIC")
        )
        message = _message(record.get("message", raw))
        rules = _strings(record.get("rule_ids")) if origin != "evidence" else evidence_rules
        # Missing/malformed records remain individually recoverable; do not group
        # unknown structures merely because their string representation matches.
        malformed = path if origin != "evidence" and not record.get("message") else ""
        fingerprint = (
            identity,
            canonical_origin,
            code,
            message,
            rules,
            record.get("source_location"),
            finding_id,
            malformed,
            {
                key: value
                for key, value in record.items()
                if key not in {"code", "message", "rule_ids"}
            },
        )
        key = "lim-" + hashlib.sha256(_canonical(fingerprint).encode("utf-8")).hexdigest()
        ref = RawLimitationRef(path, origin, check_id, finding_id, raw)
        previous = groups.get(key)
        refs = (*previous.raw_refs, ref) if previous else (ref,)
        check_ids = tuple(sorted({entry.check_id for entry in refs if entry.check_id is not None}))
        groups[key] = LimitationGroup(key, code, message, canonical_origin, rules, check_ids, refs)

    for index, raw in enumerate(item.get("diagnostics", ())):
        # ProjectStore.record_session copies these parser records into diagnostics.
        # Only an exact full raw-record match to one proven parser origin is an
        # alias. Equal message text or equal code alone proves no such linkage.
        origins = parse_origins.get(_canonical(raw), set())
        alias = next(iter(origins)) if len(origins) == 1 else None
        add(raw, f"/diagnostics/{index}", "diagnostic", group_origin=alias)
    for field in parse_fields:
        for index, raw in enumerate(result.get(field, ())):
            add(raw, f"{result_path}/{field}/{index}", field)
    for check_index, check in enumerate(result.get("checks", ())):
        check_id = str(check.get("check_id") or "")
        check_path = f"{result_path}/checks/{check_index}"
        for index, raw in enumerate(check.get("limitations", ())):
            add(raw, f"{check_path}/limitations/{index}", "check", check_id=check_id)
        for finding_index, finding in enumerate(check.get("findings", ())):
            finding_path = f"{check_path}/findings/{finding_index}"
            finding_id = str(finding.get("finding_id") or finding_path)
            evidence = finding.get("evidence") or {}
            rules = tuple(
                sorted(
                    set(_strings(finding.get("affected_rule_ids")))
                    | set(_strings(evidence.get("related_rule_ids")))
                )
            )
            for index, raw in enumerate(evidence.get("limitations", ())):
                add(
                    raw,
                    f"{finding_path}/evidence/limitations/{index}",
                    "evidence",
                    check_id=check_id,
                    finding_id=finding_id,
                    evidence_rules=rules,
                )
    return tuple(groups.values())


def check_limitations(
    item: Record, check: Record, *, groups: tuple[LimitationGroup, ...] | None = None
) -> tuple[LimitationGroup, ...]:
    """Return only the selected check's limitations, excluding other check evidence."""
    check_id = str(check.get("check_id") or "")
    return tuple(
        group
        for group in (project_item_limitations(item) if groups is None else groups)
        if group.origin == "check" and check_id in group.check_ids
    )


def finding_limitations(
    item: Record,
    check: Record,
    finding: Record,
    *,
    groups: tuple[LimitationGroup, ...] | None = None,
) -> LimitationSelection:
    """Select explicit rule intersections and keep common caveats separately.

    Source diagnostics have no rule linkage in the current schema. They remain
    common even when their line numbers or names resemble a selected rule.
    """
    check_id = str(check.get("check_id") or "")
    finding_id = str(finding.get("finding_id") or "")
    evidence = finding.get("evidence") or {}
    rules = set(_strings(finding.get("affected_rule_ids"))) | set(
        _strings(evidence.get("related_rule_ids"))
    )
    local: list[LimitationGroup] = []
    common: list[LimitationGroup] = []
    excluded = 0
    for group in project_item_limitations(item) if groups is None else groups:
        if group.origin == "evidence":
            if any(
                ref.finding_id == finding_id and ref.check_id == check_id for ref in group.raw_refs
            ):
                local.append(group)
            else:
                excluded += 1
        elif group.origin == "check":
            if check_id not in group.check_ids:
                excluded += 1
            elif not group.rule_ids:
                common.append(group)
            elif rules.intersection(group.rule_ids):
                local.append(group)
            else:
                excluded += 1
        else:
            common.append(group)
    return LimitationSelection(tuple(local), tuple(common), excluded)


def group_summary(group: LimitationGroup) -> str:
    """Keep the backend wording and distinguish record, check and unique rule counts."""
    scope = (
        f"Затронуто правил: {len(group.rule_ids)}"
        if group.rule_ids
        else "Затронутые правила не указаны"
    )
    return (
        f"{group.code}: {group.message} · {scope}; "
        f"проверок: {len(group.check_ids)}; исходных записей: {group.occurrence_count}"
    )


def group_details(group: LimitationGroup) -> str:
    """Return every original record and its provenance as readable technical JSON."""
    return json.dumps(
        {
            "group_key": group.key,
            "origin": group.origin,
            "rule_ids": group.rule_ids,
            "check_ids": group.check_ids,
            "raw_records": [
                {
                    "path": ref.path,
                    "origin": ref.origin,
                    "check_id": ref.check_id,
                    "finding_id": ref.finding_id,
                    "raw": ref.raw,
                }
                for ref in group.raw_refs
            ],
        },
        ensure_ascii=False,
        indent=2,
        default=str,
    )
