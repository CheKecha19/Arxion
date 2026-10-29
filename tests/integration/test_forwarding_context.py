"""Metadata выдержки не повышается до полного forwarding inventory."""

import json
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

import pytest
from pydantic import ValidationError
from tests.revision_fixtures import IMPORTED_AT, OBSERVED_AT, REVISION_ID

from firewall_compliance.domain.forwarding import (
    FeatureInventory,
    ForwardingContext,
    ForwardingSource,
)
from firewall_compliance.parsers.contracts import SourceDocument

ROOT = Path(__file__).parents[1] / "fixtures" / "forwarding_asa"
MANIFEST = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("scenario", MANIFEST["scenarios"], ids=lambda item: item["id"])
def test_authored_excerpt_does_not_prove_absence(scenario: dict) -> None:
    record = scenario["sources"][0]
    document = SourceDocument(
        source_name=record["path"],
        content=(ROOT / record["path"]).read_bytes(),
        captured_at=OBSERVED_AT,
    )
    assert document.content_sha256 == record["sha256"]
    source = ForwardingSource(
        source_document_id=uuid5(NAMESPACE_URL, record["path"]),
        source_name=document.source_name,
        content_sha256=document.content_sha256,
        purpose="configuration",
        device_id=scenario["device_id"],
        command=record["command"],
        declared_version="9.16",
        version_provenance="documentation",
        version_reference="Manifest собственного synthetic excerpt.",
        origin="synthetic",
        origin_reference="Команда не выполнялась на оборудовании.",
        captured_at=document.captured_at,
        selection=record["selection"],
        extent=record["extent"],
        encoding="ascii",
        capture_success=True,
    )
    context = ForwardingContext(
        revision_id=REVISION_ID,
        configuration_id=uuid5(NAMESPACE_URL, "forwarding-config:" + scenario["id"]),
        device_id=scenario["device_id"],
        imported_at=IMPORTED_AT,
        sources=(source,),
        inventories=tuple(
            FeatureInventory(
                feature=feature,
                status="unknown",
                source_document_ids=(source.source_document_id,),
                diagnostics=("Выдержка не доказывает полноту области.",),
            )
            for feature in ("configured_nat", "effective_nat", "pbr", "acl_bindings")
        ),
    )
    assert all(not item.complete and not item.enumeration_complete for item in context.inventories)
    assert ForwardingContext.model_validate_json(context.model_dump_json()) == context
    for feature in ("configured_nat", "effective_nat", "pbr", "acl_bindings"):
        payload = context.model_dump(mode="python")
        payload["inventories"] = (
            FeatureInventory(
                feature=feature,
                status="absent",
                complete=True,
                enumeration_complete=True,
                reference="Недостаточное заявление не отменяет metadata выдержки.",
                source_document_ids=(source.source_document_id,),
            ),
        )
        with pytest.raises(ValidationError):
            ForwardingContext.model_validate(payload)
