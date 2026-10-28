"""Optional reference mappings preserve technical scope and missing-evidence outcomes."""

from datetime import timedelta
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from test_control_assessment import AT, profile, source_result

from firewall_compliance.application.control_assessment import (
    ControlAssessment,
    assess_controls,
    export_control_assessment_html,
    internal_control_catalogue,
)
from firewall_compliance.application.control_reference_catalogues import (
    MAPPING_VERSION,
    REFERENCE_CATALOGUE_IDS,
    REFERENCE_REVIEW_DATE,
    cis_controls81_catalogue,
    nist_sp80041_catalogue,
    nist_sp80053_catalogue,
    reference_control_catalogue,
)
from firewall_compliance.domain.controls import ControlCatalogue
from firewall_compliance.domain.network import PortRange
from firewall_compliance.domain.policy_exposure import PolicyExposureProfile, PolicyServiceSelector


@pytest.mark.parametrize(
    "identifier,counts", zip(REFERENCE_CATALOGUE_IDS, [(3, 3), (6, 6), (7, 6)], strict=True)
)
def test_explicit_catalogue_ids_have_bounded_versioned_source_mappings(identifier, counts):
    catalogue = reference_control_catalogue(identifier)
    assert (len(catalogue.controls), len(catalogue.mappings)) == counts
    assert catalogue.catalogue_id == identifier and catalogue.version == MAPPING_VERSION
    assert REFERENCE_REVIEW_DATE == "2026-10-28"
    assert all(value.control_id.startswith(identifier + ":") for value in catalogue.controls)
    for mapping in catalogue.mappings:
        assert mapping.source_control_id and mapping.edition and mapping.covered_part
        assert len(mapping.limits) >= 4
        assert "авторами стандарта" in mapping.rationale
        assert mapping.check_versions == ("1.0.0", "1.1.0")
        assert urlsplit(mapping.source).scheme == "https"
        assert urlsplit(mapping.source).hostname in {"nvlpubs.nist.gov", "cas.docs.cisecurity.org"}
        assert mapping.check_id in {"FW-DANGEROUS-SERVICES", "FW-ADMIN-UNTRUSTED", "FW-LOGGING"}
    assert ControlCatalogue.model_validate_json(catalogue.model_dump_json()) == catalogue


@pytest.mark.parametrize(
    "identifier", ["", "nist-sp800-53-r5", "nist-sp800-53-r5-5.2.0", "benchmark", "CIS"]
)
def test_unknown_reference_or_unreviewed_edition_never_falls_back(identifier):
    with pytest.raises(ValueError, match="Unsupported"):
        reference_control_catalogue(identifier)


def test_pinned_nist_edition_and_exact_source_identifiers_remain_separate():
    catalogue = nist_sp80053_catalogue()
    assert {value.source_control_id for value in catalogue.mappings} == {
        "AC-4",
        "SC-7",
        "CM-7",
        "AU-12",
    }
    assert all("2020-12-10" in value.edition for value in catalogue.mappings)
    assert all("5.2.0" not in value.edition for value in catalogue.mappings)
    assert nist_sp80041_catalogue().mappings[0].source_control_id == "4.1"
    assert nist_sp80041_catalogue().mappings[0].source.endswith("#page=28")


@pytest.mark.parametrize(
    "factory,unmapped",
    [
        (nist_sp80041_catalogue, ("5.3",)),
        (nist_sp80053_catalogue, ("AU-2", "SC-7(5)")),
        (cis_controls81_catalogue, ("4.4", "8.1", "12.3")),
    ],
)
def test_unimplemented_procedures_deployment_and_runtime_never_become_passes(factory, unmapped):
    catalogue = factory()
    selected = profile(*(catalogue.catalogue_id + ":" + value for value in unmapped))
    result = assess_controls(
        source_result(), selected, catalogue, assessed_at=AT + timedelta(hours=1)
    )
    assert all(value.state == "insufficient_evidence" for value in result.evaluations)
    assert all("NO_TECHNICAL_MAPPING" in value.limitations for value in result.evaluations)
    assert result.coverage.fully_examined_evaluations == 0
    assert result.coverage.executed_check_evaluations == 0
    assert result.coverage.no_violations_in_examined_scope == 0


def test_many_to_many_preserves_actual_finding_ids_and_explicit_exposure_profile():
    selector = PolicyServiceSelector(
        selector_id="authored-admin",
        name="Synthetic organization service",
        protocol="tcp",
        port_ranges=(PortRange(start=22, end=22),),
    )
    exposure = PolicyExposureProfile(
        dangerous_services=(selector,),
        administrative_services=(selector,),
        administrative_targets=("192.0.2.10/32",),
        trusted_admin_networks=("198.51.100.0/24",),
    )
    source = source_result(
        content=(
            b"hostname SYNTHETIC\n"
            b"access-list TEST extended permit tcp any host 192.0.2.10 eq 22 log\n"
            b"access-group TEST in interface outside\n"
        ),
        extended_policy_checks=True,
        policy_exposure_profile=exposure,
    )
    catalogue = nist_sp80053_catalogue()
    selected = profile(
        *(catalogue.catalogue_id + ":" + value for value in ("AC-4", "SC-7", "CM-7"))
    )
    result = assess_controls(source, selected, catalogue, assessed_at=AT + timedelta(hours=1))
    assert all(value.state == "technical_violation" for value in result.evaluations)
    first, second, third = result.evaluations
    assert len(first.evidence) == len(second.evidence) == 2 and len(third.evidence) == 1
    assert first.evidence[0].finding_ids == second.evidence[0].finding_ids
    assert third.evidence[0].finding_ids == first.evidence[0].finding_ids
    assert first.evidence[0].finding_ids
    assert result.source.components[0].options.exposure_profile == exposure
    assert ControlAssessment.model_validate_json(result.model_dump_json()) == result
    html = export_control_assessment_html(result)
    assert "AC-4" in html and "не сертификация" in html


def test_missing_mapped_check_remains_missing_even_when_legacy_checks_have_no_findings():
    catalogue = nist_sp80053_catalogue()
    selected = profile(catalogue.catalogue_id + ":CM-7")
    result = assess_controls(
        source_result(), selected, catalogue, assessed_at=AT + timedelta(hours=1)
    )
    assert result.evaluations[0].state == "insufficient_evidence"
    assert result.evaluations[0].evidence[0].execution == "missing"
    assert result.coverage.executed_check_evaluations == 0


def test_internal_default_and_independent_frozen_reference_snapshots_are_unchanged():
    before = internal_control_catalogue().model_dump_json()
    catalogue = cis_controls81_catalogue()
    with pytest.raises(TypeError, match="snapshot"):
        catalogue.controls[0].title = "modified"
    another = cis_controls81_catalogue()
    assert another == catalogue and another is not catalogue
    assert internal_control_catalogue().model_dump_json() == before
    assert internal_control_catalogue().catalogue_id == "arxion-internal-technical"


def test_factories_do_not_read_configuration_or_contact_external_sources(monkeypatch):
    def reject(*_, **__):
        raise AssertionError("Unexpected I/O")

    monkeypatch.setattr(Path, "read_text", reject)
    monkeypatch.setattr(Path, "read_bytes", reject)
    for identifier in REFERENCE_CATALOGUE_IDS:
        assert reference_control_catalogue(identifier).mappings
