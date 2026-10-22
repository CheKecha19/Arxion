"""Регрессии глубокой неизменяемости без изменения builder-моделей."""

from copy import copy, deepcopy
from typing import Any

import pytest
from tests.revision_fixtures import make_revision

from firewall_compliance.domain import Device, DeviceRevision, Evidence
from firewall_compliance.domain.snapshot import snapshot


def test_snapshot_does_not_freeze_or_alias_builder() -> None:
    builder = Device(device_id="test", vendor="test", platform="test")
    frozen = builder.as_snapshot()
    builder.hostname = "changed"
    assert frozen.hostname is None
    assert isinstance(frozen, Device)
    with pytest.raises(TypeError):
        frozen.hostname = "forbidden"
    with pytest.raises(TypeError):
        del frozen.hostname


@pytest.mark.parametrize(
    "path",
    [
        ("device", "hostname"),
        ("parse_result", "configuration", "parser_version"),
        ("parse_result", "rules", 0, "name"),
        ("parse_result", "rules", 0, "source_location", "source_name"),
        ("parse_result", "rules", 0, "destinations", 0, "name"),
        ("parse_result", "rules", 0, "services", 0, "name"),
        ("parse_result", "coverage", "recognized_constructs"),
        ("interfaces", 0, "source_location", "source_name"),
    ],
)
def test_revision_nested_fields_are_locked(path: tuple[Any, ...]) -> None:
    value: Any = make_revision()
    for key in path[:-1]:
        value = value[key] if isinstance(key, int) else getattr(value, key)
    with pytest.raises(TypeError):
        setattr(value, path[-1], "changed")


@pytest.mark.parametrize(
    "operation", ["set", "delete", "update", "clear", "pop", "popitem", "setdefault", "ior", "init"]
)
def test_snapshot_mapping_mutations_are_rejected(operation: str) -> None:
    mapping = make_revision().parse_result.source_map
    key = next(iter(mapping))
    value = mapping[key]
    with pytest.raises(TypeError):
        if operation == "set":
            mapping[key] = value
        elif operation == "delete":
            del mapping[key]
        elif operation == "update":
            mapping.update({key: value})
        elif operation == "clear":
            mapping.clear()
        elif operation == "pop":
            mapping.pop(key)
        elif operation == "popitem":
            mapping.popitem()
        elif operation == "setdefault":
            mapping.setdefault(key, value)
        elif operation == "ior":
            mapping |= {key: value}
        else:
            mapping.__init__({})


def test_revision_isolated_from_original_parse_result_and_location() -> None:
    revision = make_revision()
    from tests.revision_fixtures import make_parse_result

    original = make_parse_result()
    payload = revision.model_dump(mode="python")
    payload["parse_result"] = original
    frozen = DeviceRevision.model_validate(payload)
    original.configuration.parser_version = "changed"
    original.rules[0].source_location.source_name = "changed"
    original.source_map.clear()
    assert frozen.parse_result.configuration.parser_version == "1.0.0"
    assert frozen.parse_result.rules[0].source_location.source_name == "fixture.config"
    assert frozen.parse_result.source_map


def test_snapshot_any_containers_are_recursive_and_detached() -> None:
    original: dict[str, Any] = {"list": [{"value": 1}], "set": {1, 2}}
    frozen = Evidence(summary="Тест.", facts=original).as_snapshot()
    original["list"][0]["value"] = 2
    assert frozen.facts["list"][0]["value"] == 1
    with pytest.raises(TypeError):
        frozen.facts["list"].append(2)
    with pytest.raises(TypeError):
        frozen.facts["list"][0]["value"] = 3
    with pytest.raises(TypeError):
        frozen.facts["set"].add(3)
    assert frozen.model_dump(mode="json")["facts"]["list"] == [{"value": 1}]


def test_snapshot_rejects_cycles_and_unknown_mutable_objects() -> None:
    cycle: list[Any] = []
    cycle.append(cycle)
    with pytest.raises(ValueError, match="циклические"):
        snapshot(cycle)
    with pytest.raises(TypeError, match="не поддерживает"):
        snapshot(bytearray(b"test"))


@pytest.mark.parametrize(
    "copier",
    [copy, deepcopy, lambda model: model.model_copy(), lambda model: model.model_copy(deep=True)],
)
def test_revision_copy_and_json_roundtrip_preserve_snapshot(copier: Any) -> None:
    revision = make_revision()
    copied = copier(revision)
    assert copied.model_dump(mode="json") == revision.model_dump(mode="json")
    with pytest.raises(TypeError):
        copied.parse_result.source_map.clear()
    restored = DeviceRevision.model_validate_json(revision.model_dump_json())
    assert restored.model_dump(mode="json") == revision.model_dump(mode="json")
    with pytest.raises(TypeError):
        restored.device.hostname = "changed"


def test_copy_update_does_not_alias_original_or_update_value() -> None:
    revision = make_revision()
    builder = Device(device_id="fixture-device", vendor="test", platform="fixture-platform")
    copied = revision.model_copy(update={"device": builder})
    builder.hostname = "changed"
    assert copied.device.hostname is None
    assert revision.device.hostname == "fixture-device"
    with pytest.raises(TypeError):
        copied.device.hostname = "changed"
