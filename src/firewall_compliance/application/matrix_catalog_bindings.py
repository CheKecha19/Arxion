"""Снимок адресного состава каталога по контекстам политик."""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping

from firewall_compliance.domain.access_matrix import MatrixCatalogBinding

type CatalogBindings = Mapping[tuple[str, str], tuple[str, ...]]
type MutableCatalogBindings = dict[tuple[str, str], tuple[str, ...]]


def split_catalog_bindings(
    records: Iterable[MatrixCatalogBinding],
) -> tuple[MutableCatalogBindings, dict[str, MutableCatalogBindings]]:
    base: MutableCatalogBindings = {}
    scoped: dict[str, MutableCatalogBindings] = {}
    for record in records:
        bindings = base if record.vrf is None else scoped.setdefault(record.vrf, {})
        key = record.kind, record.value
        if key in bindings:
            raise ValueError("В одном контексте повторяется адресная привязка каталога.")
        bindings[key] = record.cidrs
    return base, scoped


def freeze_catalog_bindings(
    bindings: CatalogBindings, by_vrf: Mapping[str, CatalogBindings] | None = None, *,
    referenced: Collection[tuple[str, str]] | None = None,
) -> tuple[MatrixCatalogBinding, ...]:
    result = []
    for vrf, values in ((None, bindings), *sorted((by_vrf or {}).items())):
        keys = values.keys() if referenced is None else (key for key in referenced if key in values)
        for kind, identifier in sorted(keys):
            if values[kind, identifier]:
                result.append(MatrixCatalogBinding.model_validate({
                    "kind": kind, "value": identifier, "cidrs": values[kind, identifier], "vrf": vrf,
                }))
    return tuple(result)
