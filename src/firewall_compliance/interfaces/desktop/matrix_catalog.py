"""Подтверждённые адреса каталога для сохранённых политик."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from firewall_compliance.application.matrix_scope_assessment import MatrixScopeSource, MatrixScopeTarget
from firewall_compliance.application.matrix_policy import matrix_catalog_switch_policy_contexts
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.interfaces.desktop.resource_registry import resource_address_binding

if TYPE_CHECKING:
    from firewall_compliance.interfaces.desktop.project_store import ProjectStore

type _Key = tuple[str, str]
type _Bindings = dict[_Key, tuple[str, ...]]
type _Source = tuple[str, str, str | None]


def matrix_catalog_default_switch(revision: DeviceRevision) -> bool:
    switch = revision.parse_result.switch_facts
    return switch is not None and revision.device.context in (None, "default") and all(
        item.vrf == "default" for item in switch.interfaces if item.kind != "management"
    )


def matrix_catalog_accepts_source(revision: DeviceRevision) -> bool:
    if revision.parse_result.switch_facts is not None:
        return matrix_catalog_default_switch(revision)
    device = revision.device
    return device.vendor in {"usergate", "ideco"} or device.platform in {
        "cloud-ru-vmware-nsxt", "cloud-ru-advanced-sg", "cloud-ru-evolution-sg",
    }


def matrix_cloud_catalog_sites(
    scan: Mapping[str, Any] | None, selected_site_id: str | None,
) -> tuple[str, ...]:
    if scan is None:
        return ()
    selection = scan.get("selection")
    raw = selection.get("workspace_site_ids") if isinstance(selection, Mapping) else None
    sites = (
        tuple(dict.fromkeys(site for site in raw if isinstance(site, str) and site))
        if isinstance(raw, (list, tuple)) else ()
    )
    return matrix_catalog_sites(sites or ("",), selected_site_id)


def matrix_catalog_sites(eligible: tuple[str, ...], selected_site_id: str | None) -> tuple[str, ...]:
    return eligible if selected_site_id is None else tuple(site for site in eligible if site == selected_site_id)


def matrix_revision_catalog_sites(
    revision: DeviceRevision, assignments: Mapping[str, str], selected_site_id: str | None,
) -> tuple[str, ...]:
    if revision.device.platform.startswith("cloud-ru-"):
        return ()
    return matrix_catalog_sites((assignments.get(revision.device.device_id, ""),), selected_site_id)


class MatrixCatalog:
    def __init__(self, store: ProjectStore, project_id: str) -> None:
        self._standard: dict[str, _Bindings] = defaultdict(dict)
        self._networks_by_vrf: dict[tuple[str, str], _Bindings] = defaultdict(dict)
        self._exact: dict[tuple[_Source, str, str | None], _Bindings] = defaultdict(dict)
        self.resources: dict[str, str] = {}
        self.names: dict[_Key, str] = {}
        self._labels: dict[_Key, str] = {}
        self._location: dict[_Key, str] = {}
        resources, self.resource_redirects = store.resource_registry.matrix_catalog_snapshot(project_id)
        aliases: dict[str, list[_Key]] = defaultdict(list)
        for previous, current in self.resource_redirects.items():
            aliases[current].append(("resource", previous))
        networks, _ = store.logical_networks.read(project_id)
        for network in networks:
            key = ("logical_network", network["id"])
            self.names[key] = network["name"]
            self._labels[key] = network["name"]
            if network["vrf"]:
                self._labels[key] += f" · VRF {network['vrf']}"
            if network["subnets"]:
                try:
                    binding = resource_address_binding({"site_id": network["site_id"], "prefixes": network["subnets"]})
                except ValueError:
                    self._labels[key] += " · некорректные подсети"
                else:
                    site, vrf = binding["site_id"], network["vrf"] or "default"
                    self._networks_by_vrf[site, vrf][key] = tuple(binding["prefixes"])
                    if not network["vrf"]:
                        self._standard[site][key] = tuple(binding["prefixes"])
                    self._location[key] = binding["site_id"]
            else:
                self._labels[key] += " · подсети не заданы"
        for resource_id, name, binding, source_bindings in resources:
            self.resources[resource_id] = name
            key = ("resource", resource_id)
            self.names[key] = name
            self._labels[key] = name
            keys = (key, *aliases[resource_id])
            if binding is not None:
                prefixes = tuple(binding["prefixes"])
                self._standard[binding["site_id"]].update((reference, prefixes) for reference in keys)
                self._location[key] = binding["site_id"]
            for exact in source_bindings:
                source = exact["device_id"], exact["platform"], exact["device_context"]
                prefixes = tuple(exact["prefixes"])
                self._exact[source, exact["site_id"], exact.get("vrf")].update((reference, prefixes) for reference in keys)

    def _labels_for(self, sites: tuple[str, ...], bindings: _Bindings) -> dict[_Key, str]:
        labels = self._labels.copy()
        for key, label in self._labels.items():
            if key in bindings:
                continue
            if key in self._location and self._location[key] not in sites:
                labels[key] = label + " · другая площадка"
            elif key[0] == "resource":
                labels[key] = label + " · адреса не подтверждены для выбора"
        return labels

    def standard(self, site_id: str | None) -> tuple[_Bindings, dict[_Key, str]]:
        site = site_id or ""
        bindings = self._standard.get(site, {})
        return bindings, self._labels_for((site,), bindings)

    def for_revision(self, revision: DeviceRevision, sites: tuple[str, ...]) -> _Bindings:
        if not sites or not matrix_catalog_accepts_source(revision):
            return {}
        device = revision.device
        target = device.device_id, device.platform, device.context
        standard = self._standard.get(sites[0], {}) if matrix_catalog_default_switch(revision) else {}
        return self._resolved(target, sites, None, standard)

    def for_path_source(
        self, source: MatrixScopeSource, assignments: Mapping[str, str], selected_site_id: str | None, *,
        default_switch: bool,
    ) -> _Bindings:
        if not default_switch:
            return {}
        sites = matrix_catalog_sites((assignments.get(source.device_id, ""),), selected_site_id)
        if not sites:
            return {}
        target = source.device_id, source.platform, source.device_context
        return self._resolved(target, sites, None, self._standard.get(sites[0], {}))

    def _resolved(self, target: _Source, sites: tuple[str, ...], vrf: str | None, standard: _Bindings) -> _Bindings:
        scoped = [bindings for site in sites if (bindings := self._exact.get((target, site, vrf)))]
        if not scoped:
            return standard
        conflicting: set[_Key] = set()
        exact: _Bindings = {}
        for bindings in scoped:
            for key, addresses in bindings.items():
                previous = exact.setdefault(key, addresses)
                if previous != addresses:
                    conflicting.add(key)
        resolved = {**standard, **exact}
        for key in conflicting:
            resolved.pop(key, None)
        return resolved

    def for_vrfs(self, revision: DeviceRevision, sites: tuple[str, ...]) -> dict[str, _Bindings]:
        if len(sites) != 1:
            return {}
        site = sites[0]
        device = revision.device
        target = device.device_id, device.platform, device.context
        result: dict[str, _Bindings] = {}
        for vrf in set(matrix_catalog_switch_policy_contexts(revision).values()):
            bindings = self._resolved(target, sites, vrf, self._networks_by_vrf.get((site, vrf), {}))
            if bindings:
                result[vrf] = bindings
        return result

    def for_editor(
        self, revision: DeviceRevision, sites: tuple[str, ...],
    ) -> tuple[_Bindings, dict[_Key, str], dict[str, _Bindings]]:
        bindings = self.for_revision(revision, sites)
        by_vrf = self.for_vrfs(revision, sites)
        labels = self._labels_for(sites, bindings)
        for scoped in by_vrf.values():
            for key in scoped:
                if key in self._labels:
                    labels[key] = self._labels[key]
        return bindings, labels, by_vrf

    def existing(
        self, target: MatrixScopeTarget, sites: tuple[str, ...], vrf: str | None = None,
    ) -> dict[tuple[str, str], tuple[str, ...]]:
        identity = target.device_id, target.platform, target.device_context
        return {
            (resource_id, site): prefixes
            for site in sites for (_, resource_id), prefixes in self._exact.get((identity, site, vrf), {}).items()
            if resource_id in self.resources
        }

    def suggested(self, resources: set[str], sites: tuple[str, ...]) -> dict[tuple[str, str], tuple[str, ...]]:
        return {
            (resource_id, site): prefixes for site in sites for resource_id in resources
            if (prefixes := self._standard.get(site, {}).get(("resource", resource_id)))
        }
