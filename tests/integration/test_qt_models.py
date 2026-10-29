"""Qt-модель сохраняет связь подробностей с результатом после сортировки и поиска."""

import pytest
from PySide6.QtCore import QSortFilterProxyModel, Qt

from firewall_compliance.interfaces.desktop.qt_models import RowsModel
from firewall_compliance.interfaces.desktop.qt_theme import COLORS


def test_proxy_selection_maps_to_original_payload_and_reset_removes_old_rows() -> None:
    model = RowsModel(("Устройство", "Диагностика"))
    model.replace((("z-device", "partial"), ("a-device", "unsupported")), ("z", "a"))
    proxy = QSortFilterProxyModel()
    proxy.setSourceModel(model)
    proxy.setFilterKeyColumn(-1)
    proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
    proxy.sort(0)
    assert model.payloads[proxy.mapToSource(proxy.index(0, 0)).row()] == "a"
    proxy.setFilterFixedString("PARTIAL")
    assert proxy.rowCount() == 1
    assert model.payloads[proxy.mapToSource(proxy.index(0, 0)).row()] == "z"
    model.replace(())
    assert proxy.rowCount() == 0
    assert model.payloads == []


def _luminance(color: str) -> float:
    channels = [int(color[position : position + 2], 16) / 255 for position in (1, 3, 5)]
    linear = [
        value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4
        for value in channels
    ]
    return sum(
        value * weight for value, weight in zip(linear, (0.2126, 0.7152, 0.0722), strict=True)
    )


@pytest.mark.parametrize("foreground", ["text", "muted", "blue", "purple"])
@pytest.mark.parametrize("background", ["background", "panel", "raised"])
def test_theme_text_roles_have_wcag_normal_text_contrast(foreground: str, background: str) -> None:
    light, dark = sorted(
        (_luminance(COLORS[foreground]), _luminance(COLORS[background])), reverse=True
    )
    assert (light + 0.05) / (dark + 0.05) >= 4.5
