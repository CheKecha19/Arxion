"""Qt view-only ACL filters and bounded native-scale exports on synthetic input."""

import os
from pathlib import Path
from uuid import uuid4

import pytest
from test_acl_map_workflow import NOW, graph
from test_policy_union_shadowing import rule

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QFontDatabase, QImage
from PySide6.QtWidgets import QApplication

from firewall_compliance.analysis.acl_map import AclMapFilter
from firewall_compliance.domain.enums import DataStatus
from firewall_compliance.interfaces.desktop.qt_acl_map import AclMapState, AclMapWidget


@pytest.fixture(scope="module")
def app():
    result = QApplication.instance() or QApplication([])
    # The sandboxed offscreen platform can miss the Windows font catalogue.
    # Load an installed system font only in that validation environment.
    if os.name == "nt" and not QFontDatabase.families():
        system_font = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts" / "arial.ttf"
        assert QFontDatabase.addApplicationFont(str(system_font)) >= 0
    yield result


@pytest.fixture
def directory():
    result = Path(__file__).resolve().parents[2] / "artifacts" / "acl-map-ui" / uuid4().hex
    result.mkdir(parents=True)
    return result


@pytest.fixture
def widget(app):
    result = AclMapWidget()
    result.set_map_state(AclMapState("ready", graph(), "Synthetic authored input"))
    yield result
    result.close()
    result.deleteLater()
    app.processEvents()


def test_filters_only_change_view_and_reset_restores_full_graph(widget):
    value = graph(rule("first", 10), rule("second", 20, src=(20, 30)))
    state = AclMapState("ready", value, "Synthetic two-rule input")
    widget.set_map_state(state)
    before = value.model_dump_json()
    widget.set_filters(AclMapFilter(source_cidr="0.0.0.1"))
    assert widget.state is state and widget.scene.state is state
    assert value.model_dump_json() == before
    assert [item.rule.rule_id for item in widget._relations.values()] == ["first"]
    assert len(widget.scene.relation_items) == 1
    assert widget.relation_selector.count() == 2
    assert "1 из 2" in widget.status_label.text()
    widget.reset_filters()
    assert len(widget.scene.relation_items) == 2
    assert widget.relation_selector.count() == 3
    assert widget.filters is None


def test_unknown_visible_by_default_and_explicitly_excludable(widget):
    value = graph(rule("unknown", 10, source_status=DataStatus.UNKNOWN))
    widget.set_map_state(AclMapState("partial", value, "Unknown source"))
    widget.set_filters(AclMapFilter(source_cidr="192.0.2.0/24"))
    assert widget.scene.relation_items
    widget.set_filters(AclMapFilter(source_cidr="192.0.2.0/24", include_unknown=False))
    assert not widget.scene.relation_items
    assert widget.state.graph == value
    assert widget.html_export_button.isEnabled()


def test_controls_apply_semantic_port_and_reset(widget):
    widget.port_filter.setText("9")
    widget.protocol_filter.setCurrentIndex(widget.protocol_filter.findData("tcp"))
    widget.apply_filters_button.click()
    assert not widget.scene.relation_items
    widget.reset_filters_button.click()
    assert widget.scene.relation_items
    assert widget.port_filter.text() == ""
    assert widget.unknown_filter.isChecked()


def test_filter_preserves_rule_and_source_details(widget):
    widget.set_filters(AclMapFilter(source_cidr="0.0.0.1"))
    relation = next(iter(widget._relations.values()))
    widget.relation_selector.setCurrentIndex(1)
    details = widget.details.toPlainText()
    assert relation.rule.rule_id in details
    assert relation.rule.source_location.source_name in details
    assert relation.rule.source_location.object_path in details
    assert str(widget.state.graph.revision.sources[0].source_document_id) in details


def test_filter_toolbar_fits_existing_minimum_window_size(widget, app):
    from firewall_compliance.interfaces.desktop.qt_theme import apply_theme

    apply_theme(app)
    widget.resize(1000, 650)
    widget.show()
    app.processEvents()
    assert widget.width() == 1000 and widget.height() == 650
    assert widget.minimumSizeHint().width() <= 1000
    for control in (
        widget.source_filter,
        widget.destination_filter,
        widget.protocol_filter,
        widget.port_filter,
        widget.apply_filters_button,
        widget.reset_filters_button,
        widget.html_export_button,
        widget.png_export_button,
    ):
        assert control.geometry().right() < widget.width()
        assert control.geometry().bottom() < widget.height()


@pytest.mark.parametrize(
    "source,port,protocol", [("invalid", "", "tcp"), ("", "0", "tcp"), ("", "53", "icmp")]
)
def test_invalid_filter_preserves_previous_selection(widget, source, port, protocol):
    before = widget.scene.relation_items.copy()
    widget.source_filter.setText(source)
    widget.port_filter.setText(port)
    widget.protocol_filter.setCurrentIndex(widget.protocol_filter.findData(protocol))
    widget.apply_filters_button.click()
    assert widget.filters is None
    assert widget.scene.relation_items == before
    assert "Некорректный фильтр" in widget.status_label.text()


def test_html_exports_current_filter_and_full_source_without_file_reads(widget, directory):
    widget.set_filters(AclMapFilter(source_cidr="192.0.2.0/24"))
    path = directory / "map.html"
    widget.export_html(path)
    result = path.read_text(encoding="utf-8")
    assert "192.0.2.0/24" in result
    assert "synthetic.cfg" in result
    assert widget.state.graph.revision.parse_result.configuration.content_sha256 in result
    assert widget.state.graph.limitations[0] in result


def test_png_contains_scene_at_native_scale_with_source_legend(widget, directory):
    text = "\n".join(
        item.toPlainText() for item in widget.scene.items() if hasattr(item, "toPlainText")
    )
    assert "SHA-256" in text and "synthetic.cfg" in text
    assert str(widget.state.graph.revision.revision_id) in text
    assert widget.state.graph.limitations[0] in text
    path = directory / "map.png"
    widget.export_png(path)
    image = QImage(str(path))
    assert not image.isNull()
    assert image.width() > 1000 and image.height() > 300
    assert image.width() * image.height() <= widget.MAX_PNG_PIXELS
    assert path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")


def test_png_budget_refuses_before_overwriting_existing_file(widget, directory, monkeypatch):
    target = directory / "keep.png"
    target.write_bytes(b"prior-output")
    monkeypatch.setattr(widget, "MAX_PNG_PIXELS", 1)
    with pytest.raises(ValueError, match="бюджет"):
        widget.export_png(target)
    assert target.read_bytes() == b"prior-output"


def test_render_budget_can_be_reduced_by_view_filter_without_truncating_graph(widget, monkeypatch):
    value = graph(rule("first", 10), rule("second", 20, src=(20, 30)))
    monkeypatch.setattr(widget.scene, "MAX_RELATIONS", 1)
    widget.set_map_state(AclMapState("ready", value, "Synthetic budget"))
    assert widget.scene.render_status == "limited"
    assert not widget.png_export_button.isEnabled()
    widget.set_filters(AclMapFilter(source_cidr="0.0.0.1"))
    assert widget.scene.render_status == "ready"
    assert widget.png_export_button.isEnabled()
    assert len(widget.state.graph.relations) == 2


def test_empty_state_clears_exports_and_no_stale_graph(widget, directory):
    widget.set_map_state(AclMapState("empty", None, "No source"))
    assert not widget.html_export_button.isEnabled()
    assert not widget.png_export_button.isEnabled()
    with pytest.raises(ValueError):
        widget.export_html(directory / "none.html")
    with pytest.raises(ValueError):
        widget.export_png(directory / "none.png")


@pytest.mark.parametrize("format_name", ["html", "png"])
def test_exports_protect_source_aliases(widget, directory, format_name):
    source = directory / "synthetic.cfg"
    source.write_text("synthetic original", encoding="utf-8")
    value = widget.state.graph
    config = value.revision.parse_result.configuration.model_copy(
        update={"source_name": str(source)}
    )
    # A new graph derives from the explicitly named captured source, not a file read.
    parsed = value.revision.parse_result.model_copy(update={"configuration": config})
    sources = tuple(
        item.model_copy(update={"source_name": str(source)}) for item in value.revision.sources
    )
    revision = value.revision.model_copy(update={"parse_result": parsed, "sources": sources})
    from firewall_compliance.analysis.acl_map import build_acl_map

    revised = build_acl_map(revision, built_at=NOW)
    widget.set_map_state(AclMapState("ready", revised, "Synthetic file alias"))
    target = directory / f"alias.{format_name}"
    os.link(source, target)
    with pytest.raises(ValueError, match="перезаписать"):
        getattr(widget, f"export_{format_name}")(target)
    assert source.read_text(encoding="utf-8") == "synthetic original"
