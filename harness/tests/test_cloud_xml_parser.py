"""Synthetic VMware XML boundaries, including encoding-independent DTD denial."""

import pytest

from firewall_compliance.infrastructure.cloud_vmware import CloudError, _xml


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-le", "utf-16-be"])
@pytest.mark.parametrize(
    "declaration",
    [
        '<!DOCTYPE root [<!ENTITY test "SYNTHETIC-ENTITY-CONTENT">]>',
        '<!DOCTYPE root SYSTEM "https://synthetic.invalid/private.dtd">',
        '<!DOCTYPE root [<!ENTITY test SYSTEM "file:///SYNTHETIC-PRIVATE-FILE">]>',
        '<!DOCTYPE root>',
    ],
)
def test_dtd_and_entities_are_rejected_in_every_supported_encoding(encoding, declaration):
    data = (declaration + "<root>synthetic</root>").encode(encoding)
    with pytest.raises(CloudError) as raised:
        _xml(data)
    assert "SYNTHETIC" not in str(raised.value)
    assert "synthetic.invalid" not in str(raised.value)
    assert "XML" in str(raised.value)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16"])
def test_ordinary_namespaced_cloud_xml_preserves_text_and_attributes(encoding):
    declaration = '<?xml version="1.0" encoding="' + encoding + '"?>'
    data = (
        declaration
        + '<OrgList xmlns="http://www.vmware.com/vcloud/v1.5">'
        + '<Org name="Синтетический проект" href="https://synthetic.invalid/api/org/1"/>'
        + "</OrgList>"
    ).encode(encoding)
    result = _xml(data)
    child = list(result)[0]
    assert child.tag == "{http://www.vmware.com/vcloud/v1.5}Org"
    assert child.attrib["name"] == "Синтетический проект"
    assert child.attrib["href"] == "https://synthetic.invalid/api/org/1"


@pytest.mark.parametrize(
    "data",
    [b"<root>", b"not XML", b'<?xml version="1.0" encoding="SYNTHETIC-UNKNOWN"?><root/>'],
)
def test_malformed_xml_is_a_safe_cloud_error(data):
    with pytest.raises(CloudError) as raised:
        _xml(data)
    assert "SYNTHETIC" not in str(raised.value)
    assert "XML" in str(raised.value)
