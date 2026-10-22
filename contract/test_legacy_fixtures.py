from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest

FIXTURES_DIRECTORY = Path(__file__).parents[1] / "fixtures" / "legacy"


@pytest.mark.parametrize(
    ("source_name", "expected_sha256"),
    [
        ("test_sample.json", "0c039ebe62cdeb4f9cb08c127793bff1307749cbfc978c60cba6306369a70747"),
        ("test_complex.json", "ed98386f8d7eaf5004240b517009a0bc4ad146ba4550e06a192aee3af8189ca7"),
        ("test_acl.txt", "0b9b65c924bd3d4661fb66887297b6f2125df86fac28717964457aae150cbc2f"),
    ],
)
def test_legacy_fixture_content_is_preserved(source_name: str, expected_sha256: str) -> None:
    content = (FIXTURES_DIRECTORY / source_name).read_bytes()

    assert sha256(content).hexdigest() == expected_sha256
