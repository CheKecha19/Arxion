"""Native interprocess leases remain exclusive across platform type checking."""

import os
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

from firewall_compliance.interfaces.desktop.organization_lock import (
    _workspace_lock_path,
    acquire_workspace_lease,
    workspace_lease,
)


@pytest.fixture
def database():
    root = Path("artifacts/organization-lock-tests")
    root.mkdir(parents=True, exist_ok=True)
    # Bootstrap leases must work before a database file exists.
    return (root / f"{uuid4()}.sqlite3").resolve()


def child_acquisition(database):
    code = """
import sys
from pathlib import Path
from firewall_compliance.interfaces.desktop.organization_lock import (
    WorkspaceBusyError, acquire_workspace_lease,
)
try:
    lease = acquire_workspace_lease(Path(sys.argv[1]))
except WorkspaceBusyError as error:
    print('busy')
    assert error.owner is not None
else:
    lease.close()
    print('acquired')
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = (
        str(Path("src").resolve()) + os.pathsep + environment.get("PYTHONPATH", "")
    )
    result = subprocess.run(
        [sys.executable, "-c", code, str(database)],
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    return result.stdout.strip()


def test_native_lock_excludes_child_and_releases_without_removing_lockfile(database):
    lease = acquire_workspace_lease(database)
    try:
        assert lease.owner.pid == os.getpid()
        assert child_acquisition(database) == "busy"
    finally:
        lease.close()
    lease.close()
    assert lease.path.is_file()
    assert not database.exists()
    assert child_acquisition(database) == "acquired"


def test_exception_in_lease_body_releases_native_lock(database):
    with pytest.raises(ValueError, match="Synthetic body failure"), workspace_lease(database):
        assert child_acquisition(database) == "busy"
        raise ValueError("Synthetic body failure")
    assert child_acquisition(database) == "acquired"


def test_stale_diagnostic_metadata_does_not_prevent_native_acquisition(database):
    lockfile = _workspace_lock_path(database)
    lockfile.write_bytes(b"\0{malformed stale metadata}")
    with workspace_lease(database) as lease:
        assert lease.owner.pid == os.getpid()
        assert child_acquisition(database) == "busy"
    assert child_acquisition(database) == "acquired"
