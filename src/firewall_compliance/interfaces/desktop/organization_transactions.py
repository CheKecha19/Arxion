"""Connection-local organization write capability (implementation_done_unverified).

This module neither starts nor completes transactions. The transaction owner must
keep the same transaction open for the complete approved scope and leave that
scope before committing or rolling back. SQLite's ``in_transaction`` exposes
current activity, not a transaction identity; enforcing the complete boundary
belongs to the subsequent transaction orchestration implementation.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from threading import RLock, get_ident
from weakref import WeakValueDictionary

ORGANIZATION_WRITE_FUNCTION = "fc_org_write_allowed"

# Temporary source block: the authoritative v2 schema names are not established
# yet. Expand this fixed list to the complete authoritative schema before any
# migration or connection wiring; legacy-only coverage is not a final scope.
_LEGACY_GUARDED_TABLES: tuple[str, ...] = (
    "projects",
    "runs",
    "items",
    "marks",
    "device_links",
    "integrations",
    "cloud_scans",
)
_GUARDED_OPERATIONS: tuple[str, ...] = ("INSERT", "UPDATE", "DELETE")

# Keep these exact statements as the future definition-verification source.
# Identifiers come exclusively from the private fixed lists above.
_LEGACY_GUARD_TRIGGER_DDL: tuple[str, ...] = tuple(
    f"CREATE TRIGGER fc_guard_{table}_{operation.lower()} "
    f"BEFORE {operation} ON {table}\n"
    "BEGIN\n"
    "  SELECT CASE WHEN fc_org_write_allowed() IS NOT 1\n"
    "    THEN RAISE(ABORT, 'organization writer required') END;\n"
    "END;"
    for table in _LEGACY_GUARDED_TABLES
    for operation in _GUARDED_OPERATIONS
)


def legacy_organization_guard_trigger_statements() -> tuple[str, ...]:
    """Return exact permanent guard DDL for the seven fixed legacy tables.

    This pure source contains 21 statements and never executes SQL. It accepts
    no identifiers and deliberately omits ``IF NOT EXISTS``. Coverage must be
    expanded with the authoritative v2 tables before migration or wiring.
    Implementation status: implementation_done_unverified.
    """
    return _LEGACY_GUARD_TRIGGER_DDL


def require_organization_guard_trusted_schema(
    connection: sqlite3.Connection,
) -> None:
    """Require the known schema setting needed by Python-backed trigger UDFs.

    Python's sqlite3 registration API cannot mark this UDF innocuous, so
    ``trusted_schema=OFF`` is incompatible with the selected trigger contract.
    Read the setting only: never enable it silently or probe by executing DML.
    Unsupported PRAGMA and malformed responses also fail closed. Passing this
    prerequisite does not establish actual trigger/UDF runtime compatibility;
    that proof remains deferred. This helper is not wired into connections.
    Implementation status: implementation_done_unverified.
    """
    try:
        cursor = connection.cursor()
        try:
            cursor.row_factory = None
            cursor.execute("PRAGMA main.trusted_schema")
            rows = cursor.fetchall()
        finally:
            cursor.close()
    except sqlite3.Error:
        raise OrganizationWriteGuardError(
            "Organization write guard schema mode could not be determined"
        ) from None

    if len(rows) != 1 or len(rows[0]) != 1 or type(rows[0][0]) is not int or rows[0][0] != 1:
        raise OrganizationWriteGuardError(
            "Organization write guard requires a supported trusted schema mode"
        )


def verify_legacy_organization_guard_definitions(
    connection: sqlite3.Connection,
) -> None:
    """Require exact permanent guard definitions on an existing connection.

    Read the main database schema without installing or repairing anything.
    Missing, changed, or additional own-prefix triggers fail closed. Compare
    exact names and SQL, allowing only SQLite's removal of one final statement
    semicolon. Other whitespace, casing, and body changes remain mismatches.
    Unrelated triggers are untouched. This temporary legacy-only verification
    source must expand with authoritative v2 tables before migration or wiring.
    Implementation status: implementation_done_unverified.
    """
    expected_names = tuple(
        f"fc_guard_{table}_{operation.lower()}"
        for table in _LEGACY_GUARDED_TABLES
        for operation in _GUARDED_OPERATIONS
    )
    expected = dict(zip(expected_names, _LEGACY_GUARD_TRIGGER_DDL, strict=True))
    try:
        cursor = connection.cursor()
        try:
            # Connection-level row factories must not alter schema row shape.
            cursor.row_factory = None
            cursor.execute(
                "SELECT name, sql FROM main.sqlite_schema "
                "WHERE type = 'trigger' "
                "AND substr(name, 1, 9) = 'fc_guard_' COLLATE NOCASE"
            )
            rows = cursor.fetchall()
        finally:
            cursor.close()
    except sqlite3.Error:
        raise OrganizationWriteGuardError(
            "Organization write guard definitions could not be verified"
        ) from None

    actual: dict[str, str] = {}
    for name, sql in rows:
        if not isinstance(name, str) or not isinstance(sql, str) or name in actual:
            raise OrganizationWriteGuardError("Organization write guard definitions are invalid")
        actual[name] = sql
    if actual.keys() != expected.keys() or any(
        actual[name].removesuffix(";") != statement.removesuffix(";")
        for name, statement in expected.items()
    ):
        raise OrganizationWriteGuardError(
            "Organization write guard definitions are missing or changed"
        )


# The registry coordinates registration only. Permission lives on each guard,
# bound to one exact connection. Weak values do not keep closed connections alive.
_guards: WeakValueDictionary[int, OrganizationWriteGuard] = WeakValueDictionary()
_registration_lock = RLock()


class OrganizationWriteGuardError(RuntimeError):
    """An organization write capability cannot be safely granted."""


class OrganizationWriteGuard:
    """Own the deny-by-default capability registered on one SQLite connection.

    Obtain instances through :func:`register_organization_write_guard`. Register
    once per connection, retain the returned guard with its transaction owner,
    and call ``close`` before closing the connection. Raw replacement of the UDF
    by other code is outside this compatibility guard's supported lifecycle.
    """

    def __init__(self, connection: sqlite3.Connection) -> None:
        """Initialize a disabled guard; registration is a separate operation."""
        self._connection = connection
        self._registered = False
        self._revoked = False
        self._scope_active = False
        self._approved = False
        self._owner_thread: int | None = None

    def _write_allowed(self) -> int:
        if (
            not self._registered
            or self._revoked
            or not self._approved
            or not self._scope_active
            or self._owner_thread != get_ident()
        ):
            return 0
        try:
            active = self._connection.in_transaction
        except sqlite3.Error:
            self._approved = False
            return 0
        if not active:
            # Once transaction loss is observed, a later BEGIN cannot revive it.
            self._approved = False
            return 0
        return 1

    @contextmanager
    def approved_scope(self) -> Iterator[None]:
        """Temporarily permit writes within an already active transaction.

        No SQL is executed. Nested entry revokes the outer scope's permission,
        even if its caller catches the error. Cross-thread SQL never receives
        permission. Every exit, including BaseException, resets the capability.
        The caller must not end or replace the transaction inside this scope.
        """
        if self._scope_active:
            self._approved = False
            raise OrganizationWriteGuardError("Organization write scope is already active")
        if not self._registered or self._revoked:
            raise OrganizationWriteGuardError("Organization write guard is not registered")
        try:
            active = self._connection.in_transaction
        except sqlite3.Error as exc:
            raise OrganizationWriteGuardError("SQLite connection is unavailable") from exc
        if not active:
            raise OrganizationWriteGuardError("An active SQLite transaction is required")

        self._scope_active = True
        self._owner_thread = get_ident()
        self._approved = True
        try:
            yield
        finally:
            self._approved = False
            self._owner_thread = None
            self._scope_active = False

    def close(self) -> None:
        """Irreversibly revoke this guard without closing its SQLite connection.

        The registered callback remains a deny-only function until replacement
        or connection close. This avoids unregistering a newer guard and keeps
        revocation effective even if SQLite is busy or already closed.
        """
        with _registration_lock:
            self._approved = False
            self._revoked = True
            self._registered = False
            if _guards.get(id(self._connection)) is self:
                del _guards[id(self._connection)]


def register_organization_write_guard(
    connection: sqlite3.Connection,
) -> OrganizationWriteGuard:
    """Register the zero-argument, non-deterministic organization guard UDF.

    Re-registration revokes the old handle before doing anything else. An active
    old scope makes replacement fail closed; its permission remains revoked.
    Registration failure likewise never restores the previous capability.
    """
    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("A sqlite3.Connection is required")
    with _registration_lock:
        previous = _guards.get(id(connection))
        if previous is not None:
            previous.close()
            if previous._scope_active:
                raise OrganizationWriteGuardError(
                    "Cannot replace an active organization write guard"
                )
        guard = OrganizationWriteGuard(connection)
        try:
            connection.create_function(
                ORGANIZATION_WRITE_FUNCTION,
                0,
                guard._write_allowed,
                deterministic=False,
            )
        except sqlite3.Error as exc:
            guard.close()
            raise OrganizationWriteGuardError(
                "Could not register the organization write guard"
            ) from exc
        guard._registered = True
        _guards[id(connection)] = guard
        return guard
