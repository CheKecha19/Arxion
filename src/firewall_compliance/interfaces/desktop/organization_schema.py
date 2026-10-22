"""Pure additive organization DDL; execution and seeding belong to later slices.

Legacy labels, creation times and settings remain in the original projects rows.
The deferred context-to-origin relation permits transactional singleton seeding.
Callers must enable SQLite foreign keys before executing individual statements.
"""

from __future__ import annotations

from typing import Final

AUTHORITATIVE_ORGANIZATION_TABLES: Final[tuple[str, ...]] = (
    "org_context",
    "org_origins",
    "org_profiles",
    "org_profile_settings_sources",
    "org_profile_conflicts",
    "org_profile_selections",
    "org_connections",
    "org_scan_provenance",
    "org_devices",
    "org_device_aliases",
    "org_device_source_bindings",
)

_ORGANIZATION_SCHEMA_SQL: Final[tuple[str, ...]] = (
    """
    CREATE TABLE org_context (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        organization_id TEXT NOT NULL UNIQUE CHECK (
            length(organization_id) = 36
            AND substr(organization_id, 9, 1) = '-'
            AND substr(organization_id, 14, 1) = '-'
            AND substr(organization_id, 19, 1) = '-'
            AND substr(organization_id, 24, 1) = '-'
            AND length(replace(organization_id, '-', '')) = 32
            AND replace(organization_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        ),
        display_name TEXT NOT NULL,
        version INTEGER NOT NULL DEFAULT 1 CHECK (
            typeof(version) = 'integer' AND version >= 1
        ),
        created_at TEXT NOT NULL,
        internal_write_project_id TEXT NOT NULL REFERENCES projects(id),
        internal_write_role TEXT NOT NULL DEFAULT 'internal_write'
            CHECK (internal_write_role = 'internal_write'),
        FOREIGN KEY (
            organization_id, internal_write_project_id, internal_write_role
        ) REFERENCES org_origins (organization_id, project_id, role)
            DEFERRABLE INITIALLY DEFERRED
    )
    """,
    """
    CREATE TABLE org_origins (
        organization_id TEXT NOT NULL REFERENCES org_context(organization_id),
        project_id TEXT NOT NULL REFERENCES projects(id),
        role TEXT NOT NULL CHECK (role IN ('legacy', 'internal_write')),
        PRIMARY KEY (organization_id, project_id),
        UNIQUE (organization_id, project_id, role)
    )
    """,
    """
    CREATE UNIQUE INDEX org_origins_one_internal_write
        ON org_origins (organization_id)
        WHERE role = 'internal_write'
    """,
    """
    CREATE TABLE org_profiles (
        organization_id TEXT NOT NULL REFERENCES org_context(organization_id),
        profile_id TEXT NOT NULL CHECK (
            length(profile_id) = 36
            AND substr(profile_id, 9, 1) = '-'
            AND substr(profile_id, 14, 1) = '-'
            AND substr(profile_id, 19, 1) = '-'
            AND substr(profile_id, 24, 1) = '-'
            AND length(replace(profile_id, '-', '')) = 32
            AND replace(profile_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        ),
        version INTEGER NOT NULL CHECK (
            typeof(version) = 'integer' AND version >= 1
        ),
        configuration_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (organization_id, profile_id, version)
    )
    """,
    """
    CREATE TABLE org_profile_settings_sources (
        organization_id TEXT NOT NULL REFERENCES org_context(organization_id),
        source_id TEXT NOT NULL,
        origin_project_id TEXT NOT NULL,
        source_kind TEXT NOT NULL CHECK (source_kind IN ('project', 'run')),
        run_id TEXT REFERENCES runs(id),
        PRIMARY KEY (organization_id, source_id),
        FOREIGN KEY (organization_id, origin_project_id)
            REFERENCES org_origins(organization_id, project_id),
        CHECK (
            (source_kind = 'project' AND run_id IS NULL)
            OR (source_kind = 'run' AND run_id IS NOT NULL)
        )
    )
    """,
    """
    CREATE TRIGGER org_profiles_no_update
        BEFORE UPDATE ON org_profiles
        BEGIN
            SELECT RAISE(ABORT, 'Profile versions are immutable');
        END
    """,
    """
    CREATE TRIGGER org_profiles_no_delete
        BEFORE DELETE ON org_profiles
        BEGIN
            SELECT RAISE(ABORT, 'Profile versions are immutable');
        END
    """,
    """
    CREATE TRIGGER org_profiles_no_replace
        BEFORE INSERT ON org_profiles
        WHEN EXISTS (
            SELECT 1 FROM org_profiles
            WHERE organization_id = NEW.organization_id
                AND profile_id = NEW.profile_id AND version = NEW.version
        )
        BEGIN
            SELECT RAISE(ABORT, 'Profile versions are immutable');
        END
    """,
    """
    CREATE UNIQUE INDEX org_profile_sources_one_project
        ON org_profile_settings_sources (organization_id, origin_project_id)
        WHERE source_kind = 'project'
    """,
    """
    CREATE UNIQUE INDEX org_profile_sources_one_run
        ON org_profile_settings_sources (organization_id, run_id)
        WHERE source_kind = 'run'
    """,
    """
    CREATE TRIGGER org_profile_sources_run_origin_insert
        BEFORE INSERT ON org_profile_settings_sources
        WHEN NEW.source_kind = 'run' AND NOT EXISTS (
            SELECT 1 FROM runs
            WHERE id = NEW.run_id AND project_id = NEW.origin_project_id
        )
        BEGIN
            SELECT RAISE(ABORT, 'Profile settings run does not belong to origin');
        END
    """,
    """
    CREATE TRIGGER org_profile_sources_run_origin_update
        BEFORE UPDATE ON org_profile_settings_sources
        WHEN NEW.source_kind = 'run' AND NOT EXISTS (
            SELECT 1 FROM runs
            WHERE id = NEW.run_id AND project_id = NEW.origin_project_id
        )
        BEGIN
            SELECT RAISE(ABORT, 'Profile settings run does not belong to origin');
        END
    """,
    """
    CREATE TABLE org_profile_conflicts (
        organization_id TEXT NOT NULL REFERENCES org_context(organization_id),
        conflict_id TEXT NOT NULL,
        first_source_id TEXT NOT NULL,
        second_source_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (organization_id, conflict_id),
        UNIQUE (organization_id, first_source_id, second_source_id),
        CHECK (first_source_id < second_source_id),
        FOREIGN KEY (organization_id, first_source_id)
            REFERENCES org_profile_settings_sources(organization_id, source_id),
        FOREIGN KEY (organization_id, second_source_id)
            REFERENCES org_profile_settings_sources(organization_id, source_id)
    )
    """,
    """
    CREATE TABLE org_profile_selections (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        organization_id TEXT NOT NULL REFERENCES org_context(organization_id),
        profile_id TEXT NOT NULL,
        profile_version INTEGER NOT NULL,
        choice_kind TEXT NOT NULL CHECK (choice_kind = 'explicit_choice'),
        resolves_conflict_id TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (organization_id, profile_id, profile_version)
            REFERENCES org_profiles(organization_id, profile_id, version),
        FOREIGN KEY (organization_id, resolves_conflict_id)
            REFERENCES org_profile_conflicts(organization_id, conflict_id)
    )
    """,
    """
    CREATE TRIGGER org_profile_selections_no_update
        BEFORE UPDATE ON org_profile_selections
        BEGIN
            SELECT RAISE(ABORT, 'Profile selection history is append-only');
        END
    """,
    """
    CREATE TRIGGER org_profile_selections_no_replace
        BEFORE INSERT ON org_profile_selections
        WHEN EXISTS (
            SELECT 1 FROM org_profile_selections WHERE sequence = NEW.sequence
        )
        BEGIN
            SELECT RAISE(ABORT, 'Profile selection history is append-only');
        END
    """,
    """
    CREATE TRIGGER org_profile_selections_no_delete
        BEFORE DELETE ON org_profile_selections
        BEGIN
            SELECT RAISE(ABORT, 'Profile selection history is append-only');
        END
    """,
)


# Source keys are exact identities, never patterns or basename suggestions.
# Connection scope uses the catalog UUID even for equal providers in one origin.
_DEVICE_SCHEMA_SQL: Final[tuple[str, ...]] = (
    """
    CREATE TABLE org_devices (
        organization_id TEXT NOT NULL REFERENCES org_context(organization_id),
        device_uid TEXT NOT NULL CHECK (
            length(device_uid) = 36
            AND substr(device_uid, 9, 1) = '-'
            AND substr(device_uid, 14, 1) = '-'
            AND substr(device_uid, 19, 1) = '-'
            AND substr(device_uid, 24, 1) = '-'
            AND length(replace(device_uid, '-', '')) = 32
            AND replace(device_uid, '-', '') NOT GLOB '*[^0-9a-f]*'
        ),
        display_name TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (organization_id, device_uid)
    )
    """,
    """
    CREATE TABLE org_device_aliases (
        organization_id TEXT NOT NULL REFERENCES org_context(organization_id),
        legacy_project_id TEXT NOT NULL,
        raw_device_id TEXT NOT NULL,
        device_uid TEXT NOT NULL,
        mapping_basis TEXT NOT NULL CHECK (
            mapping_basis IN ('legacy_identity', 'explicit')
        ),
        created_at TEXT NOT NULL,
        PRIMARY KEY (organization_id, legacy_project_id, raw_device_id),
        FOREIGN KEY (organization_id, legacy_project_id)
            REFERENCES org_origins(organization_id, project_id),
        FOREIGN KEY (organization_id, device_uid)
            REFERENCES org_devices(organization_id, device_uid)
    )
    """,
    """
    CREATE UNIQUE INDEX org_device_aliases_one_legacy_identity
        ON org_device_aliases (organization_id, device_uid)
        WHERE mapping_basis = 'legacy_identity'
    """,
    """
    CREATE TRIGGER org_device_aliases_legacy_insert
        BEFORE INSERT ON org_device_aliases
        WHEN NEW.mapping_basis = 'legacy_identity' AND EXISTS (
            SELECT 1 FROM org_device_aliases
            WHERE organization_id = NEW.organization_id
                AND device_uid = NEW.device_uid
        )
        BEGIN
            SELECT RAISE(ABORT, 'Additional device aliases require explicit mapping');
        END
    """,
    """
    CREATE TRIGGER org_device_aliases_legacy_update
        BEFORE UPDATE ON org_device_aliases
        WHEN NEW.mapping_basis = 'legacy_identity' AND EXISTS (
            SELECT 1 FROM org_device_aliases
            WHERE organization_id = NEW.organization_id
                AND device_uid = NEW.device_uid
                AND NOT (
                    organization_id = OLD.organization_id
                    AND legacy_project_id = OLD.legacy_project_id
                    AND raw_device_id = OLD.raw_device_id
                )
        )
        BEGIN
            SELECT RAISE(ABORT, 'Additional device aliases require explicit mapping');
        END
    """,
    """
    CREATE TABLE org_device_source_bindings (
        organization_id TEXT NOT NULL REFERENCES org_context(organization_id),
        binding_id TEXT NOT NULL,
        device_uid TEXT NOT NULL,
        origin_project_id TEXT NOT NULL,
        scope_kind TEXT NOT NULL CHECK (scope_kind IN ('origin', 'connection')),
        connection_id TEXT,
        connection_provider TEXT,
        source_kind TEXT NOT NULL CHECK (length(source_kind) > 0),
        source_key TEXT NOT NULL CHECK (length(source_key) > 0),
        mapping_basis TEXT NOT NULL CHECK (mapping_basis IN ('explicit', 'proven')),
        mapping_evidence TEXT NOT NULL CHECK (length(mapping_evidence) > 0),
        created_at TEXT NOT NULL,
        PRIMARY KEY (organization_id, binding_id),
        FOREIGN KEY (organization_id, device_uid)
            REFERENCES org_devices(organization_id, device_uid),
        FOREIGN KEY (organization_id, origin_project_id)
            REFERENCES org_origins(organization_id, project_id),
        FOREIGN KEY (
            organization_id, connection_id, origin_project_id, connection_provider
        ) REFERENCES org_connections (
            organization_id, connection_id, origin_project_id, provider
        ),
        CHECK (
            (scope_kind = 'origin'
                AND connection_id IS NULL AND connection_provider IS NULL)
            OR (scope_kind = 'connection'
                AND connection_id IS NOT NULL AND connection_provider IS NOT NULL)
        )
    )
    """,
    """
    CREATE UNIQUE INDEX org_device_bindings_exact_origin_source
        ON org_device_source_bindings (
            organization_id, origin_project_id, source_kind, source_key
        )
        WHERE scope_kind = 'origin'
    """,
    """
    CREATE UNIQUE INDEX org_device_bindings_exact_connection_source
        ON org_device_source_bindings (
            organization_id, origin_project_id, connection_id, connection_provider,
            source_kind, source_key
        )
        WHERE scope_kind = 'connection'
    """,
)


# config/protected_secret store opaque original TEXT without decoding. Historical
# scans keep selection/config/result in cloud_scans; provenance only adds refs.
# Nonempty evidence is structural metadata, not proof that a mapping is true:
# a later migration must establish an unambiguous mapping before choosing proven.
_CONNECTION_SCHEMA_SQL: Final[tuple[str, ...]] = (
    """
    CREATE TABLE org_connections (
        organization_id TEXT NOT NULL REFERENCES org_context(organization_id),
        connection_id TEXT NOT NULL CHECK (
            length(connection_id) = 36
            AND substr(connection_id, 9, 1) = '-'
            AND substr(connection_id, 14, 1) = '-'
            AND substr(connection_id, 19, 1) = '-'
            AND substr(connection_id, 24, 1) = '-'
            AND length(replace(connection_id, '-', '')) = 32
            AND replace(connection_id, '-', '') NOT GLOB '*[^0-9a-f]*'
        ),
        origin_project_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        label TEXT NOT NULL,
        config TEXT NOT NULL,
        protected_secret TEXT NOT NULL,
        created_at TEXT NOT NULL,
        legacy_project_id TEXT,
        legacy_provider TEXT,
        PRIMARY KEY (organization_id, connection_id),
        UNIQUE (organization_id, connection_id, origin_project_id),
        UNIQUE (organization_id, connection_id, origin_project_id, provider),
        FOREIGN KEY (organization_id, origin_project_id)
            REFERENCES org_origins(organization_id, project_id),
        FOREIGN KEY (legacy_project_id, legacy_provider)
            REFERENCES integrations(project_id, provider),
        CHECK (
            (legacy_project_id IS NULL AND legacy_provider IS NULL)
            OR (legacy_project_id IS NOT NULL AND legacy_provider IS NOT NULL
                AND legacy_project_id = origin_project_id
                AND legacy_provider = provider)
        )
    )
    """,
    """
    CREATE UNIQUE INDEX org_connections_one_legacy_row
        ON org_connections (legacy_project_id, legacy_provider)
        WHERE legacy_project_id IS NOT NULL
    """,
    """
    CREATE TABLE org_scan_provenance (
        organization_id TEXT NOT NULL REFERENCES org_context(organization_id),
        scan_id TEXT NOT NULL REFERENCES cloud_scans(id),
        origin_project_id TEXT NOT NULL,
        mapping_state TEXT NOT NULL DEFAULT 'unresolved_legacy'
            CHECK (mapping_state IN ('unresolved_legacy', 'proven')),
        connection_id TEXT,
        mapping_evidence TEXT,
        unresolved_reason TEXT,
        PRIMARY KEY (organization_id, scan_id),
        FOREIGN KEY (organization_id, origin_project_id)
            REFERENCES org_origins(organization_id, project_id),
        FOREIGN KEY (organization_id, connection_id, origin_project_id)
            REFERENCES org_connections(
                organization_id, connection_id, origin_project_id
            ),
        CHECK (
            (mapping_state = 'unresolved_legacy' AND connection_id IS NULL
                AND mapping_evidence IS NULL
                AND unresolved_reason IS NOT NULL AND length(unresolved_reason) > 0)
            OR (mapping_state = 'proven' AND connection_id IS NOT NULL
                AND mapping_evidence IS NOT NULL AND length(mapping_evidence) > 0
                AND unresolved_reason IS NULL)
        )
    )
    """,
    """
    CREATE TRIGGER org_scan_provenance_origin_insert
        BEFORE INSERT ON org_scan_provenance
        WHEN NOT EXISTS (
            SELECT 1 FROM cloud_scans
            WHERE id = NEW.scan_id AND project_id = NEW.origin_project_id
        )
        BEGIN
            SELECT RAISE(ABORT, 'Historical scan does not belong to origin');
        END
    """,
    """
    CREATE TRIGGER org_scan_provenance_origin_update
        BEFORE UPDATE ON org_scan_provenance
        WHEN NOT EXISTS (
            SELECT 1 FROM cloud_scans
            WHERE id = NEW.scan_id AND project_id = NEW.origin_project_id
        )
        BEGIN
            SELECT RAISE(ABORT, 'Historical scan does not belong to origin');
        END
    """,
)


def build_organization_schema_sql() -> tuple[str, ...]:
    """Return fixed ordered statements for the implemented organization tables.

    This tuple is deliberately incomplete for a full v2 store. It neither opens
    a database nor changes schema versions, legacy rows or result payloads.
    No selection means an inactive future-run profile. A conflict remains
    unresolved until an explicit selection references it; timestamps never
    select a profile or resolve conflicting legacy settings automatically.
    """
    return _ORGANIZATION_SCHEMA_SQL + _CONNECTION_SCHEMA_SQL + _DEVICE_SCHEMA_SQL
