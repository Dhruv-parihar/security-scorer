"""
Research Database Schema — Security Scoring Framework
======================================================
SQLite schema for the empirical cybersecurity research data layer.

Design principles:
- Raw findings are PRIMARY research observations. Scores are DERIVED artifacts.
- NOT_APPLICABLE is semantically distinct from FAIL and must never reduce scores.
- A finding not evaluated is NOT_TESTED — never silently PASS or FAIL.
- Target identity can be anonymized. PII is not stored.
- Provenance (tool version, methodology version, schema version) recorded per
  assessment for reproducibility.
- Foreign keys enforced. Indexes on common research query paths.
- Schema versioned via migrations table. Safe to re-run (idempotent).

Schema version: 1
"""

import sqlite3
import os
from datetime import datetime, timezone

SCHEMA_VERSION = 1

# Finding status values — must remain consistent with FINDING_STATUSES
FINDING_STATUSES = ("PASS", "FAIL", "NOT_APPLICABLE", "NOT_TESTED", "ERROR", "UNKNOWN")

# Finding layers
FINDING_LAYERS = ("OS", "NETWORK", "WEB")

# Authorization statuses
AUTH_STATUSES = ("OWNED", "LAB", "EXPLICITLY_AUTHORIZED", "CONSENTED_RESEARCH")

# Finding taxonomy categories
TAXONOMY_CATEGORIES = (
    "PATCHING", "AUTHENTICATION", "AUTHORIZATION", "ACCESS_CONTROL",
    "CONFIGURATION", "EXPOSURE", "CRYPTOGRAPHY", "INPUT_VALIDATION",
    "SESSION_SECURITY", "PRIVILEGE", "LOGGING", "INFORMATION_DISCLOSURE",
    "OUTDATED_SOFTWARE", "UNNECESSARY_SERVICE", "UNCATEGORIZED",
)

# Remediation statuses
REMEDIATION_STATUSES = ("PENDING", "IN_PROGRESS", "VERIFIED_FIXED", "WONT_FIX", "FALSE_POSITIVE")


MIGRATIONS = [
    # Migration 0 → 1: initial schema
    """
    -- SCHEMA_MIGRATIONS: tracks applied migrations
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version        INTEGER PRIMARY KEY,
        applied_at     TEXT NOT NULL,
        description    TEXT NOT NULL
    );

    -- TAXONOMY: finding category/subcategory reference table.
    -- Evolves independently of findings — findings reference by id, not by name string.
    CREATE TABLE IF NOT EXISTS taxonomy (
        taxonomy_id    INTEGER PRIMARY KEY AUTOINCREMENT,
        category       TEXT NOT NULL,
        subcategory    TEXT,
        description    TEXT,
        reference      TEXT,     -- e.g. CWE-89, OWASP-A03
        UNIQUE(category, subcategory)
    );

    -- TARGET: anonymized research target.
    -- target_alias is the human-readable label (e.g. "metasploitable-2-lab-01").
    -- No hostnames, IP addresses, or credentials stored here.
    CREATE TABLE IF NOT EXISTS target (
        target_id          TEXT PRIMARY KEY,   -- UUID
        target_alias       TEXT NOT NULL,      -- human-readable, anonymized
        target_type        TEXT NOT NULL,      -- server / workstation / network_device / web_app / lab_vm
        environment        TEXT NOT NULL,      -- lab / owned / authorized / consented
        os_family          TEXT,              -- linux / windows / macos / unknown / not_applicable
        os_name            TEXT,              -- e.g. "Ubuntu 8.04", "Parrot OS 7.3"
        os_version         TEXT,
        deployment_type    TEXT,              -- vm / bare_metal / container / cloud
        technology_notes   TEXT,             -- free-text tech stack notes
        authorization_status TEXT NOT NULL,  -- OWNED / LAB / EXPLICITLY_AUTHORIZED / CONSENTED_RESEARCH
        authorization_ref  TEXT,             -- reference doc / ticket / consent form ID
        created_at         TEXT NOT NULL,
        notes              TEXT,
        CHECK(authorization_status IN ('OWNED','LAB','EXPLICITLY_AUTHORIZED','CONSENTED_RESEARCH'))
    );

    -- ASSESSMENT: one assessment run against one target.
    CREATE TABLE IF NOT EXISTS assessment (
        assessment_id      TEXT PRIMARY KEY,   -- UUID
        target_id          TEXT NOT NULL REFERENCES target(target_id) ON DELETE RESTRICT,
        assessment_date    TEXT NOT NULL,      -- ISO-8601
        start_time         TEXT,
        end_time           TEXT,
        tool_version       TEXT NOT NULL,      -- e.g. "1.0.0"
        methodology_version TEXT NOT NULL,     -- e.g. "1.0"
        schema_version     INTEGER NOT NULL,   -- schema version at time of assessment
        scope              TEXT NOT NULL,      -- OS / NETWORK / WEB / ALL / custom
        authorization_status TEXT NOT NULL,
        assessor           TEXT,              -- anonymized assessor ID
        notes              TEXT,
        CHECK(authorization_status IN ('OWNED','LAB','EXPLICITLY_AUTHORIZED','CONSENTED_RESEARCH'))
    );

    -- FINDING: one raw observation from one assessment.
    -- This is the PRIMARY research observation unit.
    CREATE TABLE IF NOT EXISTS finding (
        finding_id         TEXT PRIMARY KEY,   -- UUID
        assessment_id      TEXT NOT NULL REFERENCES assessment(assessment_id) ON DELETE RESTRICT,
        layer              TEXT NOT NULL,      -- OS / NETWORK / WEB
        check_id           TEXT NOT NULL,      -- e.g. "ssh_root_login", "header_csp"
        check_version      TEXT,              -- version of the check/detector
        taxonomy_id        INTEGER REFERENCES taxonomy(taxonomy_id),
        status             TEXT NOT NULL,      -- PASS/FAIL/NOT_APPLICABLE/NOT_TESTED/ERROR/UNKNOWN
        severity           TEXT,              -- critical/high/medium/low/informational (null if NOT_APPLICABLE)
        confidence         TEXT DEFAULT 'HIGH', -- HIGH / MEDIUM / LOW
        description        TEXT NOT NULL,
        evidence           TEXT,              -- raw evidence string/JSON
        recommendation     TEXT,
        standard_ref       TEXT,              -- e.g. CIS-1.1, CVE-2011-2523, CWE-89
        detector_notes     TEXT,
        detected_at        TEXT NOT NULL,     -- ISO-8601
        CHECK(layer IN ('OS','NETWORK','WEB')),
        CHECK(status IN ('PASS','FAIL','NOT_APPLICABLE','NOT_TESTED','ERROR','UNKNOWN')),
        CHECK(severity IN ('critical','high','medium','low','informational') OR severity IS NULL),
        CHECK(confidence IN ('HIGH','MEDIUM','LOW'))
    );

    -- SCORE_SNAPSHOT: derived scores stored as reproducible snapshots.
    -- Scores are NOT the primary research data — findings are.
    -- Storing snapshots allows comparison across scoring model versions.
    CREATE TABLE IF NOT EXISTS score_snapshot (
        snapshot_id        TEXT PRIMARY KEY,   -- UUID
        assessment_id      TEXT NOT NULL REFERENCES assessment(assessment_id) ON DELETE RESTRICT,
        scoring_model_id   TEXT NOT NULL,      -- e.g. "weighted_composite_v1"
        scoring_model_ver  TEXT NOT NULL,      -- version of scoring algorithm
        os_score           REAL,
        network_score      REAL,
        web_score          REAL,
        composite_score    REAL,
        weight_os          REAL,
        weight_network     REAL,
        weight_web         REAL,
        weakest_layer      TEXT,
        model_metadata     TEXT,              -- JSON: any extra model params
        calculated_at      TEXT NOT NULL,     -- ISO-8601
        notes              TEXT
    );

    -- REMEDIATION: longitudinal remediation tracking per finding.
    CREATE TABLE IF NOT EXISTS remediation (
        remediation_id     TEXT PRIMARY KEY,   -- UUID
        finding_id         TEXT NOT NULL REFERENCES finding(finding_id) ON DELETE RESTRICT,
        recommendation     TEXT NOT NULL,
        status             TEXT NOT NULL DEFAULT 'PENDING',
        remediation_date   TEXT,              -- when remediation was applied
        effort_hours       REAL,             -- optional effort estimate
        verification_assessment_id TEXT REFERENCES assessment(assessment_id),
        verification_result TEXT,            -- VERIFIED_FIXED / STILL_PRESENT / REGRESSED
        notes              TEXT,
        created_at         TEXT NOT NULL,
        CHECK(status IN ('PENDING','IN_PROGRESS','VERIFIED_FIXED','WONT_FIX','FALSE_POSITIVE'))
    );

    -- INDEXES for common research queries
    CREATE INDEX IF NOT EXISTS idx_finding_assessment  ON finding(assessment_id);
    CREATE INDEX IF NOT EXISTS idx_finding_layer       ON finding(layer);
    CREATE INDEX IF NOT EXISTS idx_finding_status      ON finding(status);
    CREATE INDEX IF NOT EXISTS idx_finding_severity    ON finding(severity);
    CREATE INDEX IF NOT EXISTS idx_finding_check_id    ON finding(check_id);
    CREATE INDEX IF NOT EXISTS idx_assessment_target   ON assessment(target_id);
    CREATE INDEX IF NOT EXISTS idx_assessment_date     ON assessment(assessment_date);
    CREATE INDEX IF NOT EXISTS idx_score_assessment    ON score_snapshot(assessment_id);
    CREATE INDEX IF NOT EXISTS idx_remediation_finding ON remediation(finding_id);
    CREATE INDEX IF NOT EXISTS idx_target_auth         ON target(authorization_status);
    """,
]


def get_db_path(db_path=None):
    if db_path:
        return db_path
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "research.db")


def get_connection(db_path=None):
    """Return a SQLite connection with foreign keys enforced."""
    conn = sqlite3.connect(get_db_path(db_path))
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


def get_current_version(conn):
    try:
        row = conn.execute(
            "SELECT MAX(version) as v FROM schema_migrations"
        ).fetchone()
        return row["v"] if row and row["v"] is not None else -1
    except sqlite3.OperationalError:
        return -1


def migrate(conn):
    """Apply pending migrations idempotently. Returns new schema version."""
    current = get_current_version(conn)
    for i, sql in enumerate(MIGRATIONS):
        if i > current:
            conn.executescript(sql)
            conn.execute(
                "INSERT INTO schema_migrations(version, applied_at, description) VALUES (?,?,?)",
                (i, datetime.now(timezone.utc).isoformat(), f"migration_{i}")
            )
            conn.commit()
    return get_current_version(conn)


def initialize(db_path=None):
    """Initialize or migrate the research database. Returns (conn, version)."""
    conn = get_connection(db_path)
    version = migrate(conn)
    return conn, version


def seed_taxonomy(conn):
    """Seed the taxonomy table with initial categories. Idempotent."""
    entries = [
        ("PATCHING", None, "Missing patches or updates", None),
        ("AUTHENTICATION", None, "Authentication weaknesses", None),
        ("AUTHORIZATION", None, "Authorization/access control weaknesses", None),
        ("ACCESS_CONTROL", None, "Filesystem/resource access control", None),
        ("CONFIGURATION", None, "Security misconfiguration", "OWASP-A05"),
        ("EXPOSURE", None, "Unnecessary service or port exposure", None),
        ("CRYPTOGRAPHY", None, "Weak or absent cryptographic controls", None),
        ("INPUT_VALIDATION", None, "Missing or insufficient input validation", "CWE-20"),
        ("SESSION_SECURITY", None, "Session management weaknesses", None),
        ("PRIVILEGE", None, "Privilege configuration issues", None),
        ("LOGGING", None, "Missing or insufficient logging", None),
        ("INFORMATION_DISCLOSURE", None, "Unintended information disclosure", None),
        ("OUTDATED_SOFTWARE", None, "End-of-life or unpatched software", None),
        ("UNNECESSARY_SERVICE", None, "Unneeded services running", None),
        ("UNCATEGORIZED", None, "Not yet categorized", None),
    ]
    conn.executemany(
        "INSERT OR IGNORE INTO taxonomy(category, subcategory, description, reference) VALUES (?,?,?,?)",
        entries
    )
    conn.commit()
