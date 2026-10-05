"""
Test Suite — Research Database (Phase 1)
=========================================
Tests schema creation, FK integrity, all finding statuses,
NOT_APPLICABLE semantics, score snapshots, longitudinal remediation,
migration versioning, and prevalence queries.

Run: python3 -m pytest tests/test_database.py -v
  or: python3 tests/test_database.py
"""

import pytest
import sqlite3
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.schema import (
    initialize, seed_taxonomy, get_current_version,
    FINDING_STATUSES, FINDING_LAYERS, AUTH_STATUSES, SCHEMA_VERSION,
    MIGRATIONS, migrate,
)
from db.repository import (
    create_target, get_target, list_targets, add_target_identifier,
    list_target_identifiers,
    create_assessment, get_assessment, list_assessments, close_assessment,
    create_finding, get_findings, get_findings_by_status,
    get_finding_prevalence,
    create_score_snapshot, get_score_snapshots,
    create_remediation, update_remediation_status, get_remediations,
    get_taxonomy_id,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def db():
    """In-memory DB, initialized fresh for each test."""
    conn, version = initialize(":memory:")
    seed_taxonomy(conn)
    yield conn, version
    conn.close()


@pytest.fixture
def target_id(db):
    conn, _ = db
    return create_target(
        conn, alias="test-target-01", target_type="lab_vm",
        environment="lab", authorization_status="LAB",
        os_family="linux", os_name="Ubuntu 8.04",
        os_version="8.04", deployment_type="vm"
    )


@pytest.fixture
def assessment_id(db, target_id):
    conn, _ = db
    return create_assessment(
        conn, target_id=target_id, scope="ALL",
        authorization_status="LAB"
    )


# ── Schema creation ───────────────────────────────────────────────────────────

class TestSchemaCreation:
    def test_schema_version_is_current(self, db):
        conn, version = db
        assert version == SCHEMA_VERSION

    def test_all_tables_exist(self, db):
        conn, _ = db
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
        expected = {
            "schema_migrations", "taxonomy", "target", "target_identifier", "assessment",
            "finding", "score_snapshot", "remediation"
        }
        assert expected.issubset(tables), f"Missing tables: {expected - tables}"

    def test_foreign_keys_enabled(self, db):
        conn, _ = db
        result = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        assert result == 1

    def test_migration_is_idempotent(self, db):
        conn, v1 = db
        from db.schema import migrate
        v2 = migrate(conn)
        assert v1 == v2  # re-running migration must not change version

    def test_migration_recorded(self, db):
        conn, _ = db
        rows = conn.execute("SELECT * FROM schema_migrations").fetchall()
        assert len(rows) >= 1
        assert rows[0]["version"] == 0

    def test_taxonomy_seeded(self, db):
        conn, _ = db
        rows = conn.execute("SELECT * FROM taxonomy").fetchall()
        assert len(rows) == 15
        cats = {r["category"] for r in rows}
        assert "PATCHING" in cats
        assert "UNCATEGORIZED" in cats

    def test_indexes_exist(self, db):
        conn, _ = db
        indexes = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()}
        assert "idx_finding_assessment" in indexes
        assert "idx_finding_status" in indexes
        assert "idx_assessment_target" in indexes


class TestTargetIdentifierMigration:
    @staticmethod
    def _v2_connection():
        """Create a database that represents the schema before migration 3."""
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        for version, sql in enumerate(MIGRATIONS[:2]):
            conn.executescript(sql)
            conn.execute(
                "INSERT INTO schema_migrations(version, applied_at, description) "
                "VALUES (?, '2026-10-05T00:00:00+00:00', ?)",
                (version, f"migration_{version}"),
            )
        conn.commit()
        return conn

    def test_unique_legacy_alias_is_backfilled(self):
        conn = self._v2_connection()
        try:
            conn.execute("""
                INSERT INTO target (
                    target_id, target_alias, target_type, environment,
                    authorization_status, created_at
                ) VALUES ('legacy-target', 'legacy-lab', 'lab_vm', 'lab', 'LAB', 'now')
            """)
            conn.commit()
            assert migrate(conn) == 3
            row = conn.execute(
                "SELECT target_id FROM target_identifier WHERE identifier = ?",
                ("legacy-lab",),
            ).fetchone()
            assert row["target_id"] == "legacy-target"
        finally:
            conn.close()

    def test_ambiguous_legacy_alias_is_not_backfilled(self):
        conn = self._v2_connection()
        try:
            for target_id in ("legacy-a", "legacy-b"):
                conn.execute("""
                    INSERT INTO target (
                        target_id, target_alias, target_type, environment,
                        authorization_status, created_at
                    ) VALUES (?, 'shared-legacy-alias', 'lab_vm', 'lab', 'LAB', 'now')
                """, (target_id,))
            conn.commit()
            assert migrate(conn) == 3
            assert conn.execute(
                "SELECT 1 FROM target_identifier WHERE identifier = ?",
                ("shared-legacy-alias",),
            ).fetchone() is None
        finally:
            conn.close()


# ── Target ────────────────────────────────────────────────────────────────────

class TestTarget:
    def test_create_target_returns_uuid(self, db):
        conn, _ = db
        tid = create_target(conn, "lab-01", "lab_vm", "lab", "LAB")
        assert len(tid) == 36
        assert tid.count("-") == 4

    def test_get_target(self, db, target_id):
        conn, _ = db
        t = get_target(conn, target_id)
        assert t is not None
        assert t["target_alias"] == "test-target-01"
        assert t["authorization_status"] == "LAB"

    def test_list_targets(self, db):
        conn, _ = db
        create_target(conn, "t1", "lab_vm", "lab", "LAB")
        create_target(conn, "t2", "server", "owned", "OWNED")
        targets = list_targets(conn)
        assert len(targets) >= 2

    def test_primary_alias_is_registered_as_an_identifier(self, db, target_id):
        conn, _ = db
        identifiers = list_target_identifiers(conn, target_id)
        assert [row["identifier"] for row in identifiers] == ["test-target-01"]

    def test_add_explicit_target_identifier(self, db, target_id):
        conn, _ = db
        add_target_identifier(conn, target_id, "https://lab.example.test/app")
        identifiers = list_target_identifiers(conn, target_id)
        assert {row["identifier"] for row in identifiers} == {
            "test-target-01", "https://lab.example.test/app"
        }

    def test_duplicate_primary_identifier_is_rejected_before_target_creation(self, db):
        conn, _ = db
        create_target(conn, "unique-lab", "lab_vm", "lab", "LAB")
        with pytest.raises(ValueError, match="already bound"):
            create_target(conn, "unique-lab", "server", "owned", "OWNED")
        assert len(list_targets(conn)) == 1

    def test_invalid_authorization_status_rejected(self, db):
        conn, _ = db
        with pytest.raises(AssertionError):
            create_target(conn, "bad", "lab_vm", "lab", "INVALID_STATUS")

    def test_all_valid_auth_statuses_accepted(self, db):
        conn, _ = db
        for status in AUTH_STATUSES:
            tid = create_target(conn, f"t-{status}", "lab_vm", "lab", status)
            assert get_target(conn, tid)["authorization_status"] == status


# ── Assessment ────────────────────────────────────────────────────────────────

class TestAssessment:
    def test_create_assessment_returns_uuid(self, db, target_id):
        conn, _ = db
        aid = create_assessment(conn, target_id, "ALL", "LAB")
        assert len(aid) == 36

    def test_get_assessment(self, db, assessment_id):
        conn, _ = db
        a = get_assessment(conn, assessment_id)
        assert a is not None
        assert a["scope"] == "ALL"
        assert a["tool_version"] == "1.0.0"
        assert a["schema_version"] == SCHEMA_VERSION

    def test_invalid_target_id_rejected(self, db):
        conn, _ = db
        with pytest.raises(sqlite3.IntegrityError):
            create_assessment(conn, "nonexistent-uuid", "ALL", "LAB")

    def test_assessment_authorization_must_match_target(self, db, target_id):
        conn, _ = db
        with pytest.raises(ValueError, match="exactly match"):
            create_assessment(conn, target_id, "ALL", "OWNED")
        assert list_assessments(conn, target_id) == []

    def test_close_assessment_sets_end_time(self, db, assessment_id):
        conn, _ = db
        close_assessment(conn, assessment_id)
        a = get_assessment(conn, assessment_id)
        assert a["end_time"] is not None


# ── Finding — All Statuses ────────────────────────────────────────────────────

class TestFindingStatuses:
    def _make(self, conn, assessment_id, status, severity=None, check_id=None):
        return create_finding(
            conn, assessment_id=assessment_id,
            layer="OS", check_id=check_id or f"check_{status}",
            status=status, description=f"Test finding: {status}",
            severity=severity
        )

    def test_pass_finding(self, db, assessment_id):
        conn, _ = db
        fid = self._make(conn, assessment_id, "PASS", severity=None, check_id="c_pass")
        f = get_findings(conn, assessment_id)
        statuses = [r["status"] for r in f]
        assert "PASS" in statuses

    def test_fail_finding(self, db, assessment_id):
        conn, _ = db
        self._make(conn, assessment_id, "FAIL", severity="high")
        findings = get_findings_by_status(conn, assessment_id, "FAIL")
        assert len(findings) == 1
        assert findings[0]["severity"] == "high"

    def test_not_applicable_finding(self, db, assessment_id):
        conn, _ = db
        fid = self._make(conn, assessment_id, "NOT_APPLICABLE")
        findings = get_findings_by_status(conn, assessment_id, "NOT_APPLICABLE")
        assert len(findings) == 1
        assert findings[0]["status"] == "NOT_APPLICABLE"
        assert findings[0]["severity"] is None

    def test_not_tested_finding(self, db, assessment_id):
        conn, _ = db
        self._make(conn, assessment_id, "NOT_TESTED")
        findings = get_findings_by_status(conn, assessment_id, "NOT_TESTED")
        assert len(findings) == 1

    def test_error_finding(self, db, assessment_id):
        conn, _ = db
        self._make(conn, assessment_id, "ERROR")
        findings = get_findings_by_status(conn, assessment_id, "ERROR")
        assert len(findings) == 1

    def test_unknown_finding(self, db, assessment_id):
        conn, _ = db
        self._make(conn, assessment_id, "UNKNOWN")
        findings = get_findings_by_status(conn, assessment_id, "UNKNOWN")
        assert len(findings) == 1

    def test_all_six_statuses_distinct(self, db, assessment_id):
        conn, _ = db
        severities = {
            "PASS": None, "FAIL": "medium",
            "NOT_APPLICABLE": None, "NOT_TESTED": None,
            "ERROR": None, "UNKNOWN": None
        }
        for status, sev in severities.items():
            self._make(conn, assessment_id, status, sev, f"chk_{status}")
        all_findings = get_findings(conn, assessment_id)
        found_statuses = {f["status"] for f in all_findings}
        assert found_statuses == set(FINDING_STATUSES)


# ── NOT_APPLICABLE Semantics ──────────────────────────────────────────────────

class TestNotApplicableSemantics:
    def test_not_applicable_persists_correctly(self, db, assessment_id):
        conn, _ = db
        fid = create_finding(
            conn, assessment_id, "OS", "windows_specific_check",
            "NOT_APPLICABLE", "Check not applicable on this OS"
        )
        findings = get_findings_by_status(conn, assessment_id, "NOT_APPLICABLE")
        assert any(f["finding_id"] == fid for f in findings)

    def test_not_applicable_severity_must_be_none(self, db, assessment_id):
        conn, _ = db
        with pytest.raises(ValueError):
            create_finding(
                conn, assessment_id, "OS", "bad_check",
                "NOT_APPLICABLE", "Should not have severity",
                severity="high"
            )

    def test_not_tested_severity_must_be_none(self, db, assessment_id):
        conn, _ = db
        with pytest.raises(ValueError):
            create_finding(
                conn, assessment_id, "OS", "nt_check",
                "NOT_TESTED", "Not tested",
                severity="medium"
            )

    @pytest.mark.parametrize("status", ("ERROR", "UNKNOWN"))
    def test_unevaluated_status_severity_must_be_none(self, db, assessment_id, status):
        conn, _ = db
        with pytest.raises(ValueError):
            create_finding(
                conn, assessment_id, "OS", f"{status}_check",
                status, "Unevaluated check", severity="medium"
            )

    def test_not_applicable_excluded_from_prevalence(self, db, assessment_id):
        conn, _ = db
        create_finding(conn, assessment_id, "OS", "ssh_root",
                       "FAIL", "SSH root login enabled", severity="high")
        create_finding(conn, assessment_id, "OS", "ssh_root",
                       "NOT_APPLICABLE", "Not applicable on this target")
        rows = get_finding_prevalence(conn, check_id="ssh_root")
        assert len(rows) == 1
        assert rows[0]["total_applicable"] == 1  # NOT_APPLICABLE not counted
        assert rows[0]["fail_count"] == 1


# ── Foreign Key Integrity ─────────────────────────────────────────────────────

class TestForeignKeyIntegrity:
    def test_finding_requires_valid_assessment(self, db):
        conn, _ = db
        with pytest.raises(sqlite3.IntegrityError):
            create_finding(conn, "bad-assessment-id", "OS",
                           "check1", "PASS", "desc")

    def test_remediation_requires_valid_finding(self, db, assessment_id):
        conn, _ = db
        with pytest.raises(sqlite3.IntegrityError):
            create_remediation(conn, "bad-finding-id", "Fix it")

    def test_score_snapshot_requires_valid_assessment(self, db):
        conn, _ = db
        with pytest.raises(sqlite3.IntegrityError):
            create_score_snapshot(
                conn, "bad-assessment-id",
                {"composite_score": 50, "layers": {}, "weakest_layer": None}
            )

    def test_assessment_requires_valid_target(self, db):
        conn, _ = db
        with pytest.raises(sqlite3.IntegrityError):
            create_assessment(conn, "bad-target-id", "ALL", "LAB")


# ── Score Snapshot ────────────────────────────────────────────────────────────

class TestScoreSnapshot:
    def test_create_score_snapshot(self, db, assessment_id):
        conn, _ = db
        composite = {
            "composite_score": 32,
            "weakest_layer": "network",
            "layers": {
                "os_hardening": {"score": 50},
                "network": {"score": 0},
                "webapp": {"score": 50},
            }
        }
        sid = create_score_snapshot(conn, assessment_id, composite)
        snaps = get_score_snapshots(conn, assessment_id)
        assert len(snaps) == 1
        assert snaps[0]["composite_score"] == 32
        assert snaps[0]["os_score"] == 50
        assert snaps[0]["network_score"] == 0
        assert snaps[0]["web_score"] == 50
        assert snaps[0]["weakest_layer"] == "network"
        assert snaps[0]["scoring_model_id"] == "weighted_composite_v1"
        assert snaps[0]["snapshot_sequence"] == 1

    def test_multiple_snapshots_different_models(self, db, assessment_id):
        conn, _ = db
        composite = {"composite_score": 40, "weakest_layer": "network",
                     "layers": {"os_hardening": {"score": 60},
                                "network": {"score": 10}, "webapp": {"score": 60}}}
        create_score_snapshot(conn, assessment_id, composite,
                              scoring_model_id="weighted_composite_v1")
        create_score_snapshot(conn, assessment_id, composite,
                              scoring_model_id="equal_weight_v1",
                              weight_os=0.33, weight_network=0.33, weight_web=0.34)
        snaps = get_score_snapshots(conn, assessment_id)
        assert len(snaps) == 2
        models = {s["scoring_model_id"] for s in snaps}
        assert "weighted_composite_v1" in models
        assert "equal_weight_v1" in models
        assert [s["snapshot_sequence"] for s in snaps] == [1, 2]


# ── Remediation Longitudinal ──────────────────────────────────────────────────

class TestRemediation:
    def test_create_remediation(self, db, assessment_id):
        conn, _ = db
        fid = create_finding(conn, assessment_id, "OS", "ssh_root",
                             "FAIL", "Root login enabled", severity="high",
                             recommendation="Set PermitRootLogin no")
        rid = create_remediation(conn, fid, "Set PermitRootLogin no in sshd_config")
        rems = get_remediations(conn, fid)
        assert len(rems) == 1
        assert rems[0]["status"] == "PENDING"

    def test_update_remediation_to_verified_fixed(self, db, assessment_id):
        conn, _ = db
        fid = create_finding(conn, assessment_id, "OS", "firewall",
                             "FAIL", "No firewall", severity="high")
        rid = create_remediation(conn, fid, "Enable ufw")
        update_remediation_status(conn, rid, "VERIFIED_FIXED",
                                  remediation_date="2026-09-18T12:00:00Z",
                                  effort_hours=0.25,
                                  verification_result="VERIFIED_FIXED")
        rems = get_remediations(conn, fid)
        assert rems[0]["status"] == "VERIFIED_FIXED"
        assert rems[0]["effort_hours"] == 0.25
        assert rems[0]["verification_result"] == "VERIFIED_FIXED"

    def test_all_remediation_statuses_valid(self, db, assessment_id):
        conn, _ = db
        from db.schema import REMEDIATION_STATUSES
        for i, status in enumerate(REMEDIATION_STATUSES):
            fid = create_finding(conn, assessment_id, "WEB",
                                 f"check_{i}", "FAIL", "desc", severity="low")
            rid = create_remediation(conn, fid, "fix")
            update_remediation_status(conn, rid, status)
            rems = get_remediations(conn, fid)
            assert rems[0]["status"] == status

    def test_invalid_remediation_status_rejected(self, db, assessment_id):
        conn, _ = db
        fid = create_finding(conn, assessment_id, "WEB", "check_x",
                             "FAIL", "desc", severity="low")
        rid = create_remediation(conn, fid, "fix")
        with pytest.raises(AssertionError):
            update_remediation_status(conn, rid, "NOT_A_STATUS")


# ── Prevalence Query ──────────────────────────────────────────────────────────

class TestPrevalenceQuery:
    def test_prevalence_counts_correctly(self, db):
        conn, _ = db
        # 3 targets, 3 assessments, same check
        for i in range(3):
            tid = create_target(conn, f"target-{i}", "lab_vm", "lab", "LAB")
            aid = create_assessment(conn, tid, "OS", "LAB")
            status = "FAIL" if i < 2 else "PASS"
            sev = "high" if status == "FAIL" else None
            create_finding(conn, aid, "OS", "ssh_root", status,
                          "SSH root", severity=sev)
        rows = get_finding_prevalence(conn, check_id="ssh_root")
        assert len(rows) == 1
        assert rows[0]["total_applicable"] == 3
        assert rows[0]["fail_count"] == 2
        assert rows[0]["pass_count"] == 1
        assert rows[0]["fail_pct"] == pytest.approx(66.7, abs=0.1)


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import traceback
    tests = [
        TestSchemaCreation, TestTarget, TestAssessment,
        TestFindingStatuses, TestNotApplicableSemantics,
        TestForeignKeyIntegrity, TestScoreSnapshot,
        TestRemediation, TestPrevalenceQuery
    ]
    passed = failed = 0
    for cls in tests:
        instance = cls()
        for name in [m for m in dir(cls) if m.startswith("test_")]:
            conn, version = initialize(":memory:")
            seed_taxonomy(conn)
            db_fixture = (conn, version)
            try:
                tid = create_target(conn, "test-target-01", "lab_vm",
                                    "lab", "LAB", os_family="linux",
                                    os_name="Ubuntu 8.04", deployment_type="vm")
                aid = create_assessment(conn, tid, "ALL", "LAB")
                getattr(instance, name)(db_fixture, aid) if "assessment_id" in getattr(cls, name).__code__.co_varnames else (
                    getattr(instance, name)(db_fixture, tid) if "target_id" in getattr(cls, name).__code__.co_varnames else
                    getattr(instance, name)(db_fixture)
                )
                print(f"  PASS  {cls.__name__}.{name}")
                passed += 1
            except Exception as e:
                print(f"  FAIL  {cls.__name__}.{name}: {e}")
                failed += 1
            finally:
                conn.close()
    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed")
    if failed:
        sys.exit(1)
