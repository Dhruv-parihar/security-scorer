"""Shared, read-only analysis rules for observation identity and snapshots."""
import sqlite3
from pathlib import Path

LATEST_SNAPSHOTS = '''
SELECT * FROM (
    SELECT ss.*, ROW_NUMBER() OVER (
        PARTITION BY assessment_id ORDER BY calculated_at DESC, snapshot_sequence DESC
    ) AS snapshot_rank FROM score_snapshot ss
) WHERE snapshot_rank=1
'''


def validate_evaluations(conn):
    conflict = conn.execute('''SELECT assessment_id, layer, check_id FROM finding
        WHERE status IN ('PASS','FAIL') GROUP BY assessment_id, layer, check_id
        HAVING COUNT(DISTINCT status)>1 LIMIT 1''').fetchone()
    if conflict:
        raise ValueError('Conflicting PASS/FAIL records for the same assessment, layer and check')


EVALUATIONS = '''SELECT assessment_id, layer, check_id, MAX(status) AS status,
    MAX(CASE WHEN status='FAIL' THEN severity END) AS severity
    FROM finding WHERE status IN ('PASS','FAIL')
    GROUP BY assessment_id, layer, check_id'''


def open_readonly(path):
    conn = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA query_only=ON')
    return conn
