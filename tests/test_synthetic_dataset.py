"""Tests for deterministic non-empirical fixture generation."""
import json

import pytest

from analysis.longitudinal import run_longitudinal_analysis
from analysis.prevalence import run_full_analysis
from db.schema import get_connection
from tools.generate_synthetic_dataset import SYNTHETIC_LABEL, generate


def test_generator_creates_labelled_database_and_manifest(tmp_path):
    output = tmp_path / "synthetic.db"
    database, manifest = generate(output)
    assert database == output.resolve()
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["label"] == SYNTHETIC_LABEL
    assert data["target_count"] == 2
    conn = get_connection(database)
    try:
        assert conn.execute("SELECT COUNT(*) FROM target").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM assessment").fetchone()[0] == 3
        assert all(SYNTHETIC_LABEL in row[0] for row in conn.execute("SELECT notes FROM target"))
        assert run_full_analysis(conn)["assessment_distribution"]["total_assessments"] == 3
        longitudinal = run_longitudinal_analysis(conn)
        assert longitudinal["comparison_count"] == 1
        compared_target = next(target for target in longitudinal["targets"]
                               if target["comparison_count"] == 1)
        comparison = compared_target["comparisons"][0]
        assert comparison["counts"]["resolved"] == 1
        assert comparison["counts"]["not_comparable"] == 1
    finally:
        conn.close()


def test_generator_never_overwrites_existing_output(tmp_path):
    output = tmp_path / "synthetic.db"
    generate(output)
    with pytest.raises(FileExistsError):
        generate(output)
