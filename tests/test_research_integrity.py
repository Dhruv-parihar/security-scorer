"""Synthetic counterexamples for research semantics; no network or host scans."""
from types import SimpleNamespace
from unittest.mock import patch
from itertools import count
import pytest
from db.schema import initialize
from db.repository import create_target, create_assessment, create_finding, create_score_snapshot
from modules.scoring import compute_composite, _is_failed_finding
from modules import os_hardening, network_scan, webapp_scan
from analysis.prevalence import finding_prevalence, layer_prevalence, finding_cooccurrence, assessment_distribution
from analysis.scoring_sensitivity import load_assessment_layer_scores, run_full_analysis


@pytest.fixture
def conn():
    db, _ = initialize(':memory:')
    yield db
    db.close()


_target_sequence = count()


def assessment(conn, alias='synthetic'):
    target = create_target(
        conn, f"{alias}-{next(_target_sequence)}", 'lab_vm', 'lab', 'LAB'
    )
    return create_assessment(conn, target, 'ALL', 'LAB')


def finding(conn, aid, check='same', layer='OS', status='FAIL'):
    return create_finding(conn, aid, layer, check, status, 'Synthetic test observation',
                          severity='high' if status in ('PASS', 'FAIL') else None)


def snapshot(conn, aid, score, **kwargs):
    return create_score_snapshot(conn, aid, {'composite_score': score,
        'layers': {'os_hardening': {'score': score}}}, **kwargs)


def test_windows_has_no_evaluated_os_score():
    with patch.object(os_hardening, '_detect_os', return_value='windows'):
        result = os_hardening.run()
    assert result['score'] is None
    assert result['applicable_checks'] == 0


def test_unevaluated_layer_does_not_lower_composite():
    result = compute_composite({'os_hardening': {'score': 0, 'applicable_checks': 0},
                                'webapp': {'score': 80}})
    assert result['composite_score'] == 80
    assert 'os_hardening' not in result['layers']


def test_error_layer_does_not_lower_composite():
    assert compute_composite({'network': {'score': 0, 'error': 'timeout'},
                              'webapp': {'score': 80}})['composite_score'] == 80


@pytest.mark.parametrize('status', ['NOT_APPLICABLE', 'NOT_TESTED', 'ERROR', 'UNKNOWN', 'PASS'])
def test_explicit_nonfailure_overrides_legacy_boolean(status):
    assert not _is_failed_finding({'status': status, 'passed': False, 'severity': 'high'})


def test_explicit_failure_without_legacy_boolean_is_kept():
    assert _is_failed_finding({'status': 'FAIL', 'severity': None})


def test_zero_weights_mean_no_composite():
    assert compute_composite({'webapp': {'score': 80}}, {'webapp': 0})['composite_score'] is None


@pytest.mark.parametrize('bad_weight', [-1, float('nan'), float('inf')])
def test_invalid_weights_rejected(bad_weight):
    with pytest.raises(ValueError):
        compute_composite({'webapp': {'score': 80}}, {'webapp': bad_weight})


def test_layer_denominator_ignores_duplicate_evidence(conn):
    aid = assessment(conn)
    finding(conn, aid)
    finding(conn, aid)
    finding(conn, aid, check='other', status='PASS')
    result = layer_prevalence(conn)[0]
    assert result['total_check_evaluations'] == 2
    assert result['overall_fail_pct'] == 50


def test_conflicting_evaluated_statuses_raise(conn):
    aid = assessment(conn)
    finding(conn, aid)
    finding(conn, aid, status='PASS')
    with pytest.raises(ValueError, match='Conflicting'):
        finding_prevalence(conn)


def test_cooccurrence_keeps_layer_in_identity(conn):
    aid = assessment(conn)
    finding(conn, aid, layer='OS')
    finding(conn, aid, layer='WEB')
    result = finding_cooccurrence(conn)
    assert len(result) == 1
    assert result[0]['cross_layer'] is True


def test_cooccurrence_layer_filter_is_parameterized(conn):
    aid = assessment(conn)
    finding(conn, aid, check='a')
    finding(conn, aid, check='b')
    assert finding_cooccurrence(conn, layer_filter="OS' OR 1=1 --") == []


def test_score_distribution_median_and_decimal_buckets(conn):
    for score in [20.5, 80.5]:
        snapshot(conn, assessment(conn), score)
    dist = assessment_distribution(conn)['composite_score_distribution']
    assert dist['median'] == 50.5
    assert sum(dist['buckets'].values()) == 2


def test_snapshot_recalculation_does_not_multiply_assessments(conn):
    aid = assessment(conn)
    snapshot(conn, aid, 20)
    snapshot(conn, aid, 30)
    assert len(load_assessment_layer_scores(conn)) == 1
    assert assessment_distribution(conn)['composite_score_distribution']['n'] == 1


def test_sensitivity_counts_all_pairs(conn):
    for score in [10, 20, 30, 40, 50, 60]:
        snapshot(conn, assessment(conn), score)
    result = run_full_analysis(conn, include_sweep=False)
    assert result['summary']['ordering_analysis']['pairs_analyzed'] == 15


def test_failed_nmap_process_is_not_perfect_security():
    with patch.object(network_scan.subprocess, 'run', return_value=SimpleNamespace(
            returncode=1, stdout='', stderr='invalid target')):
        result = network_scan.run('synthetic.invalid')
    assert result['score'] is None
    assert result['error']


def test_nmap_service_without_version_is_counted():
    with patch.object(network_scan.subprocess, 'run', return_value=SimpleNamespace(
            returncode=0, stdout='443/tcp open https\n', stderr='')):
        result = network_scan.run('synthetic.invalid')
    assert result['open_ports'] == 1


@pytest.mark.parametrize('check', [webapp_scan._check_sqli, webapp_scan._check_xss])
def test_web_checks_without_parameters_are_explicitly_not_tested(check):
    result = check('https://synthetic.invalid/', SimpleNamespace())
    assert result['status'] == 'NOT_TESTED'
    assert result['severity'] is None


@pytest.mark.parametrize('check', [webapp_scan._check_sqli, webapp_scan._check_xss])
def test_web_check_transport_error_preserves_error_status(check):
    session = SimpleNamespace(get=lambda *a, **k: (_ for _ in ()).throw(webapp_scan.requests.Timeout()))
    result = check('https://synthetic.invalid/?id=1', session)
    assert result['status'] == 'ERROR'
    assert result['passed'] is None
