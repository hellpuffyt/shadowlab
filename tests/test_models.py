from shadowlab.models import FieldScore, Finding, ScoreResult, Severity


def test_severity_rank_ordering():
    ranks = [s.rank for s in (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
    assert ranks == sorted(ranks)
    assert Severity.CRITICAL.rank > Severity.INFO.rank


def test_field_score_ratio():
    fs = FieldScore(field="x", points_earned=5.0, points_possible=10.0, detail="")
    assert fs.ratio == 0.5


def test_field_score_ratio_zero_possible():
    fs = FieldScore(field="x", points_earned=0.0, points_possible=0.0, detail="")
    assert fs.ratio == 1.0


def test_score_result_percent():
    result = ScoreResult(
        scenario_id="s",
        points_earned=75.0,
        points_possible=100.0,
        field_scores=(),
        passed=True,
    )
    assert result.percent == 75.0


def test_score_result_percent_zero_possible():
    result = ScoreResult(
        scenario_id="s", points_earned=0.0, points_possible=0.0, field_scores=(), passed=False
    )
    assert result.percent == 0.0


def test_finding_defaults():
    f = Finding(rule_id="r1", severity=Severity.HIGH, message="msg")
    assert f.line is None
    assert f.evidence == ""
