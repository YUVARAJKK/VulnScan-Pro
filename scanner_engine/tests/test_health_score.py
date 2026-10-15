"""Tests for health score computation."""

from analysis.health_score import compute_health_score


def test_perfect_score():
    score, grade = compute_health_score(0)
    assert score == 100
    assert grade == 'A+'


def test_zero_score():
    score, grade = compute_health_score(100)
    assert score == 0
    assert grade == 'F'


def test_grade_a():
    score, grade = compute_health_score(15)
    assert score == 85
    assert grade == 'A'


def test_grade_b():
    score, grade = compute_health_score(25)
    assert score == 75
    assert grade == 'B'


def test_grade_c():
    score, grade = compute_health_score(35)
    assert score == 65
    assert grade == 'C'


def test_grade_d():
    score, grade = compute_health_score(55)
    assert score == 45
    assert grade == 'D'
