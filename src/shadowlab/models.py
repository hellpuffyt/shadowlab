"""Shared dataclasses used across scenario loading, analysis, and scoring."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Category(str, Enum):
    """The three exercise families shadowlab supports."""

    LOG_ANALYSIS = "log-analysis"
    CONFIG_AUDIT = "config-audit"
    INCIDENT_RESPONSE = "incident-response"


class Severity(str, Enum):
    """Severity of a single finding, ordered low to high."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self)


@dataclass(frozen=True, slots=True)
class Finding:
    """A single detected issue, produced by a real analyzer or submitted by a learner."""

    rule_id: str
    severity: Severity
    message: str
    line: int | None = None
    evidence: str = ""


@dataclass(frozen=True, slots=True)
class Scenario:
    """Metadata + bundled fixture paths for one exercise."""

    id: str
    category: Category
    title: str
    difficulty: str
    prompt: str
    data_files: tuple[str, ...]
    directory: str
    submission_schema: dict[str, str] = field(default_factory=dict)
    max_points: float = 100.0


@dataclass(frozen=True, slots=True)
class FieldScore:
    """Score contribution of a single submission field."""

    field: str
    points_earned: float
    points_possible: float
    detail: str

    @property
    def ratio(self) -> float:
        if self.points_possible == 0:
            return 1.0
        return self.points_earned / self.points_possible


@dataclass(frozen=True, slots=True)
class ScoreResult:
    """Full scored outcome for one submission against one scenario."""

    scenario_id: str
    points_earned: float
    points_possible: float
    field_scores: tuple[FieldScore, ...]
    passed: bool

    @property
    def percent(self) -> float:
        if self.points_possible == 0:
            return 0.0
        return round(100.0 * self.points_earned / self.points_possible, 2)
