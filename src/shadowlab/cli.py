"""shadowlab's terminal experience: list, show, submit, and report commands."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.markup import escape
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from shadowlab import engine
from shadowlab.engine import InvalidSubmissionError, UnknownScenarioError
from shadowlab.models import Category, FieldScore, Scenario, ScoreResult
from shadowlab.report import build_report_html

_DEFAULT_HISTORY = Path("shadowlab_history.json")

_SEVERITY_COLOR = {
    "info": "grey62",
    "low": "cyan",
    "medium": "yellow",
    "high": "orange3",
    "critical": "bold red",
}


def _console(no_color: bool = False) -> Console:
    return Console(no_color=no_color, highlight=False)


def _cmd_list(args: argparse.Namespace) -> int:
    console = _console(args.no_color)
    category = Category(args.category) if args.category else None
    scenarios = engine.list_scenarios(category)
    table = Table(title="shadowlab scenarios", show_lines=False)
    table.add_column("id", style="bold")
    table.add_column("category")
    table.add_column("difficulty")
    table.add_column("title")
    table.add_column("points", justify="right")
    for s in sorted(scenarios, key=lambda s: (s.category.value, s.id)):
        table.add_row(s.id, s.category.value, s.difficulty, s.title, f"{s.max_points:g}")
    console.print(table)
    return 0


def _cmd_show(args: argparse.Namespace) -> int:
    console = _console(args.no_color)
    try:
        bundle = engine.load_scenario(args.scenario_id)
        sdef = engine.scenario_def_for(args.scenario_id)
    except UnknownScenarioError as exc:
        console.print(f"[bold red]error:[/bold red] {escape(str(exc))}")
        return 1

    s = bundle.scenario
    console.print(Panel(Markdown(s.prompt), title=f"{s.id} -- {s.title}", subtitle=s.category.value))

    for fname, text in bundle.data.items():
        lexer = "markdown" if fname.endswith(".md") else "text"
        console.print(Panel(Syntax(text, lexer, line_numbers=True, word_wrap=True), title=fname))

    if sdef.kind == "log_fields":
        table = Table(title="Expected submission fields")
        table.add_column("field")
        table.add_column("description")
        for name, desc in s.submission_schema.items():
            table.add_row(name, desc)
        console.print(table)
    elif sdef.kind == "checklist":
        table = Table(title="Finding-id catalog (submit as {\"selected_ids\": [...]})")
        table.add_column("id")
        table.add_column("description")
        assert sdef.checklist_catalog is not None
        # Alphabetical, so the display order does not reveal which ids are real.
        for rid in sorted(sdef.checklist_catalog.all_ids):
            table.add_row(rid, sdef.checklist_catalog.descriptions.get(rid, ""))
        console.print(table)
    elif sdef.kind == "ir_sequence":
        table = Table(title="Action catalog (submit as {\"ordered_ids\": [...]})")
        table.add_column("id")
        table.add_column("action")
        assert sdef.action_catalog is not None
        # Neither the IR phase (which labelled every distractor "harmful") nor
        # the catalog order (which is the ideal order) is shown: both are the
        # answer key. Entries are listed alphabetically by id.
        for entry in sorted(sdef.action_catalog.entries, key=lambda e: e.id):
            table.add_row(entry.id, entry.text)
        console.print(table)
    return 0


def _print_score(console: Console, scenario_id: str, title: str, result: ScoreResult) -> None:
    color = "green" if result.passed else "red"
    console.print(
        f"\n[bold]{scenario_id}[/bold] -- {title}: "
        f"[{color}]{result.percent:g}%[/{color}] "
        f"({result.points_earned:g}/{result.points_possible:g} pts) "
        f"{'PASS' if result.passed else 'FAIL'}"
    )
    table = Table(show_header=True, header_style="bold")
    table.add_column("rubric item")
    table.add_column("points", justify="right")
    table.add_column("explanation")
    for fs in result.field_scores:
        pts = f"{fs.points_earned:g}/{fs.points_possible:g}"
        style = "green" if fs.ratio >= 0.85 else ("yellow" if fs.ratio >= 0.4 else "red")
        # `detail` echoes learner-submitted values; escape so they are shown
        # verbatim instead of being parsed as Rich markup (an answer such as
        # "[/x]" used to crash the CLI with MarkupError).
        table.add_row(escape(fs.field), f"[{style}]{pts}[/{style}]", escape(fs.detail))
    console.print(table)


class HistoryError(Exception):
    """The history file exists but cannot be used; it is left untouched."""


def _load_history(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        # Never treat an unreadable history as empty: the next save would
        # silently overwrite every previously recorded attempt.
        raise HistoryError(f"cannot read history file {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise HistoryError(f"history file {path} is not a JSON object")
    return loaded


def _save_history(path: Path, history: dict[str, dict[str, Any]]) -> None:
    """Write atomically (temp file + rename) so an interrupted write cannot
    truncate the existing history."""
    payload = json.dumps(history, indent=2, sort_keys=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.resolve().parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _cmd_submit(args: argparse.Namespace) -> int:
    console = _console(args.no_color)
    try:
        submission = json.loads(Path(args.answers).read_text(encoding="utf-8"))
    except OSError as exc:
        console.print(f"[bold red]error:[/bold red] could not read {escape(str(args.answers))}: {escape(str(exc))}")
        return 1
    except json.JSONDecodeError as exc:
        console.print(f"[bold red]error:[/bold red] {escape(str(args.answers))} is not valid JSON: {escape(str(exc))}")
        return 1

    try:
        result = engine.grade(args.scenario_id, submission)
        scenario = engine.load_scenario(args.scenario_id).scenario
    except UnknownScenarioError as exc:
        console.print(f"[bold red]error:[/bold red] {escape(str(exc))}")
        return 1
    except InvalidSubmissionError as exc:
        console.print(f"[bold red]invalid submission:[/bold red] {escape(str(exc))}")
        return 1

    _print_score(console, args.scenario_id, scenario.title, result)

    if not args.no_record:
        history_path = Path(args.history)
        try:
            history = _load_history(history_path)
        except HistoryError as exc:
            console.print(f"[bold red]error:[/bold red] {escape(str(exc))}; attempt not recorded (use --no-record)")
            return 1
        history[args.scenario_id] = {
            "points_earned": result.points_earned,
            "points_possible": result.points_possible,
            "percent": result.percent,
            "passed": result.passed,
            "field_scores": [
                {
                    "field": fs.field,
                    "points_earned": fs.points_earned,
                    "points_possible": fs.points_possible,
                    "detail": fs.detail,
                }
                for fs in result.field_scores
            ],
        }
        _save_history(history_path, history)
        console.print(f"[dim]recorded to {escape(str(history_path))}[/dim]")

    return 0 if result.passed else 2


def _result_from_record(scenario_id: str, record: Any) -> ScoreResult:
    """Rebuild a ScoreResult from a history record, validating types so a
    hand-edited or corrupted record is rejected instead of crashing (or being
    formatted into the HTML report unchecked)."""
    if not isinstance(record, dict):
        raise TypeError("record is not an object")

    def num(value: Any) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError("expected a number")
        return float(value)

    field_scores = tuple(
        FieldScore(
            field=str(f["field"]),
            points_earned=num(f["points_earned"]),
            points_possible=num(f["points_possible"]),
            detail=str(f["detail"]),
        )
        for f in record["field_scores"]
    )
    return ScoreResult(
        scenario_id=scenario_id,
        points_earned=num(record["points_earned"]),
        points_possible=num(record["points_possible"]),
        field_scores=field_scores,
        passed=bool(record["passed"]),
    )


def _cmd_report(args: argparse.Namespace) -> int:
    console = _console(args.no_color)
    history_path = Path(args.history)
    try:
        history = _load_history(history_path)
    except HistoryError as exc:
        console.print(f"[bold red]error:[/bold red] {escape(str(exc))}")
        return 1
    if not history:
        console.print(
            f"[yellow]no recorded attempts found in {escape(str(history_path))}; run `shadowlab submit` first.[/yellow]"
        )
        return 1

    pairs: list[tuple[Scenario, ScoreResult]] = []
    skipped: list[str] = []
    for scenario_id, record in history.items():
        try:
            scenario = engine.load_scenario(scenario_id).scenario
        except UnknownScenarioError:
            continue
        try:
            result = _result_from_record(scenario_id, record)
        except (KeyError, TypeError, ValueError):
            skipped.append(scenario_id)
            continue
        pairs.append((scenario, result))
    if skipped:
        console.print(f"[yellow]skipped malformed history record(s): {escape(', '.join(sorted(skipped)))}[/yellow]")
    if not pairs:
        console.print("[bold red]error:[/bold red] no usable recorded attempts")
        return 1

    pairs.sort(key=lambda p: (p[0].category.value, p[0].id))
    html_out = build_report_html(pairs)
    out_path = Path(args.out)
    out_path.write_text(html_out, encoding="utf-8")
    console.print(f"[green]wrote report card to {out_path}[/green] ({len(pairs)} scenario(s))")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="shadowlab", description=__doc__)
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="list bundled scenarios")
    p_list.add_argument("--category", choices=[c.value for c in Category], default=None)
    p_list.set_defaults(func=_cmd_list)

    p_show = sub.add_parser("show", help="show a scenario's prompt, fixture data, and submission schema")
    p_show.add_argument("scenario_id")
    p_show.set_defaults(func=_cmd_show)

    p_submit = sub.add_parser("submit", help="grade a JSON submission against a scenario")
    p_submit.add_argument("scenario_id")
    p_submit.add_argument("--answers", required=True, help="path to a JSON file with your answer")
    p_submit.add_argument("--history", default=str(_DEFAULT_HISTORY), help="local history file to record into")
    p_submit.add_argument("--no-record", action="store_true", help="don't record this attempt to history")
    p_submit.set_defaults(func=_cmd_submit)

    p_report = sub.add_parser("report", help="export an HTML report card from recorded attempts")
    p_report.add_argument("--history", default=str(_DEFAULT_HISTORY), help="local history file to read from")
    p_report.add_argument("--out", default="shadowlab_report.html", help="output HTML path")
    p_report.set_defaults(func=_cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
