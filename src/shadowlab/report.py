"""HTML report-card export for one or more graded attempts."""

from __future__ import annotations

import html
from datetime import datetime, timezone

from shadowlab.models import Scenario, ScoreResult

_CSS = """
:root {
  color-scheme: light dark;
  --bg: #0b0f14; --panel: #131a22; --border: #23303c; --text: #e6edf3;
  --muted: #8b98a5; --accent: #58e6b3; --warn: #f2c94c; --bad: #f2555a;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2.5rem 1.5rem 4rem; background: var(--bg); color: var(--text);
  font: 15px/1.5 -apple-system, "Segoe UI", Roboto, sans-serif;
}
.wrap { max-width: 920px; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 0 0 0.25rem; letter-spacing: -0.02em; }
.subtitle { color: var(--muted); margin: 0 0 2rem; font-size: 0.95rem; }
.summary { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2.5rem; }
.stat {
  background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
  padding: 1rem 1.25rem; min-width: 140px; flex: 1;
}
.stat .n { font-size: 1.8rem; font-weight: 700; }
.stat .l { color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; }
.card {
  background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
  padding: 1.25rem 1.5rem; margin-bottom: 1.25rem;
}
.card-head { display: flex; justify-content: space-between; align-items: baseline; gap: 1rem; flex-wrap: wrap; }
.card-head h2 { font-size: 1.05rem; margin: 0; }
.pct { font-size: 1.3rem; font-weight: 700; }
.pct.pass { color: var(--accent); }
.pct.fail { color: var(--bad); }
.badge {
  display: inline-block; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em;
  padding: 0.15rem 0.5rem; border-radius: 999px; border: 1px solid var(--border); color: var(--muted);
}
table { width: 100%; border-collapse: collapse; margin-top: 0.9rem; font-size: 0.88rem; }
th, td { text-align: left; padding: 0.4rem 0.5rem; border-bottom: 1px solid var(--border); vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: 0.75rem; text-transform: uppercase; }
td.pts { white-space: nowrap; font-variant-numeric: tabular-nums; }
.bar-track { background: #1c2733; border-radius: 6px; height: 6px; overflow: hidden; margin-top: 1rem; }
.bar-fill { height: 100%; background: var(--accent); }
.bar-fill.warn { background: var(--warn); }
.bar-fill.bad { background: var(--bad); }
footer { color: var(--muted); font-size: 0.78rem; margin-top: 2.5rem; text-align: center; }
"""


def _esc(value: object) -> str:
    return html.escape(str(value))


def _bar_class(ratio: float) -> str:
    if ratio >= 0.85:
        return ""
    if ratio >= 0.6:
        return "warn"
    return "bad"


def build_report_html(results: list[tuple[Scenario, ScoreResult]], *, title: str = "shadowlab report card") -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_earned = sum(r.points_earned for _, r in results)
    total_possible = sum(r.points_possible for _, r in results)
    overall_pct = round(100 * total_earned / total_possible, 1) if total_possible else 0.0
    passed_count = sum(1 for _, r in results if r.passed)

    cards = []
    for scenario, result in results:
        pct = result.percent
        pass_class = "pass" if result.passed else "fail"
        rows = []
        for fs in result.field_scores:
            rows.append(
                f"<tr><td>{_esc(fs.field)}</td>"
                f"<td class='pts'>{fs.points_earned:g} / {fs.points_possible:g}</td>"
                f"<td>{_esc(fs.detail)}</td></tr>"
            )
        bar_class = _bar_class(pct / 100)
        cards.append(
            f"""<section class="card">
  <div class="card-head">
    <h2>{_esc(scenario.title)} <span class="badge">{_esc(scenario.category.value)}</span></h2>
    <span class="pct {pass_class}">{pct:g}%</span>
  </div>
  <div class="bar-track"><div class="bar-fill {bar_class}" style="width:{max(0, min(100, pct))}%"></div></div>
  <table>
    <thead><tr><th>Rubric item</th><th>Points</th><th>Explanation</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</section>"""
        )

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(title)}</title>
<style>{_CSS}</style>
</head><body><div class="wrap">
  <h1>{_esc(title)}</h1>
  <p class="subtitle">Generated {now} &middot; all fixtures synthetic, all scoring local</p>
  <div class="summary">
    <div class="stat"><div class="n">{overall_pct:g}%</div><div class="l">Overall score</div></div>
    <div class="stat"><div class="n">{passed_count}/{len(results)}</div><div class="l">Scenarios passed</div></div>
    <div class="stat"><div class="n">{total_earned:g}/{total_possible:g}</div><div class="l">Points</div></div>
  </div>
  {''.join(cards)}
  <footer>shadowlab &middot; a local, defensive-only security exercise runner</footer>
</div></body></html>
"""
