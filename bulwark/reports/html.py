"""HTML report generator for Bulwark evaluation results.

Produces a self-contained HTML document with inline CSS -- no external
stylesheets or JavaScript dependencies required.
"""

from __future__ import annotations

from datetime import datetime
from html import escape

from bulwark.core.categories import ASI_CATEGORIES, ASICode
from bulwark.core.models import EvalReport, EvalRecord, Verdict


# --------------------------------------------------------------------------- #
# Verdict colour palette
# --------------------------------------------------------------------------- #

_VERDICT_COLORS: dict[Verdict, str] = {
    Verdict.PASS: "#22c55e",
    Verdict.FAIL: "#eab308",
    Verdict.VULNERABLE: "#ef4444",
    Verdict.UNCERTAIN: "#3b82f6",
    Verdict.ERROR: "#a855f7",
    Verdict.TIMEOUT: "#6b7280",
}

_VERDICT_BG: dict[Verdict, str] = {
    Verdict.PASS: "rgba(34,197,94,0.15)",
    Verdict.FAIL: "rgba(234,179,8,0.15)",
    Verdict.VULNERABLE: "rgba(239,68,68,0.15)",
    Verdict.UNCERTAIN: "rgba(59,130,246,0.15)",
    Verdict.ERROR: "rgba(168,85,247,0.15)",
    Verdict.TIMEOUT: "rgba(107,114,128,0.15)",
}


def _risk_color(score: float) -> str:
    """Return a colour for the risk score."""
    if score <= 20:
        return "#22c55e"
    elif score <= 50:
        return "#eab308"
    elif score <= 75:
        return "#ef4444"
    return "#dc2626"


def _risk_label(score: float) -> str:
    """Return a human label for the risk score."""
    if score <= 20:
        return "LOW"
    elif score <= 50:
        return "MODERATE"
    elif score <= 75:
        return "HIGH"
    return "CRITICAL"


def generate_html_report(report: EvalReport) -> str:
    """Render an EvalReport as a self-contained HTML string.

    Parameters
    ----------
    report:
        The completed evaluation report.

    Returns
    -------
    str
        A complete HTML document with inline CSS.
    """
    s = report.summary
    duration = (report.completed_at - report.started_at).total_seconds()
    risk_col = _risk_color(s.risk_score)
    risk_lbl = _risk_label(s.risk_score)

    # --- Build category breakdown rows ---
    cat_rows = ""
    for cat in s.categories_tested:
        cat_records = [r for r in report.records if r.prompt.category == cat]
        cat_pass = sum(1 for r in cat_records if r.overall_verdict == Verdict.PASS)
        cat_vuln = sum(
            1
            for r in cat_records
            if r.overall_verdict in (Verdict.VULNERABLE, Verdict.FAIL)
        )
        cat_total = len(cat_records)
        cat_meta = ASI_CATEGORIES.get(cat)
        cat_name = cat_meta.name if cat_meta else cat.value
        worst_marker = (
            ' <span style="color:#ef4444;font-weight:600;">WORST</span>'
            if cat == s.worst_category
            else ""
        )
        pass_rate = f"{cat_pass / cat_total:.0%}" if cat_total > 0 else "N/A"
        cat_rows += f"""
        <tr>
          <td><code>{escape(cat.value)}</code></td>
          <td>{escape(cat_name)}{worst_marker}</td>
          <td>{cat_total}</td>
          <td style="color:#22c55e;">{cat_pass}</td>
          <td style="color:#ef4444;">{cat_vuln}</td>
          <td>{pass_rate}</td>
        </tr>"""

    # --- Build detailed findings rows ---
    findings_rows = ""
    for record in report.records:
        v = record.overall_verdict
        color = _VERDICT_COLORS.get(v, "#ffffff")
        bg = _VERDICT_BG.get(v, "transparent")

        # Collect reasoning
        reasoning_parts = [
            dr.reasoning for dr in record.detector_results if dr.reasoning
        ]
        reasoning = escape(reasoning_parts[0]) if reasoning_parts else "No reasoning."

        # Remediation
        remediation_parts = [
            dr.remediation_hint
            for dr in record.detector_results
            if dr.remediation_hint
        ]
        remediation = (
            escape(remediation_parts[0]) if remediation_parts else ""
        )

        # Indicators
        all_indicators = []
        for dr in record.detector_results:
            all_indicators.extend(dr.indicators)
        indicators_html = ""
        if all_indicators:
            items = "".join(
                f"<li><code>{escape(ind)}</code></li>"
                for ind in all_indicators[:5]
            )
            indicators_html = f'<ul style="margin:4px 0 0 16px;padding:0;">{items}</ul>'

        findings_rows += f"""
        <tr>
          <td><code>{escape(record.prompt.id)}</code></td>
          <td><code>{escape(record.prompt.category.value)}</code></td>
          <td>{escape(record.prompt.severity.value)}</td>
          <td style="background:{bg};color:{color};font-weight:700;text-align:center;">
            {escape(v.value)}
          </td>
          <td style="text-align:center;">{record.overall_confidence:.0%}</td>
          <td>
            <div style="margin-bottom:4px;">{reasoning}</div>
            {indicators_html}
            {"<div style='margin-top:6px;color:#94a3b8;font-size:0.85em;'><strong>Remediation:</strong> " + remediation + "</div>" if remediation else ""}
          </td>
          <td style="text-align:right;font-family:monospace;">{record.response_time_ms:.0f}ms</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Bulwark Evaluation Report -- {escape(report.agent_name)}</title>
<style>
  :root {{
    --bg: #0f172a;
    --surface: #1e293b;
    --surface-2: #334155;
    --border: #475569;
    --text: #e2e8f0;
    --text-dim: #94a3b8;
    --accent: #06b6d4;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: 'SF Mono', 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 24px;
    max-width: 1400px;
    margin: 0 auto;
  }}
  h1, h2, h3 {{
    font-weight: 700;
    margin-bottom: 12px;
  }}
  h1 {{
    font-size: 1.8em;
    color: var(--accent);
    border-bottom: 2px solid var(--accent);
    padding-bottom: 12px;
    margin-bottom: 24px;
  }}
  h2 {{
    font-size: 1.3em;
    color: var(--accent);
    margin-top: 32px;
    margin-bottom: 16px;
  }}
  .header-meta {{
    display: flex;
    flex-wrap: wrap;
    gap: 24px;
    margin-bottom: 32px;
    color: var(--text-dim);
    font-size: 0.9em;
  }}
  .header-meta span {{
    color: var(--text);
    font-weight: 600;
  }}
  .cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
  }}
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    text-align: center;
  }}
  .card .label {{
    font-size: 0.8em;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 4px;
  }}
  .card .value {{
    font-size: 2em;
    font-weight: 800;
    line-height: 1.2;
  }}
  .card .sub {{
    font-size: 0.75em;
    color: var(--text-dim);
    margin-top: 2px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 24px;
    font-size: 0.85em;
  }}
  th {{
    background: var(--surface);
    color: var(--accent);
    text-align: left;
    padding: 10px 12px;
    border-bottom: 2px solid var(--border);
    font-weight: 700;
    text-transform: uppercase;
    font-size: 0.8em;
    letter-spacing: 0.04em;
  }}
  td {{
    padding: 10px 12px;
    border-bottom: 1px solid var(--surface-2);
    vertical-align: top;
  }}
  tr:hover {{
    background: rgba(6, 182, 212, 0.04);
  }}
  code {{
    background: var(--surface-2);
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 0.9em;
  }}
  .risk-badge {{
    display: inline-block;
    padding: 4px 12px;
    border-radius: 4px;
    font-weight: 800;
    font-size: 0.9em;
  }}
  .footer {{
    margin-top: 48px;
    padding-top: 16px;
    border-top: 1px solid var(--surface-2);
    color: var(--text-dim);
    font-size: 0.8em;
    text-align: center;
  }}
  ul {{ list-style: disc; }}
  li {{ margin-bottom: 2px; }}
</style>
</head>
<body>

<h1>BULWARK SECURITY EVALUATION REPORT</h1>

<div class="header-meta">
  <div>Agent: <span>{escape(report.agent_name)}</span></div>
  <div>Target: <span>{escape(report.target)}</span></div>
  <div>Started: <span>{report.started_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</span></div>
  <div>Completed: <span>{report.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</span></div>
  <div>Duration: <span>{duration:.1f}s</span></div>
</div>

<h2>Summary</h2>

<div class="cards">
  <div class="card">
    <div class="label">Total Prompts</div>
    <div class="value" style="color:var(--accent);">{s.total}</div>
  </div>
  <div class="card">
    <div class="label">Passed</div>
    <div class="value" style="color:#22c55e;">{s.passed}</div>
    <div class="sub">{s.pass_rate:.1%} pass rate</div>
  </div>
  <div class="card">
    <div class="label">Failed</div>
    <div class="value" style="color:#eab308;">{s.failed}</div>
  </div>
  <div class="card">
    <div class="label">Vulnerable</div>
    <div class="value" style="color:#ef4444;">{s.vulnerable}</div>
  </div>
  <div class="card">
    <div class="label">Uncertain</div>
    <div class="value" style="color:#3b82f6;">{s.uncertain}</div>
  </div>
  <div class="card">
    <div class="label">Errors</div>
    <div class="value" style="color:#a855f7;">{s.errors}</div>
  </div>
  <div class="card">
    <div class="label">Timeouts</div>
    <div class="value" style="color:#6b7280;">{s.timeouts}</div>
  </div>
  <div class="card">
    <div class="label">Risk Score</div>
    <div class="value" style="color:{risk_col};">{s.risk_score}</div>
    <div class="sub">
      <span class="risk-badge" style="background:{risk_col}20;color:{risk_col};">{risk_lbl}</span>
    </div>
  </div>
</div>

<h2>Category Breakdown</h2>

<table>
  <thead>
    <tr>
      <th>Code</th>
      <th>Category</th>
      <th>Total</th>
      <th>Passed</th>
      <th>Vulnerable/Failed</th>
      <th>Pass Rate</th>
    </tr>
  </thead>
  <tbody>{cat_rows}
  </tbody>
</table>

<h2>Detailed Findings</h2>

<table>
  <thead>
    <tr>
      <th>Prompt ID</th>
      <th>Category</th>
      <th>Severity</th>
      <th>Verdict</th>
      <th>Confidence</th>
      <th>Analysis</th>
      <th>Latency</th>
    </tr>
  </thead>
  <tbody>{findings_rows}
  </tbody>
</table>

<div class="footer">
  Generated by Bulwark AI Agent Security Evaluation Framework |
  {report.completed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
</div>

</body>
</html>"""

    return html
