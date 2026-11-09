"""Write findings as JSON, Markdown, HTML, and SARIF reports."""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from secwatch import __version__
from secwatch.models import SEVERITY_ORDER, Finding

SEV_COLORS = {"critical": "#b42318", "high": "#d9480f", "medium": "#b7791f", "low": "#2b6cb0", "info": "#4a5568"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity_rank, f.category, f.rule_id, f.entity))


def summarize(findings: list[Finding]) -> dict:
    sev = Counter(f.severity for f in findings)
    return {
        "total": len(findings),
        "by_severity": {s: sev.get(s, 0) for s in sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get, reverse=True)},
        "by_category": dict(Counter(f.category for f in findings)),
        "mitre_techniques": sorted({f.mitre_technique for f in findings if f.mitre_technique}),
    }


def to_json(findings: list[Finding]) -> str:
    return json.dumps(
        {
            "tool": "secwatch",
            "version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "summary": summarize(findings),
            "findings": [f.to_dict() for f in _sorted(findings)],
        },
        indent=2,
    )


def to_markdown(findings: list[Finding]) -> str:
    s = summarize(findings)
    lines = [
        "# SecWatch Security Report",
        "",
        f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC} · {s['total']} findings",
        "",
        "| Severity | Count |",
        "|---|---|",
        *[f"| {k.title()} | {v} |" for k, v in s["by_severity"].items()],
        "",
        "## Findings",
        "",
        "| Severity | ID | Title | Entity | Count | ATT&CK |",
        "|---|---|---|---|---|---|",
    ]
    for f in _sorted(findings):
        ent = f.entity.replace("|", "\\|")
        lines.append(f"| {f.severity.upper()} | {f.rule_id} | {f.title} | `{ent}` | {f.count} | {f.mitre_technique} |")
    lines += ["", "## Details", ""]
    for f in _sorted(findings):
        lines += [f"### [{f.severity.upper()}] {f.rule_id}: {f.title}", "", f.description, ""]
        if f.entity:
            lines.append(f"- **Entity:** `{f.entity}`")
        if f.first_seen:
            lines.append(f"- **Seen:** {f.first_seen} to {f.last_seen} ({f.count} events)")
        if f.mitre_technique:
            lines.append(f"- **MITRE ATT&CK:** {f.mitre_tactic} / {f.mitre_technique}")
        if f.remediation:
            lines.append(f"- **Remediation:** {f.remediation}")
        if f.evidence:
            lines += ["", "```", *f.evidence, "```"]
        lines.append("")
    return "\n".join(lines)


def to_html(findings: list[Finding]) -> str:
    s = summarize(findings)
    esc = html.escape
    cards = "".join(
        f'<div class="card"><span class="n" style="color:{SEV_COLORS[k]}">{v}</span><span>{k.title()}</span></div>'
        for k, v in s["by_severity"].items()
    )
    rows = []
    for f in _sorted(findings):
        ev = esc("\n".join(f.evidence))
        rows.append(
            f'<details class="f"><summary><span class="sev" style="background:{SEV_COLORS.get(f.severity, "#4a5568")}">'
            f"{esc(f.severity.upper())}</span> <b>{esc(f.rule_id)}</b> {esc(f.title)}"
            f'<span class="ent">{esc(f.entity)}</span></summary>'
            f"<p>{esc(f.description)}</p>"
            + (f"<p><b>MITRE ATT&amp;CK:</b> {esc(f.mitre_tactic)} · {esc(f.mitre_technique)}</p>" if f.mitre_technique else "")
            + (f"<p><b>Seen:</b> {esc(f.first_seen)} → {esc(f.last_seen)} ({f.count} events)</p>" if f.first_seen else "")
            + (f"<p><b>Remediation:</b> {esc(f.remediation)}</p>" if f.remediation else "")
            + (f"<pre>{ev}</pre>" if ev else "")
            + "</details>"
        )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>SecWatch Report</title>
<style>
:root{{--bg:#f7f8fa;--fg:#1a202c;--card:#fff;--muted:#5a6475;--line:#e2e8f0}}
@media (prefers-color-scheme:dark){{:root{{--bg:#11151c;--fg:#e6e9ef;--card:#1a202b;--muted:#9aa4b2;--line:#2a3240}}}}
body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;background:var(--bg);color:var(--fg);margin:0;padding:2rem;max-width:1100px;margin:auto}}
h1{{margin:0 0 .25rem}}.muted{{color:var(--muted)}}
.cards{{display:flex;gap:1rem;flex-wrap:wrap;margin:1.5rem 0}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:1rem 1.25rem;display:flex;flex-direction:column;min-width:110px}}
.n{{font-size:2rem;font-weight:700}}
.f{{background:var(--card);border:1px solid var(--line);border-radius:8px;margin:.5rem 0;padding:.75rem 1rem}}
summary{{cursor:pointer;display:flex;gap:.6rem;align-items:center;flex-wrap:wrap}}
.sev{{color:#fff;border-radius:4px;padding:.1rem .45rem;font-size:.75rem;font-weight:700}}
.ent{{margin-left:auto;color:var(--muted);font-family:ui-monospace,monospace;font-size:.85rem}}
pre{{background:var(--bg);border:1px solid var(--line);padding:.75rem;overflow-x:auto;font-size:.8rem;border-radius:6px}}
</style></head><body>
<h1>SecWatch Security Report</h1>
<p class="muted">Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC} · {s['total']} findings · {len(s['mitre_techniques'])} ATT&amp;CK techniques</p>
<div class="cards">{cards}</div>
{''.join(rows) or '<p>No findings.</p>'}
</body></html>"""


def to_sarif(findings: list[Finding]) -> str:
    """SARIF 2.1.0 output so findings appear in GitHub code scanning."""
    rules, seen = [], set()
    for f in findings:
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            rules.append({
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "help": {"text": f.remediation or f.description},
                "properties": {"tags": [f.category] + ([f.mitre_technique] if f.mitre_technique else [])},
            })
    results = [
        {
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.title}: {f.description} [{f.entity}]"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "infra/terraform/main.tf" if f.category == "iac" else "sample_data"}}}],
        }
        for f in _sorted(findings)
    ]
    return json.dumps({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "secwatch", "version": __version__, "rules": rules}}, "results": results}],
    }, indent=2)


WRITERS = {"json": to_json, "md": to_markdown, "html": to_html, "sarif": to_sarif}


def write_reports(findings: list[Finding], out_dir: str | Path, formats: list[str], name: str = "report") -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = []
    for fmt in formats:
        if fmt not in WRITERS:
            raise ValueError(f"Unknown format '{fmt}'. Choose from {sorted(WRITERS)}.")
        p = out / f"{name}.{fmt}"
        p.write_text(WRITERS[fmt](findings), encoding="utf-8")
        paths.append(p)
    return paths
