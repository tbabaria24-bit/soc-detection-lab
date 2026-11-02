"""Turn alerts into analyst-friendly output.

* ``alerts.json``                 machine-readable alerts (for a SIEM or ticketing system)
* ``incident_report.md``          a readable incident report with timeline and response steps
* ``attack_navigator_layer.json`` a layer you can load into MITRE ATT&CK Navigator
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .engine import SEVERITY_ORDER, Alert, Rule

TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
]
SEVERITY_LABEL = {"critical": "🟥 Critical", "high": "🟧 High", "medium": "🟨 Medium", "low": "🟦 Low",
                  "informational": "⬜ Info"}
EVIDENCE_LINES = 6


def write_reports(alerts: list[Alert], rules: list[Rule], stats: dict, out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": out_dir / "alerts.json",
        "markdown": out_dir / "incident_report.md",
        "navigator": out_dir / "attack_navigator_layer.json",
    }
    paths["json"].write_text(json.dumps([a.to_dict() for a in alerts], indent=2), encoding="utf-8")
    paths["markdown"].write_text(render_markdown(alerts, rules, stats), encoding="utf-8")
    paths["navigator"].write_text(json.dumps(navigator_layer(alerts), indent=2), encoding="utf-8")
    return paths


def render_markdown(alerts: list[Alert], rules: list[Rule], stats: dict) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sev = Counter(a.rule.severity for a in alerts)
    hosts = sorted({h for a in alerts for h in a.hosts})
    ips = sorted({str(e.get("src_ip")) for a in alerts for e in a.evidence if e.get("src_ip")})

    out: list[str] = ["# Incident Report", ""]
    out.append(f"*Generated {now} by SOC Detection Lab. {stats['events']} events from "
               f"{stats['files']} log files checked against {len(rules)} detection rules.*")
    out.append("")

    out += ["## Summary", ""]
    if not alerts:
        out += ["No detections. No rule matched the analyzed logs.", ""]
        return "\n".join(out)
    first, last = alerts[0].first_seen, max(a.last_seen for a in alerts)
    out.append(f"**{len(alerts)} alerts** between {_ts(first)} and {_ts(last)} UTC.")
    out.append("")
    out.append("| Severity | Alerts |")
    out.append("| --- | --- |")
    for level in SEVERITY_ORDER:
        if sev[level]:
            out.append(f"| {SEVERITY_LABEL[level]} | {sev[level]} |")
    out.append("")
    out.append(f"- **Affected hosts:** {', '.join(hosts) or 'n/a'}")
    out.append(f"- **Source IPs involved:** {', '.join(ips) or 'n/a'}")
    tactics = list(dict.fromkeys(a.rule.tactic for a in alerts))  # first appearance, in time order
    out.append(f"- **Attack stages, in the order seen:** {' → '.join(tactics)}")
    out.append("")

    out += ["## Attack timeline", "", "| Time (UTC) | Severity | Host | Technique | Detection | Details |",
            "| --- | --- | --- | --- | --- | --- |"]
    for a in alerts:
        out.append(f"| {_ts(a.first_seen)} | {SEVERITY_LABEL[a.rule.severity]} | {', '.join(a.hosts)} | "
                   f"{a.rule.technique_id} | {a.rule.title} | {_cell(a.summary())} |")
    out.append("")

    out += ["## MITRE ATT&CK coverage", "", "| Tactic | Technique | Alerts |", "| --- | --- | --- |"]
    by_tech = Counter((a.rule.tactic, a.rule.technique_id, a.rule.technique_name) for a in alerts)
    for (tactic, tid, name), n in sorted(by_tech.items(), key=lambda kv: (_tactic_rank(kv[0][0]), kv[0][1])):
        out.append(f"| {tactic} | [{tid}]({_mitre_url(tid)}) {name} | {n} |")
    out.append("")

    out += ["## Findings", ""]
    for i, a in enumerate(sorted(alerts, key=lambda x: (SEVERITY_ORDER[x.rule.severity], x.first_seen)), 1):
        r = a.rule
        out.append(f"### {i}. {r.title}")
        out.append("")
        out.append(f"**Severity:** {SEVERITY_LABEL[r.severity]} · **MITRE:** {r.tactic} / "
                   f"[{r.technique_id} {r.technique_name}]({_mitre_url(r.technique_id)}) · "
                   f"**Host:** {', '.join(a.hosts)} · **Rule:** `{r.id}`")
        out.append("")
        if r.description:
            out += [r.description, ""]
        out += [f"**What happened:** {a.summary()}", ""]
        out.append(f"**Evidence** ({len(a.evidence)} events" +
                   (f", {EVIDENCE_LINES} shown" if len(a.evidence) > EVIDENCE_LINES else "") + "):")
        out.append("")
        out.append("```")
        ev = a.evidence
        if len(ev) > EVIDENCE_LINES:  # show the start and the last event (often the most important)
            out += [e.raw for e in ev[: EVIDENCE_LINES - 1]]
            out.append(f"... {len(ev) - EVIDENCE_LINES} more ...")
            out.append(ev[-1].raw)
        else:
            out += [e.raw for e in ev]
        out.append("```")
        out.append("")
        if r.response:
            out.append("**Recommended response:**")
            out.append("")
            out += [f"{n}. {step}" for n, step in enumerate(r.response, 1)]
            out.append("")
    return "\n".join(out)


def navigator_layer(alerts: list[Alert]) -> dict:
    """An ATT&CK Navigator layer: each detected technique scored by alert count."""
    counts = Counter(a.rule.technique_id for a in alerts)
    titles: dict[str, set[str]] = {}
    for a in alerts:
        titles.setdefault(a.rule.technique_id, set()).add(a.rule.title)
    return {
        "name": "SOC Detection Lab - detected techniques",
        "versions": {"layer": "4.5", "navigator": "5.1.0", "attack": "16"},
        "domain": "enterprise-attack",
        "description": "Techniques detected by SOC Detection Lab. Score = number of alerts.",
        "techniques": [
            {"techniqueID": tid, "score": n, "comment": "; ".join(sorted(titles[tid])), "enabled": True}
            for tid, n in sorted(counts.items())
        ],
        "gradient": {"colors": ["#ffe8a3", "#ff6b6b"], "minValue": 0, "maxValue": max(counts.values(), default=1)},
        "layout": {"layout": "side", "showName": True},
        "hideDisabled": False,
    }


def console_summary(alerts: list[Alert]) -> str:
    if not alerts:
        return "No detections."
    width = max(len(a.rule.title) for a in alerts)
    lines = [f"{'TIME (UTC)':19}  {'SEVERITY':8}  {'TECHNIQUE':10}  {'DETECTION':{width}}  HOST"]
    for a in alerts:
        lines.append(f"{_ts(a.first_seen):19}  {a.rule.severity.upper():8}  {a.rule.technique_id:10}  "
                     f"{a.rule.title:{width}}  {', '.join(a.hosts)}")
    return "\n".join(lines)


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _tactic_rank(tactic: str) -> int:
    return TACTIC_ORDER.index(tactic) if tactic in TACTIC_ORDER else len(TACTIC_ORDER)


def _mitre_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"
