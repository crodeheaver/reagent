"""Reconcile a bounded inventory with existing session results without mutation."""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from re_agent.core.session import Session
from re_agent.core.target_plan import TargetPlan
from re_agent.reports.tracker import match_cell
from re_agent.utils.address import normalize_address


def manifest_coverage(plan: TargetPlan, session: Session, current_identity: str) -> dict[str, Any]:
    records = {normalize_address(entry["address"]): entry for entry in session.get_all_functions()}
    rows = []
    totals = dict.fromkeys(("unattempted", "attempted", "accepted", "failed", "stale"), 0)
    compatible = session.identity == current_identity == plan.identity
    matching = {"exact": 0, "scored": 0, "exact_bytes": 0, "measured_bytes": 0}
    for target in sorted(plan.functions, key=lambda target: target.address):
        entry = records.get(target.address)
        checkpoint = session.get_checkpoint(target.address)
        if entry is None and checkpoint is None:
            status = "unattempted"
        elif not compatible:
            status = "stale"
        elif entry is None:
            status = "attempted"
        else:
            status = "accepted" if entry.get("success") else "failed"
        totals[status] += 1
        evidence = entry or checkpoint or {}
        match = evidence.get("match")
        if status != "stale" and isinstance(match, dict) and not match.get("error") and not match.get("violations"):
            exact = bool(match.get("exact")) and evidence.get("match_tier") == "exact"
            matching["exact" if exact else "scored"] += 1
            size = match.get("target_size")
            if isinstance(size, int):
                matching["measured_bytes"] += size
                matching["exact_bytes"] += size if exact else 0
        rows.append({**asdict(target), "status": status, "checker": evidence.get("verdict"),
                     "objective": evidence.get("objective_verdict"),
                     "candidate_validation": evidence.get("validation_verdict"),
                     "validation_checks": evidence.get("validation_checks", []),
                     "parity": evidence.get("parity_status"), "match": match_cell(match),
                     "match_tier": evidence.get("match_tier")})
    selected = {target.address for target in plan.functions}
    return {"planned": len(plan.functions), "totals": totals, "matching": matching, "functions": rows,
            "manifest_current": plan.identity == current_identity,
            "session_current": session.identity == current_identity,
            "external_dependencies": [edge for edge in plan.edges if edge["target"] not in selected],
            "gaps": [asdict(gap) for gap in plan.gaps],
            "scope": "Selected manifest only; acceptance is configured-policy acceptance, not proof of equivalence."}


def format_coverage(report: dict[str, Any], markdown: bool = False) -> str:
    lines = [report["scope"], f"Planned: {report['planned']}; " + ", ".join(
        f"{key}: {value}" for key, value in report["totals"].items()
    ), f"Manifest current: {report['manifest_current']}; session current: {report['session_current']}",
        f"External dependencies: {len(report['external_dependencies'])}; evidence gaps: {len(report['gaps'])}", ""]
    matching = report.get("matching", {})
    if matching.get("exact") or matching.get("scored"):
        measured = matching["measured_bytes"]
        share = f" ({matching['exact_bytes'] / measured:.1%} of {measured} measured bytes)" if measured else ""
        lines.insert(-1, f"Exact matches: {matching['exact']}; scored without exact match: {matching['scored']}{share}")
    if markdown:
        lines.extend(["| Address | Status | Checker | Objective | Candidate validation | Match |",
                      "|---|---|---|---|---|---|"])
    for row in report["functions"]:
        values = [row["address"], row["status"], row["checker"] or "unavailable",
                  row["objective"] or "unavailable", row["candidate_validation"] or "unavailable",
                  row.get("match", "-")]
        lines.append("| " + " | ".join(values) + " |" if markdown else "  ".join(values))
        for check in row["validation_checks"]:
            lines.append(f"  {row['address']} {check['kind']}: {check['verdict']} ({check['detail']})")
    return "\n".join(lines)
