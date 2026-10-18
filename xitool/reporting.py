"""Report minimizzati: severità, confidenza, priorità ed esito restano distinti."""
import uuid
from . import __version__
from .assessment import assess
from .storage import atomic_write, confined, save_json, utcnow
from .scanners import MODULES


def export_project(project, engines, summary):
    runs = [engine for engine in engines if engine.project == project]
    issues = {}
    for engine in runs:
        for result in engine.state["results"]:
            row = assess(dict(result))
            key = row["issue_fingerprint"]
            if key not in issues:
                issues[key] = {"id": key, "domain": engine.target, "resource": row["url"], "check": row["check"],
                               "status": row["status"], "severity": row["severity"], "confidence_score": row["confidence_score"],
                               "review_priority": row["review_priority"], "confidence_factors": row["confidence_factors"], "provenance": []}
            issues[key]["provenance"].append({"module": engine.module, "run": engine.state["run_id"], "finding_id": row["id"],
                                             "evidence": row.get("evidence", {}), "limitations": row.get("limitations", "")})
    executed = {row["module"] for row in summary if row["project"] == project.name and row.get("processed")}
    if "subfinding" in executed:
        executed.add("crawler")
    value = {"project": project.name, "version": __version__, "created_at": utcnow(), "domains": sorted({engine.target or "legacy" for engine in runs}),
             "scope": {engine.target or "legacy": {"domains": engine.scope.raw_domains, "excluded_hosts": engine.scope.excluded,
                       "allowed_ip_ranges": [str(network) for network in engine.scope.networks]} for engine in runs},
             "modules_executed": sorted(executed), "modules_not_executed": sorted((set(MODULES) | {"crawler", "smart"}) - executed),
             "execution": [row for row in summary if row["project"] == project.name], "findings": list(issues.values()),
             "limitations": "Riepilogo del batch corrente. Assenze e priorità non sono severità o prova di risoluzione; dettagli nei report delle run."}
    directory = confined(project, project / "reports")
    identity = "batch_" + uuid.uuid4().hex
    save_json(directory / (identity + ".json"), value)
    lines = [f"XITool {__version__} — {project.name}", f"Data: {value['created_at']}", f"Domini: {', '.join(value['domains'])}", ""]
    for row in value["execution"]:
        lines.append(f"{row['domain']} / {row['module']}: {row['status']} ({row.get('errors', 0)} errori)")
    lines += ["", "Risultati unici: " + str(len(issues))]
    for row in issues.values():
        lines.append(f"{row['status']} | {row['review_priority']} | confidenza ordinale {row['confidence_score']}/100 | {row['resource']}")
    lines += ["", value["limitations"]]
    atomic_write(directory / (identity + ".txt"), "\n".join(lines) + "\n")
    atomic_write(directory / (identity + ".md"), "# " + "\n\n".join(lines) + "\n")
    return directory / (identity + ".json")
