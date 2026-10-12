"""Operation reports (JSON for tooling + a self-contained HTML page for people)."""
from __future__ import annotations

import datetime as dt
import html
import json
from dataclasses import dataclass, field
from pathlib import Path

from . import APP_NAME, __version__
from .models import Program
from .paths import human_size
from .textutil import slug


@dataclass
class OperationReport:
    operation: str  # uninstall | forced | scan
    program: Program
    started: str = field(default_factory=lambda: dt.datetime.now().isoformat(timespec="seconds"))
    finished: str = ""
    restore_point: dict | None = None
    plan: dict | None = None
    run: dict | None = None
    verification: dict | None = None
    scan: dict | None = None
    removal: dict | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"tool": APP_NAME, "version": __version__, "operation": self.operation,
                "started": self.started, "finished": self.finished, "program": self.program.to_dict(),
                "restore_point": self.restore_point, "plan": self.plan, "run": self.run,
                "verification": self.verification, "scan": self.scan, "removal": self.removal,
                "notes": self.notes}

    def save(self, folder: Path, tr=lambda k, **kw: k) -> tuple[Path, Path]:
        self.finished = self.finished or dt.datetime.now().isoformat(timespec="seconds")
        folder.mkdir(parents=True, exist_ok=True)
        stem = dt.datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + slug(self.program.name)
        json_path = folder / f"{stem}.json"
        html_path = folder / f"{stem}.html"
        data = self.to_dict()
        json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        html_path.write_text(render_html(data, tr), encoding="utf-8")
        return json_path, html_path


def _row(label: str, value) -> str:
    return f"<tr><th>{html.escape(label)}</th><td>{html.escape(str(value or '—'))}</td></tr>"


def render_html(d: dict, tr) -> str:
    p = d["program"]
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'><title>",
        html.escape(f"{APP_NAME} – {p['name']}"),
        "</title><style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#1b2430;background:#fff}"
        "h1{color:#0e7c6b}h2{margin-top:28px;border-bottom:1px solid #ddd}"
        "table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:4px 8px;vertical-align:top;"
        "border-bottom:1px solid #eee;font-size:13px}th{width:220px;color:#555}"
        ".HIGH{color:#0a7a2f;font-weight:600}.MEDIUM{color:#a66b00;font-weight:600}.LOW{color:#666}"
        ".mono{font-family:Consolas,monospace;word-break:break-all}</style></head><body>",
        f"<h1>{html.escape(APP_NAME)} – {html.escape(tr('report.title'))}</h1>",
        "<table>",
        _row(tr("report.operation"), tr("op." + d["operation"])),
        _row(tr("col.name"), p["name"]), _row(tr("col.version"), p["version"]),
        _row(tr("col.publisher"), p["publisher"]), _row(tr("detail.location"), p["install_location"]),
        _row(tr("report.started"), d["started"]), _row(tr("report.finished"), d["finished"]),
        _row(tr("report.tool"), f"{d['tool']} {d['version']}"),
        "</table>",
    ]
    if d.get("restore_point"):
        rp = d["restore_point"]
        parts += [f"<h2>{html.escape(tr('report.restore_point'))}</h2><table>",
                  _row(tr("report.result"), tr("yes") if rp.get("ok") else tr("no")),
                  _row(tr("report.details"), rp.get("message")), "</table>"]
    if d.get("plan") or d.get("run"):
        parts.append(f"<h2>{html.escape(tr('report.uninstaller'))}</h2><table>")
        if d.get("plan"):
            parts.append(_row(tr("report.command"), f"{d['plan']['executable']} {d['plan']['arguments']}"))
        if d.get("run"):
            parts += [_row(tr("report.exit_code"), d["run"].get("exit_code")),
                      _row(tr("report.result"), tr("outcome." + d["run"].get("outcome", "unknown")))]
        if d.get("verification"):
            for k, v in d["verification"].items():
                parts.append(_row(tr("verify." + k), tr("yes") if v is True else tr("no") if v is False else v))
        parts.append("</table>")
    if d.get("scan"):
        s = d["scan"]
        parts += [f"<h2>{html.escape(tr('report.scan'))}</h2><table>",
                  _row(tr("report.mode"), tr("mode." + s["mode"].lower())),
                  _row(tr("report.found"), len(s["leftovers"])),
                  _row(tr("conf.HIGH"), s["counts"].get("HIGH")), _row(tr("conf.MEDIUM"), s["counts"].get("MEDIUM")),
                  _row(tr("conf.LOW"), s["counts"].get("LOW")), _row(tr("report.protected"), s["counts"].get("PROTECTED")),
                  "</table>"]
    if d.get("removal"):
        r = d["removal"]
        parts += [f"<h2>{html.escape(tr('report.removal'))}</h2>",
                  f"<p class='mono'>{html.escape(tr('report.quarantine_at'))}: {html.escape(r.get('session', ''))}</p>",
                  "<table><tr><th>", html.escape(tr("report.status")), "</th><th>", html.escape(tr("col.item")),
                  "</th><th>", html.escape(tr("col.confidence")), "</th><th>", html.escape(tr("col.size")), "</th></tr>"]
        for item in r.get("items", []):
            lo = item["leftover"]
            status = tr("status." + item["status"]) + (f" ({item['error']})" if item.get("error") else "")
            parts.append(f"<tr><td>{html.escape(status)}</td><td class='mono'>{html.escape(lo['display'])}</td>"
                         f"<td class='{lo['confidence']}'>{html.escape(tr('conf.' + lo['confidence']))}</td>"
                         f"<td>{html.escape(human_size(lo.get('size', 0)))}</td></tr>")
        parts.append("</table>")
    if d.get("notes"):
        parts.append(f"<h2>{html.escape(tr('report.notes'))}</h2><ul>")
        parts += [f"<li>{html.escape(n)}</li>" for n in d["notes"]]
        parts.append("</ul>")
    parts.append("</body></html>")
    return "".join(parts)
