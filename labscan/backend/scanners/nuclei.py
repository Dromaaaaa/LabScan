"""Module nuclei : détection de vulnérabilités connues via templates.

nuclei émet un objet JSON par ligne (-jsonl). On en extrait l'identifiant
du template, le nom, la sévérité et l'URL où la détection a eu lieu.
"""

from __future__ import annotations

import json

from .base import BaseScanner

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


class NucleiScanner(BaseScanner):
    name = "nuclei"
    binary = "nuclei"
    description = "Détection de vulnérabilités connues (templates communautaires)"
    presets = {
        "default": {"label": "Templates par défaut", "args": []},
        "cves": {"label": "CVE connues", "args": ["-tags", "cve"]},
        "tech": {"label": "Détection de technologies", "args": ["-tags", "tech"]},
        "exposures": {"label": "Expositions (fichiers, panneaux)", "args": ["-tags", "exposure,panel"]},
    }

    def build_command(self, target: str, options: dict) -> list[str]:
        args = self.preset_args(options)
        return [
            self.binary, "-u", target,
            "-jsonl", "-silent", "-no-color",
            "-timeout", "10", "-rate-limit", "50",
            *args,
        ]

    def parse(self, stdout: str, stderr: str) -> dict:
        findings = []
        counts: dict[str, int] = {}
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = obj.get("info", {})
            severity = (info.get("severity") or "unknown").lower()
            counts[severity] = counts.get(severity, 0) + 1
            findings.append({
                "template": obj.get("template-id"),
                "name": info.get("name"),
                "severity": severity,
                "tags": info.get("tags", []),
                "matched_at": obj.get("matched-at") or obj.get("host"),
            })
        findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 5))
        return {"findings": findings, "count": len(findings), "by_severity": counts}
