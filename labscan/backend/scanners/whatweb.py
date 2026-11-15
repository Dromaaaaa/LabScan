"""Module whatweb : identification des technologies d'un site web."""

from __future__ import annotations

import json

from .base import BaseScanner


class WhatWebScanner(BaseScanner):
    name = "whatweb"
    binary = "whatweb"
    description = "Identification des technologies web (CMS, serveur, frameworks)"
    presets = {
        "passive": {"label": "Passif (une requête)", "args": ["-a", "1"]},
        "aggressive": {"label": "Agressif (requêtes supplémentaires)", "args": ["-a", "3"]},
    }

    def build_command(self, target: str, options: dict) -> list[str]:
        args = self.preset_args(options)
        return [
            self.binary, *args,
            "--color=never", "--no-errors", "-q",
            "--log-json=/dev/stdout",
            target,
        ]

    def parse(self, stdout: str, stderr: str) -> dict:
        entries = []
        start, end = stdout.find("["), stdout.rfind("]")
        if start != -1 and end > start:
            try:
                entries = json.loads(stdout[start:end + 1])
            except json.JSONDecodeError:
                entries = []

        sites = []
        for e in entries:
            if not isinstance(e, dict):
                continue
            plugins = []
            for name, data in (e.get("plugins") or {}).items():
                details = []
                for key in ("version", "string", "module", "os"):
                    details += [str(v) for v in data.get(key, [])]
                plugins.append({"name": name, "details": details})
            sites.append({
                "url": e.get("target"),
                "http_status": e.get("http_status"),
                "technologies": sorted(plugins, key=lambda p: p["name"].lower()),
            })
        return {"sites": sites}
