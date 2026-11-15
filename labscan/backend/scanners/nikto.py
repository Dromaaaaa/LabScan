"""Module nikto : scanner de configuration de serveur web.

Nikto 2.1.x ne produit pas de JSON exploitable ; on parse la sortie texte.
Chaque ligne de résultat commence par "+ ". Les lignes d'en-tête
(cible, horodatage, compteurs) sont classées à part des observations.
"""

from __future__ import annotations

import re

from .base import BaseScanner

_META = re.compile(
    r"^(Target IP|Target Hostname|Target Port|Start Time|End Time|Server|"
    r"\d+ items? checked|\d+ host\(s\) tested|No CGI Directories)"
)


class NiktoScanner(BaseScanner):
    name = "nikto"
    binary = "nikto"
    description = "Scanner de configuration et d'en-têtes de serveur web"
    presets = {
        "default": {"label": "Analyse standard", "args": []},
        "headers": {"label": "En-têtes et méthodes uniquement", "args": ["-Tuning", "b"]},
    }

    def build_command(self, target: str, options: dict) -> list[str]:
        args = self.preset_args(options)
        return [self.binary, "-h", target, "-nointeractive", "-ask", "no", *args]

    def parse(self, stdout: str, stderr: str) -> dict:
        server = None
        findings = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line.startswith("+ "):
                continue
            text = line[2:].strip()
            if text.startswith("Server:"):
                server = text.split(":", 1)[1].strip()
                continue
            if _META.match(text):
                continue
            findings.append(text)
        return {"server": server, "findings": findings, "count": len(findings)}
