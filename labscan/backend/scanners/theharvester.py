"""Module theHarvester : OSINT passif sur un domaine (emails, sous-domaines).

Contrairement aux autres modules, theHarvester n'envoie rien à la cible :
il interroge des sources publiques. Il n'est donc pas soumis au périmètre
réseau mais à l'allowlist de domaines (requires_scope = False, voir scope.py).
Le binaire s'installe via : pipx install theHarvester.
"""

from __future__ import annotations

import re

from .base import BaseScanner

_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_HOST = re.compile(r"^[\w.-]+\.[a-z]{2,}(?::\d{1,3}(?:\.\d{1,3}){3})?$", re.I)


class TheHarvesterScanner(BaseScanner):
    name = "theharvester"
    binary = "theHarvester"
    description = "OSINT passif : emails et sous-domaines depuis des sources publiques"
    requires_scope = False
    presets = {
        "basic": {"label": "Sources rapides (bing, duckduckgo)", "args": ["-b", "bing,duckduckgo"]},
        "subdomains": {"label": "Sous-domaines (crtsh, bing)", "args": ["-b", "crtsh,bing"]},
    }

    def build_command(self, target: str, options: dict) -> list[str]:
        args = self.preset_args(options)
        domain = target.split("://")[-1].split("/")[0]
        return [self.binary, "-d", domain, *args]

    def parse(self, stdout: str, stderr: str) -> dict:
        emails: set[str] = set()
        hosts: set[str] = set()
        section = None
        for line in stdout.splitlines():
            low = line.lower()
            if "emails found" in low:
                section = "emails"
                continue
            if "hosts found" in low:
                section = "hosts"
                continue
            if line.startswith("[") or set(line.strip()) <= {"-"} or not line.strip():
                if line.startswith("[*]"):
                    section = None
                continue
            if section == "emails":
                emails.update(_EMAIL.findall(line))
            elif section == "hosts" and _HOST.match(line.strip()):
                hosts.add(line.strip())
        return {
            "emails": sorted(emails),
            "hosts": sorted(hosts),
            "count": len(emails) + len(hosts),
        }
