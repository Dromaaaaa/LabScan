"""Module gobuster : découverte de contenus web (dossiers, fichiers)."""

from __future__ import annotations

import re

from .base import BaseScanner

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_LINE = re.compile(r"^(/\S*)\s+\(Status:\s*(\d+)\)(?:\s*\[Size:\s*(\d+)\])?(?:\s*\[--> *([^\]]+)\])?")


class GobusterScanner(BaseScanner):
    name = "gobuster"
    binary = "gobuster"
    description = "Découverte de dossiers et fichiers cachés sur un serveur web"
    presets = {
        "common": {
            "label": "Liste courante (dirb common)",
            "wordlist": "/usr/share/dirb/wordlists/common.txt",
            "args": ["-t", "20"],
        },
        "big": {
            "label": "Liste étendue (dirb big)",
            "wordlist": "/usr/share/dirb/wordlists/big.txt",
            "args": ["-t", "20"],
        },
    }

    def build_command(self, target: str, options: dict) -> list[str]:
        wordlist = self.validate_wordlist(options)
        args = self.presets[options.get("preset") or next(iter(self.presets))]["args"]
        if not target.startswith(("http://", "https://")):
            target = "http://" + target
        return [self.binary, "dir", "-u", target, "-w", wordlist, "-q", "--no-error", "-z", *args]

    def parse(self, stdout: str, stderr: str) -> dict:
        found = []
        clean = _ANSI.sub("", stdout).replace("\r", "\n")
        for line in clean.splitlines():
            m = _LINE.match(line.strip())
            if m:
                found.append({
                    "path": m.group(1),
                    "status": int(m.group(2)),
                    "size": int(m.group(3)) if m.group(3) else None,
                    "redirect": m.group(4),
                })
        found.sort(key=lambda x: x["path"])
        return {"found": found, "count": len(found)}
