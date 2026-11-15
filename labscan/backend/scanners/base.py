"""
Interface commune à tous les scanners.

Chaque outil (nmap, whatweb, masscan, nuclei...) hérite de BaseScanner et
implémente build_command() et parse(). Le reste de l'application ne connaît
que cette interface : ajouter un outil ne modifie jamais le code existant.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

SCAN_TIMEOUT_SECONDS = 60 * 60


class ScanOptionError(ValueError):
    """Option de scan invalide (preset inconnu, ports mal formés...)."""


@dataclass
class ScanResult:
    tool: str
    target: str
    preset: str
    command: list[str]
    started_at: str
    finished_at: str
    raw_output: str
    parsed: dict = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class BaseScanner(ABC):
    name: str = "base"
    binary: str = ""
    description: str = ""
    # Presets autorisés : {"clé": {"label": str, "args": [str, ...]}}
    presets: dict[str, dict] = {}
    # True  : l'outil envoie des paquets à la cible -> périmètre réseau (check_target)
    # False : OSINT passif sur un domaine -> allowlist de domaines (check_osint_target)
    requires_scope: bool = True

    PORTS_RE = re.compile(r"^[0-9,\-]{1,200}$")

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    def info(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "available": self.is_available(),
            "requires_scope": self.requires_scope,
            "presets": {k: v["label"] for k, v in self.presets.items()},
        }

    def validate_wordlist(self, options: dict) -> str:
        """Renvoie le chemin de wordlist du preset choisi, après vérification."""
        preset = options.get("preset") or next(iter(self.presets))
        if preset not in self.presets:
            raise ScanOptionError(f"preset inconnu pour {self.name} : {preset}")
        path = self.presets[preset].get("wordlist")
        if not path or not os.path.isfile(path):
            raise ScanOptionError(f"wordlist introuvable : {path or 'non définie'}")
        return path

    def preset_args(self, options: dict) -> list[str]:
        preset = options.get("preset") or next(iter(self.presets))
        if preset not in self.presets:
            raise ScanOptionError(f"preset inconnu pour {self.name} : {preset}")
        return list(self.presets[preset]["args"])

    def validate_ports(self, ports: str | None) -> str | None:
        if not ports:
            return None
        if not self.PORTS_RE.match(ports):
            raise ScanOptionError("format de ports invalide (ex : 22,80,443 ou 1-1024)")
        return ports

    @abstractmethod
    def build_command(self, target: str, options: dict) -> list[str]:
        """Construit la liste d'arguments passée au binaire."""

    @abstractmethod
    def parse(self, stdout: str, stderr: str) -> dict:
        """Transforme la sortie brute en structure exploitable par l'interface."""

    async def run(self, target: str, options: dict | None = None) -> ScanResult:
        options = options or {}
        started = datetime.now(timezone.utc).isoformat()
        cmd = self.build_command(target, options)
        stdout = stderr = ""
        parsed: dict = {}
        error: str | None = None

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                out_b, err_b = await asyncio.wait_for(
                    proc.communicate(), timeout=SCAN_TIMEOUT_SECONDS
                )
            except asyncio.TimeoutError:
                proc.kill()
                out_b, err_b = await proc.communicate()
                error = f"délai dépassé ({SCAN_TIMEOUT_SECONDS} s)"

            stdout = out_b.decode(errors="replace")
            stderr = err_b.decode(errors="replace")
            if error is None and proc.returncode != 0:
                error = f"code de sortie {proc.returncode}"
            try:
                parsed = self.parse(stdout, stderr)
            except Exception as exc:  # noqa: BLE001
                error = error or f"échec du parsing : {exc}"
        except FileNotFoundError:
            error = f"binaire '{self.binary}' introuvable"
        except Exception as exc:  # noqa: BLE001
            error = str(exc)

        return ScanResult(
            tool=self.name,
            target=target,
            preset=options.get("preset") or next(iter(self.presets), ""),
            command=cmd,
            started_at=started,
            finished_at=datetime.now(timezone.utc).isoformat(),
            raw_output=stdout + (("\n" + stderr) if stderr.strip() else ""),
            parsed=parsed,
            error=error,
        )
