"""Registre des scanners. Ajouter un outil = l'importer et l'ajouter ici."""

from .base import BaseScanner, ScanOptionError, ScanResult
from .gobuster import GobusterScanner
from .nikto import NiktoScanner
from .nmap import NmapScanner
from .nuclei import NucleiScanner
from .theharvester import TheHarvesterScanner
from .whatweb import WhatWebScanner

SCANNERS: dict[str, BaseScanner] = {
    s.name: s for s in (
        NmapScanner(),
        WhatWebScanner(),
        GobusterScanner(),
        NiktoScanner(),
        NucleiScanner(),
        TheHarvesterScanner(),
    )
}

__all__ = ["SCANNERS", "BaseScanner", "ScanOptionError", "ScanResult"]
