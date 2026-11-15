"""
Contrôle de périmètre : aucune cible n'est scannée si elle n'est pas
explicitement autorisée dans scope.json.

Règles :
  - IP : doit appartenir à un des réseaux de "cidrs"
  - Plage CIDR : doit être entièrement incluse dans un réseau autorisé
  - Nom d'hôte / URL : soit listé tel quel dans "hosts",
    soit toutes ses adresses résolues sont dans "cidrs"
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
from pathlib import Path
from urllib.parse import urlparse

SCOPE_FILE = Path(__file__).resolve().parent.parent / "scope.json"
TARGET_RE = re.compile(r"^[A-Za-z0-9.\-:/_\[\]]{1,253}$")

DEFAULT_SCOPE = {
    "cidrs": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    "hosts": [],
}


class ScopeError(ValueError):
    """Cible refusée par le contrôle de périmètre."""


def load_scope() -> dict:
    if not SCOPE_FILE.exists():
        SCOPE_FILE.write_text(json.dumps(DEFAULT_SCOPE, indent=2) + "\n", encoding="utf-8")
    data = json.loads(SCOPE_FILE.read_text(encoding="utf-8"))
    return {
        "cidrs": [str(ipaddress.ip_network(c, strict=False)) for c in data.get("cidrs", [])],
        "hosts": [h.lower().strip() for h in data.get("hosts", []) if h.strip()],
    }


def _networks(scope: dict):
    return [ipaddress.ip_network(c, strict=False) for c in scope["cidrs"]]


def _ip_allowed(ip: ipaddress._BaseAddress, nets) -> bool:
    return any(ip.version == n.version and ip in n for n in nets)


def _extract_host(target: str) -> str:
    if "://" in target:
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ScopeError("URL invalide (http:// ou https:// attendu)")
        return parsed.hostname
    return target


def check_osint_target(target: str) -> str:
    """OSINT passif : le domaine doit figurer dans l'allowlist 'hosts' (ou en être un sous-domaine)."""
    domain = target.strip().split("://")[-1].split("/")[0].lower()
    if not domain or not TARGET_RE.match(domain):
        raise ScopeError("format de domaine invalide")
    allow = load_scope()["hosts"]
    if not any(domain == h or domain.endswith("." + h) for h in allow):
        raise ScopeError(
            f"{domain} n'est pas dans l'allowlist OSINT. "
            "Ajoute le domaine autorisé dans scope.json > hosts."
        )
    return domain


def check_target(target: str) -> str:
    """Retourne la cible nettoyée si elle est dans le périmètre, lève ScopeError sinon."""
    target = target.strip()
    if not target or target.startswith("-") or not TARGET_RE.match(target.split("://")[-1]):
        raise ScopeError("format de cible invalide")

    scope = load_scope()
    nets = _networks(scope)
    host = _extract_host(target)

    # Plage CIDR
    if "/" in host:
        try:
            net = ipaddress.ip_network(host, strict=False)
        except ValueError as exc:
            raise ScopeError("plage CIDR invalide") from exc
        if not any(net.version == n.version and net.subnet_of(n) for n in nets):
            raise ScopeError(f"{net} n'est pas entièrement incluse dans le périmètre autorisé")
        return target

    # Adresse IP
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        ip = None
    if ip is not None:
        if not _ip_allowed(ip, nets):
            raise ScopeError(f"{ip} est hors périmètre")
        return target

    # Nom d'hôte
    if host.lower() in scope["hosts"]:
        return target
    try:
        resolved = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except socket.gaierror as exc:
        raise ScopeError(f"impossible de résoudre {host}") from exc
    outside = [a for a in resolved if not _ip_allowed(ipaddress.ip_address(a), nets)]
    if outside:
        raise ScopeError(f"{host} résout vers des adresses hors périmètre : {', '.join(sorted(outside))}")
    return target
