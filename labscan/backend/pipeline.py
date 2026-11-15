"""
Chaîne de reconnaissance : nmap (services) puis whatweb + nikto sur chaque
service HTTP découvert.

Ne contient aucune exploitation : uniquement de la découverte et de la
détection, enchaînées automatiquement pour éviter de relancer chaque outil
à la main.
"""

from __future__ import annotations

HTTP_PORTS = {80, 443, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8443, 8888}
HTTPS_PORTS = {443, 8443}

# Étapes lancées sur chaque service HTTP trouvé : (outil, preset)
WEB_STEPS = (("whatweb", "passive"), ("nikto", "default"))


def http_endpoints(nmap_result: dict) -> list[str]:
    """Extrait les URL HTTP(S) des hôtes/ports ouverts d'un résultat nmap."""
    endpoints: list[str] = []
    for host in (nmap_result.get("parsed", {}).get("hosts") or []):
        address = host.get("ipv4") or host.get("ipv6")
        if not address:
            continue
        for port in host.get("ports", []):
            if port.get("state") != "open":
                continue
            service = (port.get("service") or "").lower()
            number = port.get("port")
            if "http" not in service and number not in HTTP_PORTS:
                continue
            https = number in HTTPS_PORTS or "https" in service or "ssl" in service
            scheme = "https" if https else "http"
            url = f"{scheme}://{address}:{number}"
            if url not in endpoints:
                endpoints.append(url)
    return endpoints
