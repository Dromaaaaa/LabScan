"""Module nmap : lancement via presets, parsing de la sortie XML (-oX -)."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from .base import BaseScanner


class NmapScanner(BaseScanner):
    name = "nmap"
    binary = "nmap"
    description = "Découverte d'hôtes, scan de ports, détection de services"
    presets = {
        "quick": {"label": "Ports courants (top 100)", "args": ["-T4", "-F"]},
        "ping": {"label": "Découverte d'hôtes (pas de scan de ports)", "args": ["-sn"]},
        "services": {"label": "Services et versions", "args": ["-T4", "-sV", "--version-light"]},
        "scripts": {"label": "Services + scripts NSE par défaut", "args": ["-T4", "-sV", "-sC"]},
        "full": {"label": "Tous les ports TCP (lent)", "args": ["-T4", "-p-"]},
    }

    def build_command(self, target: str, options: dict) -> list[str]:
        args = self.preset_args(options)
        ports = self.validate_ports(options.get("ports"))
        if ports and options.get("preset") != "ping":
            # -p remplace -F / -p- du preset
            args = [a for a in args if a not in ("-F", "-p-")] + ["-p", ports]
        return [self.binary, *args, "-oX", "-", "--", target]

    def parse(self, stdout: str, stderr: str) -> dict:
        start = stdout.find("<?xml")
        if start == -1:
            return {"hosts": [], "summary": {}}
        root = ET.fromstring(stdout[start:])

        hosts = [self._parse_host(h) for h in root.findall("host")]
        finished = root.find("runstats/finished")
        hosts_stats = root.find("runstats/hosts")

        return {
            "hosts": hosts,
            "summary": {
                "args": root.get("args"),
                "nmap_version": root.get("version"),
                "elapsed": finished.get("elapsed") if finished is not None else None,
                "hosts_up": int(hosts_stats.get("up", 0)) if hosts_stats is not None else 0,
                "hosts_total": int(hosts_stats.get("total", 0)) if hosts_stats is not None else 0,
                "open_ports": sum(
                    1 for h in hosts for p in h["ports"] if p["state"] == "open"
                ),
            },
        }

    @staticmethod
    def _parse_host(host: ET.Element) -> dict:
        status = host.find("status")
        addresses = {a.get("addrtype"): a.get("addr") for a in host.findall("address")}
        mac_el = next((a for a in host.findall("address") if a.get("addrtype") == "mac"), None)

        ports = []
        for p in host.findall("ports/port"):
            state = p.find("state")
            svc = p.find("service")
            ports.append({
                "port": int(p.get("portid")),
                "protocol": p.get("protocol"),
                "state": state.get("state") if state is not None else "unknown",
                "reason": state.get("reason") if state is not None else None,
                "service": svc.get("name") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
                "extrainfo": svc.get("extrainfo") if svc is not None else None,
                "cpe": [c.text for c in p.findall("service/cpe")],
                "scripts": [
                    {"id": s.get("id"), "output": (s.get("output") or "").strip()}
                    for s in p.findall("script")
                ],
            })

        os_matches = [
            {"name": m.get("name"), "accuracy": int(m.get("accuracy", 0))}
            for m in host.findall("os/osmatch")
        ]

        return {
            "status": status.get("state") if status is not None else "unknown",
            "ipv4": addresses.get("ipv4"),
            "ipv6": addresses.get("ipv6"),
            "mac": addresses.get("mac"),
            "vendor": mac_el.get("vendor") if mac_el is not None else None,
            "hostnames": [h.get("name") for h in host.findall("hostnames/hostname")],
            "ports": sorted(ports, key=lambda x: (x["protocol"], x["port"])),
            "os": os_matches[:3],
            "host_scripts": [
                {"id": s.get("id"), "output": (s.get("output") or "").strip()}
                for s in host.findall("hostscript/script")
            ],
        }
