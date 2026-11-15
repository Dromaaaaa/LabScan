"""Génération de rapports PDF (scan isolé ou chaîne) avec reportlab."""

from __future__ import annotations

from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

INK = colors.HexColor("#1b2127")
MUTED = colors.HexColor("#5b6670")
ACCENT = colors.HexColor("#1f9d57")
LINE = colors.HexColor("#d4dae0")
SEV = {
    "critical": colors.HexColor("#c0392b"), "high": colors.HexColor("#d35400"),
    "medium": colors.HexColor("#b8860b"), "low": colors.HexColor("#2d7dd2"),
    "info": MUTED,
}

_ss = getSampleStyleSheet()
H1 = ParagraphStyle("H1", parent=_ss["Heading1"], textColor=INK, fontSize=18, spaceAfter=2)
H2 = ParagraphStyle("H2", parent=_ss["Heading2"], textColor=INK, fontSize=12, spaceBefore=10, spaceAfter=4)
META = ParagraphStyle("META", parent=_ss["Normal"], textColor=MUTED, fontSize=8.5, fontName="Courier")
BODY = ParagraphStyle("BODY", parent=_ss["Normal"], textColor=INK, fontSize=9, leading=13)
CODE = ParagraphStyle("CODE", parent=_ss["Normal"], textColor=INK, fontSize=8, fontName="Courier",
                      backColor=colors.HexColor("#f2f4f6"), borderPadding=5, leading=11)
CELL = ParagraphStyle("CELL", parent=_ss["Normal"], fontSize=8, leading=11)


def _esc(value) -> str:
    return (str(value if value is not None else "")
            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _table(headers: list[str], rows: list[list], widths: list[float]):
    data = [[Paragraph(f"<b>{h}</b>", CELL) for h in headers]]
    data += [[c if hasattr(c, "wrap") else Paragraph(_esc(c), CELL) for c in r] for r in rows]
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("LINEBELOW", (0, 0), (-1, 0), 0.6, INK),
        ("LINEBELOW", (0, 1), (-1, -2), 0.3, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _scan_flowables(scan: dict, width: float) -> list:
    out = [Paragraph(f"{_esc(scan['tool'])} — {_esc(scan['target'])}", H2),
           Paragraph(f"#{scan['id']} · profil {_esc(scan.get('preset'))} · {_esc(scan['status'])}", META)]
    result = scan.get("result")
    if not result:
        out.append(Paragraph("Aucun résultat enregistré.", BODY))
        return out
    if result.get("error"):
        out.append(Paragraph(f"<b>Erreur :</b> {_esc(result['error'])}", BODY))
    out.append(Spacer(1, 3))
    out.append(Paragraph(_esc(" ".join(result.get("command", []))), CODE))
    out.append(Spacer(1, 5))

    parsed = result.get("parsed", {})
    out += _tool_body(scan["tool"], parsed, width)
    return out


def _tool_body(tool: str, parsed: dict, width: float) -> list:
    if tool == "nmap":
        out = []
        for h in parsed.get("hosts", []):
            if h.get("status") != "up" and not h.get("ports"):
                continue
            name = h.get("ipv4") or h.get("ipv6") or "?"
            names = ", ".join(h.get("hostnames") or [])
            out.append(Paragraph(f"<b>{_esc(name)}</b> {_esc(names)}", BODY))
            rows = [[f"{p['port']}/{p['protocol']}", p["state"], p.get("service") or "",
                     " ".join(x for x in (p.get("product"), p.get("version")) if x)]
                    for p in h.get("ports", []) if p["state"] == "open"]
            if rows:
                out.append(_table(["Port", "État", "Service", "Version"], rows,
                                  [25 * mm, 20 * mm, 35 * mm, width - 80 * mm]))
            out.append(Spacer(1, 4))
        return out or [Paragraph("Aucun hôte actif.", BODY)]

    if tool == "whatweb":
        out = []
        for s in parsed.get("sites", []):
            out.append(Paragraph(f"<b>{_esc(s['url'])}</b> (HTTP {_esc(s.get('http_status'))})", BODY))
            techs = ", ".join(
                t["name"] + (f" [{', '.join(t['details'])}]" if t["details"] else "")
                for t in s.get("technologies", []))
            out.append(Paragraph(_esc(techs), BODY))
            out.append(Spacer(1, 4))
        return out or [Paragraph("Aucune technologie identifiée.", BODY)]

    if tool == "gobuster":
        rows = [[f["path"], f["status"], f.get("size") or "", f.get("redirect") or ""]
                for f in parsed.get("found", [])]
        return [_table(["Chemin", "Statut", "Taille", "Redirige vers"], rows,
                       [width - 90 * mm, 20 * mm, 25 * mm, 45 * mm])] if rows \
            else [Paragraph("Aucun chemin trouvé.", BODY)]

    if tool == "nikto":
        out = []
        if parsed.get("server"):
            out.append(Paragraph(f"<b>Serveur :</b> {_esc(parsed['server'])}", BODY))
        for f in parsed.get("findings", []):
            out.append(Paragraph("• " + _esc(f), BODY))
        return out or [Paragraph("Aucune observation.", BODY)]

    if tool == "nuclei":
        rows = []
        for f in parsed.get("findings", []):
            badge = Paragraph(
                f"<font color='{SEV.get(f['severity'], MUTED).hexval()[2:]}'><b>{_esc(f['severity'])}</b></font>",
                CELL)
            rows.append([badge, Paragraph(f"{_esc(f.get('name') or f['template'])}", CELL),
                         Paragraph(_esc(f.get("matched_at")), CELL)])
        return [_table(["Sévérité", "Détection", "Cible"], rows,
                       [22 * mm, width - 82 * mm, 60 * mm])] if rows \
            else [Paragraph("Aucune détection.", BODY)]

    if tool == "theharvester":
        out = []
        if parsed.get("emails"):
            out.append(Paragraph("<b>Emails :</b> " + _esc(", ".join(parsed["emails"])), BODY))
        if parsed.get("hosts"):
            out.append(Paragraph("<b>Hôtes :</b> " + _esc(", ".join(parsed["hosts"])), BODY))
        return out or [Paragraph("Aucun résultat OSINT.", BODY)]

    return [Paragraph(_esc(str(parsed))[:2000], BODY)]


def _document(title: str, subtitle: str, flowables: list) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title=title,
                            leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm)
    width = doc.width
    story = [Paragraph("LabScan", ParagraphStyle("brand", parent=META, textColor=ACCENT,
                                                 fontSize=9, alignment=TA_LEFT)),
             Paragraph(title, H1), Paragraph(subtitle, META),
             HRFlowable(width="100%", thickness=0.6, color=INK, spaceBefore=6, spaceAfter=8)]
    story += flowables
    doc.build(story)
    return buf.getvalue()


def scan_pdf(scan: dict) -> bytes:
    sub = f"Scan #{scan['id']} · {scan['tool']} · {scan.get('created_at', '')[:19].replace('T', ' ')}"
    return _document(scan["target"], sub, _scan_flowables(scan, 174 * mm))


def pipeline_pdf(pipeline: dict) -> bytes:
    scans = pipeline.get("scans", [])
    sub = (f"Chaîne #{pipeline['id']} · {len(scans)} étapes · "
           f"{pipeline.get('created_at', '')[:19].replace('T', ' ')}")
    flow = [Paragraph(f"Cible : {_esc(pipeline['target'])} · statut {_esc(pipeline['status'])}", BODY),
            Spacer(1, 4)]
    for scan in scans:
        flow += _scan_flowables(scan, 174 * mm)
        flow.append(HRFlowable(width="100%", thickness=0.3, color=LINE, spaceBefore=8, spaceAfter=4))
    return _document(f"Chaîne — {pipeline['target']}", sub, flow)
