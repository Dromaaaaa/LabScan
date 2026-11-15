# LabScan

Console web de reconnaissance pour environnements de lab (machines locales, TryHackMe, Hack The Box, Root-Me).
Elle orchestre des outils en ligne de commande, parse leurs résultats, les affiche et garde un historique des scans.

## Fonctionnalités

- Interface web : lancement de scans, historique, vue détaillée, sortie brute, export JSON
- Six modules de reconnaissance et de détection :

| Module | Rôle | Phase |
|---|---|---|
| `nmap` | ports, services, scripts NSE | découverte réseau |
| `whatweb` | technologies web | énumération |
| `gobuster` | dossiers et fichiers cachés | énumération web |
| `nikto` | configuration et en-têtes serveur | détection |
| `nuclei` | vulnérabilités connues (templates) | détection |
| `theharvester` | OSINT passif (emails, sous-domaines) | reconnaissance |

- Chaîne automatique : nmap repère les services HTTP, puis whatweb et nikto sont lancés sur chacun
- Export de chaque scan et de chaque chaîne en PDF (rapport mis en page) ou en JSON
- Contrôle de périmètre : toute cible hors de `scope.json` est refusée avant exécution
- Exécution asynchrone, 2 scans en parallèle maximum, délai max d'une heure par scan
- Aucune option libre transmise aux outils : seuls des profils prédéfinis sont exécutables

Les modules détectent et énumèrent ; ils ne contiennent aucune routine d'exploitation.

La gestion complète du périmètre (ajout et retrait d'adresses ou de domaines) est détaillée dans `SCOPE.md`.

## Installation

Prérequis : Python 3.10+. Les outils externes sont optionnels, chacun apparaît
comme « non installé » dans l'interface tant que son binaire est absent.

```bash
# Debian / Ubuntu / Kali
sudo apt install nmap whatweb gobuster nikto dirb

# nuclei (binaire Go)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# theHarvester
pipx install theHarvester

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

L'export PDF repose sur reportlab, inclus dans `requirements.txt`.

Les wordlists de gobuster pointent par défaut vers `/usr/share/dirb/wordlists/`
(paquet `dirb`). Sur Kali, `seclists` offre des listes plus complètes : adapter
les chemins dans `backend/scanners/gobuster.py`.

## Lancement

```bash
uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Interface : http://127.0.0.1:8000
Documentation de l'API : http://127.0.0.1:8000/docs

L'application exécute des commandes sur la machine hôte : elle doit rester liée à `127.0.0.1` et ne jamais être exposée sur un réseau.

## Périmètre (`scope.json`)

Généré au premier lancement avec les plages privées (RFC 1918) et la boucle locale :

```json
{
  "cidrs": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  "hosts": []
}
```

| Type de cible | Règle appliquée |
|---|---|
| IP | doit appartenir à un réseau de `cidrs` |
| Plage CIDR | doit être entièrement incluse dans un réseau de `cidrs` |
| Nom d'hôte ou URL | listé dans `hosts`, ou toutes ses adresses résolues sont dans `cidrs` |

Les machines TryHackMe et Hack The Box sont joignables via VPN sur des adresses en `10.x.x.x`, déjà couvertes.
Un hôte public (challenge Root-Me par exemple) s'ajoute dans `hosts` uniquement si la plateforme autorise explicitement le scan de cette cible.

### Deux niveaux de contrôle

| Type d'outil | Contrôle appliqué |
|---|---|
| Scan réseau (nmap, whatweb, gobuster, nikto, nuclei) | la cible doit être dans le périmètre réseau (`cidrs` / `hosts`) |
| OSINT passif (theharvester) | le domaine doit figurer dans `hosts`, ou en être un sous-domaine |

theHarvester n'envoie rien à la cible : il interroge des sources publiques. Il est donc contrôlé par l'allowlist de domaines plutôt que par le périmètre réseau, et un domaine à analyser doit être ajouté explicitement dans `hosts`.

## Profils nmap

| Profil | Arguments |
|---|---|
| Ports courants | `-T4 -F` |
| Découverte d'hôtes | `-sn` |
| Services et versions | `-T4 -sV --version-light` |
| Services + scripts NSE | `-T4 -sV -sC` |
| Tous les ports TCP | `-T4 -p-` |

Sans droits root, nmap effectue un scan TCP connect au lieu d'un scan SYN, et l'adresse MAC des hôtes n'est pas remontée.

## Architecture

```
labscan/
├── backend/
│   ├── main.py          API FastAPI, file d'exécution, service du front
│   ├── scope.py         contrôle de périmètre
│   ├── pipeline.py      chaîne nmap -> whatweb + nikto
│   ├── report.py        génération des rapports PDF
│   ├── db.py            historique SQLite (labscan.db)
│   └── scanners/
│       ├── base.py          classe BaseScanner (interface commune)
│       ├── nmap.py          module nmap (parsing XML)
│       ├── whatweb.py       module whatweb (parsing JSON)
│       ├── gobuster.py      module gobuster (parsing texte)
│       ├── nikto.py         module nikto (parsing texte)
│       ├── nuclei.py        module nuclei (parsing JSONL)
│       ├── theharvester.py  module OSINT (hors périmètre réseau)
│       └── __init__.py      registre des scanners
├── frontend/            interface (HTML, CSS, JavaScript sans dépendance)
├── scope.json
└── requirements.txt
```

## Ajouter un outil

1. Créer `backend/scanners/<outil>.py` avec une classe héritant de `BaseScanner`
2. Définir `name`, `binary`, `description` et `presets`
3. Implémenter `build_command(target, options)` qui renvoie la liste d'arguments
4. Implémenter `parse(stdout, stderr)` qui renvoie un dictionnaire
5. Ajouter l'instance dans `SCANNERS` (`backend/scanners/__init__.py`)
6. Ajouter une fonction de rendu dans `RENDERERS` (`frontend/app.js`) ; à défaut, le résultat s'affiche en JSON brut

## API

| Méthode | Route | Rôle |
|---|---|---|
| GET | `/api/tools` | outils, disponibilité, profils |
| GET | `/api/scope` | périmètre actif |
| POST | `/api/scans` | lancer un scan `{tool, target, preset, ports}` |
| GET | `/api/scans` | historique |
| GET | `/api/scans/{id}` | détail et résultat |
| GET | `/api/scans/{id}/export` | export JSON |
| GET | `/api/scans/{id}/pdf` | export PDF |
| DELETE | `/api/scans/{id}` | suppression |
| POST | `/api/pipelines` | lancer une chaîne `{target}` |
| GET | `/api/pipelines` | liste des chaînes |
| GET | `/api/pipelines/{id}` | détail d'une chaîne et de ses étapes |
| GET | `/api/pipelines/{id}/pdf` | export PDF de la chaîne |
| DELETE | `/api/pipelines/{id}` | suppression |
