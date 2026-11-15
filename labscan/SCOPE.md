# Gestion du périmètre (scope)

Le périmètre définit les cibles que LabScan accepte de scanner. Toute cible
hors périmètre est refusée avant qu'aucun outil ne soit lancé, avec un code
HTTP 403 et un message explicatif. C'est le garde-fou qui garantit que l'outil
ne touche que des machines autorisées (lab local, VPN TryHackMe ou Hack The Box,
cible de CTF explicitement ouverte au scan).

## Le fichier scope.json

Le fichier `scope.json` se trouve à la racine du projet. Il est créé
automatiquement au premier lancement avec cette valeur par défaut :

```json
{
  "cidrs": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  "hosts": []
}
```

Deux listes le composent :

| Clé | Contenu | Rôle |
|-----|---------|------|
| `cidrs` | plages réseau au format CIDR | adresses et plages autorisées au scan réseau |
| `hosts` | noms de domaine ou d'hôte | cibles nommées autorisées (scan réseau et OSINT) |

Les valeurs par défaut correspondent à la boucle locale (`127.0.0.0/8`) et aux
trois plages d'adresses privées définies par la RFC 1918. Les machines
TryHackMe et Hack The Box, jointes par VPN, reçoivent des adresses dans ces
plages (le plus souvent en `10.x.x.x`), elles sont donc déjà couvertes.

## Prise en compte des modifications

Le fichier est relu à chaque scan. Une modification de `scope.json` est donc
active immédiatement, sans redémarrer le serveur. Les plages actives sont
affichées en haut de l'interface, ce qui permet de vérifier d'un coup d'oeil
ce qui est autorisé.

## Deux niveaux de contrôle

Le contrôle appliqué dépend du type d'outil.

| Type d'outil | Outils concernés | Contrôle |
|--------------|------------------|----------|
| Scan réseau | nmap, whatweb, gobuster, nikto, nuclei | la cible doit être dans le périmètre réseau (`cidrs` ou `hosts`) |
| OSINT passif | theharvester | le domaine doit figurer dans `hosts`, ou en être un sous-domaine |

theHarvester n'envoie aucun paquet à la cible : il interroge des sources
publiques. Il est donc contrôlé par la liste `hosts` plutôt que par les plages
réseau, ce qui évite d'autoriser au passage le scan de n'importe quel domaine
public.

## Règles de vérification

Selon la forme de la cible saisie, la règle appliquée change.

| Forme de la cible | Exemple | Condition d'acceptation |
|-------------------|---------|-------------------------|
| Adresse IP | `192.168.56.101` | appartient à une plage de `cidrs` |
| Plage CIDR | `10.10.0.0/24` | entièrement incluse dans une plage de `cidrs` |
| Nom d'hôte ou URL | `box.htb`, `http://10.10.11.5` | présent dans `hosts`, ou toutes ses adresses résolues sont dans `cidrs` |

Pour un nom d'hôte absent de `hosts`, la résolution DNS est effectuée et chaque
adresse obtenue est vérifiée. Si une seule adresse sort du périmètre, la cible
est refusée. Cela empêche qu'un nom de domaine pointant vers une adresse
publique passe à travers les plages privées.

## Ajouter une cible

### Ajouter une adresse ou une plage

Pour autoriser une adresse isolée, l'ajouter sous forme de plage `/32` :

```json
{
  "cidrs": [
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "203.0.113.42/32"
  ],
  "hosts": []
}
```

Pour autoriser un sous-réseau complet, ajouter la plage correspondante :

```json
"cidrs": ["192.168.56.0/24"]
```

### Ajouter un hôte nommé

Pour une machine ou un domaine désigné par son nom, l'ajouter dans `hosts` :

```json
{
  "cidrs": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  "hosts": ["target.htb", "challenge01.root-me.org"]
}
```

Un hôte présent dans `hosts` est accepté directement, sans vérification de son
adresse résolue. Cette entrée est à réserver aux cibles explicitement
autorisées par la plateforme concernée.

### Autoriser l'OSINT sur un domaine

theHarvester exige que le domaine figure dans `hosts`. Ajouter le domaine
racine suffit à couvrir ses sous-domaines :

```json
"hosts": ["example.com"]
```

Cette entrée autorise alors `example.com`, `www.example.com`, `mail.example.com`
et tout autre sous-domaine.

## Retirer une cible

Pour retirer une autorisation, supprimer la ligne correspondante de `cidrs` ou
de `hosts`, puis enregistrer le fichier. Le retrait est pris en compte dès le
scan suivant. Une cible retirée est de nouveau refusée, y compris si elle avait
été scannée auparavant.

Après une session sur une cible temporaire (machine de CTF, adresse de VPN
attribuée pour la durée d'un exercice), il est recommandé de retirer l'entrée
une fois l'exercice terminé, afin de conserver un périmètre réduit au strict
nécessaire.

## Recommandations

Garder le périmètre aussi restreint que possible limite le risque de scanner
une cible par erreur.

- N'ajouter une plage ou un hôte qu'au moment d'en avoir besoin, et le retirer
  ensuite.
- Ne jamais ajouter de plage publique large. Une entrée comme `0.0.0.0/0`
  autoriserait l'ensemble d'Internet et retirerait toute protection.
- Préférer une entrée `/32` pour une adresse unique plutôt qu'une plage étendue.
- Vérifier, avant d'ajouter un hôte public, que la plateforme autorise
  explicitement le scan de cette cible. Scanner une machine sans autorisation
  est illégal, indépendamment de l'outil employé.
- Conserver les plages privées par défaut couvre déjà le lab local et les VPN
  des plateformes d'entraînement.

## Validation d'une entrée

Une plage ou une adresse mal formée est rejetée au chargement du fichier et
provoque une erreur de lecture. En cas de doute sur une entrée, lancer un scan
de test sur une cible connue et vérifier le message retourné : une cible
acceptée démarre le scan, une cible refusée affiche la raison du refus.
