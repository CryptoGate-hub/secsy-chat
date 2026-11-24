<p align="center">
  <img src="docs/logo.jpg" alt="Cryptogate" width="200">
</p>

<h1 align="center">Secsy Chat</h1>

<p align="center">
  Messagerie instantanée <b>chiffrée</b> en Python : serveur TCP multi-thread, client en terminal (TUI), canaux, messages privés chiffrés de bout en bout, intégrité signée.
</p>

> Projet intégratif **UE14 – Intégration de la sécurité 1** (HELMo, Bachelier en informatique, orientation Sécurité des systèmes).
> **Équipe** : Youssef Benchakroun (chef de projet), Abdul Rahman Alahmad, Nouh Fache.
> **Audit de sécurité** : Youssef Benchakroun (audit et corrections principales) ; failles complémentaires découvertes par Abdul Rahman Alahmad et corrigées par Nouh Fache.
> Le projet a fait l'objet d'un **audit de sécurité** : les failles trouvées et corrigées sont documentées dans [docs/AUDIT_SECURITE.md](docs/AUDIT_SECURITE.md).

## Ce que fait le projet

- **Canaux publics et privés** (secret protégé par Argon2), création, entrée, sortie, expulsion (temporaire ou définitive) et suppression par le créateur.
- **Messages privés** entre utilisateurs, chiffrés de bout en bout (seul le destinataire peut les lire).
- **Historique** : les 20 derniers messages du canal et des messages privés sont restaurés à la connexion.
- **Interface en terminal** (TUI) avec liste des canaux et des utilisateurs connectés.
- Un assistant IA (Gemini) en **bonus optionnel**, isolé dans un seul fichier (voir [Assistant IA](#assistant-ia-optionnel)).

## Sécurité en un coup d'œil

| Couche | Mécanisme |
|---|---|
| Mots de passe | Hachage **Argon2** côté serveur |
| Clé de transport | **Diffie-Hellman** (groupe RFC 3526, 2048 bits), établi *avant* tout identifiant |
| Identité du serveur | Le serveur **signe le Diffie-Hellman** avec sa clé RSA (`server.key`) ; le client vérifie avec `server.pub` avant d'envoyer son mot de passe |
| Transport client ↔ serveur | **AES-256-GCM** ; type d'échange, sens et **numéro de trame** authentifiés (une trame rejouée est refusée) |
| Contenu des messages | Clé **ChaCha20-Poly1305** unique par message, chiffrée avec la clé publique **RSA-2048** du destinataire |
| Intégrité et authenticité | Somme **SHA-256** (émetteur, destinataire, horodatage, charge) signée en **RSA**, vérifiée par le serveur **et** le destinataire |
| Authentification | Mot de passe **+** signature RSA d'un horodatage (clé publique enregistrée à la première connexion) ; **essais limités** (5 par pseudo, puis attente croissante) |
| Protocole | En-tête de 11 octets, schémas **JSON Schema** pour chaque message, instruction et évènement |
| Limites anti-abus | Taille d'un message plafonnée (16 Ko chiffré), 10 messages / 10 s par connexion, 5 canaux créés / minute par utilisateur, 10 comptes créés / 10 min par IP, essais de mot de passe de canal limités, 10 connexions max par IP |

**Ce que le serveur peut lire.** Les messages privés sont chiffrés avec la clé publique du destinataire : le serveur ne peut pas les lire tant qu'il fournit la bonne clé (voir les limites connues). Les messages de canal sont chiffrés avec la clé du canal, que le serveur génère, stocke et distribue aux membres (c'est le schéma imposé par l'énoncé) : le serveur *peut* donc les déchiffrer. Dans les deux cas, il vérifie les signatures avant de stocker et de relayer.
Détails : [docs/PROTOCOLE.md](docs/PROTOCOLE.md). Limites connues et écarts : fin de [docs/AUDIT_SECURITE.md](docs/AUDIT_SECURITE.md).

## Installation

Prérequis : **Python 3.10+**.

```powershell
git clone https://github.com/CryptoGate-hub/secsy-chat.git
cd secsy-chat
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # Linux / macOS : source .venv/bin/activate
pip install -r requirements.txt
```

> Sous Windows, si `pip` est bloqué (« Une stratégie de contrôle d'application a bloqué ce fichier »), utilise `python -m pip install -r requirements.txt`.

**Interface TUI.** Le client utilise la bibliothèque `secsychat-tui` fournie par HELMo dans le cadre du cours (elle n'est pas redistribuée ici). Installe-la depuis la source fournie par l'école :

```powershell
pip install <chemin vers secsychat_tui-0.1.0-py3-none-any.whl>
python -c "import secsychat_tui; print('TUI OK')"
```

## Lancement

```powershell
# Terminal 1 : le serveur (port 4000)
python server.py

# Terminal 2 et 3 : deux clients
python client.py 127.0.0.1 4000 alice
python client.py 127.0.0.1 4000 bobby
```

Au premier démarrage, le serveur crée sa clé d'identité `server.key` (à garder secrète) et écrit `server.pub`, puis affiche son **empreinte**. Un client lancé dans le même dossier la trouve tout seul. Sur un autre PC, copie `server.pub` à côté de `client.py` ; sinon, à la première connexion, le client enregistre la clé reçue et affiche son empreinte : compare-la à celle du serveur (même principe que SSH).

À la **première connexion** d'un pseudo (3 à 20 caractères : lettres, chiffres, `_`, `-`, `.`), une paire de clés RSA est créée dans `<pseudo>.key` et le compte est créé avec le mot de passe saisi (8 caractères minimum, sans écho).
Conserve ton fichier `.key` : sans lui, le compte n'est plus accessible (voulu). Ne le partage jamais et ne le commite jamais (il est dans le `.gitignore`).

## Commandes

| Commande | Effet |
|---|---|
| `/commands` | Liste des commandes |
| `/users` (`/who`), `/status` (`/where`) | Utilisateurs connectés, canal actif |
| `/create <nom> [mdp]` | Crée un canal (privé si un mot de passe est donné, 6 caractères minimum) |
| `/join <nom> [mdp]` | Rejoint un canal |
| `/leave` | Quitte le canal actuel (retour dans `#general`) |
| `/kick <canal> <membre> [secondes]` | Expulse un membre : définitivement, ou pour une durée (créateur du canal uniquement) |
| `/delete <nom>` | Supprime un canal (créateur uniquement) |
| `/pm <pseudo> <message>` | Message privé chiffré de bout en bout |

## Structure

```
secsy-chat/
├── server.py          # Serveur TCP multi-thread
├── client.py          # Client TUI
├── ai_assistant.py    # Assistant IA Gemini (optionnel)
├── tests/             # Tests de sécurité de bout en bout (serveur réel + clients sans interface)
├── LICENSE            # Licence MIT
├── common/
│   ├── security.py    # Cryptographie (Argon2, DH, AES-GCM, ChaCha20, RSA, SHA-256, NanoId)
│   ├── network.py     # Sockets : en-tête de 11 octets
│   ├── database.py    # Accès SQLite
│   ├── data.py        # Utilisateurs, canaux, messages
│   ├── message.py, statement.py, event.py, exchange.py   # Types d'échanges + schémas JSON
└── docs/              # Documentation technique et audit de sécurité
```

## Assistant IA (optionnel)

`/ia <question>`, `/ia pro <question>` et `@whitehat <question>` interrogent Gemini (`/ia2 <fichiers> [consigne]` analyse des fichiers). Un message normal n'est **jamais** envoyé à l'IA. **Attention : ce message part en clair vers Google et sort donc du chiffrement de bout en bout.** Le client l'indique avant le premier usage, et seul le message adressé à l'IA est envoyé (jamais l'historique du canal).

Mets ta clé (gratuite : https://aistudio.google.com/api-keys) dans un fichier `gemini.key` à côté de `client.py`, ou dans la variable d'environnement `GEMINI_API_KEY`. Le fichier est ignoré par git (`*.key`) : la clé n'est jamais publiée.

Sans clé, l'IA se désactive toute seule et le client explique pourquoi. Pour la couper définitivement : `AI_ENABLED = False` dans `ai_assistant.py`.

## Tests

```powershell
python tests/test_securite.py
```
Le script lance un vrai serveur dans un dossier temporaire (port 4000 libre requis) et rejoue les attaques corrigées pendant l'audit : rejeu de trames, essais de mot de passe de canal, message géant, rafale de messages, kick, création en masse. Environ une minute ; un `FAIL` signifie qu'une protection a régressé.

## Limites connues

Projet pédagogique, à ne pas utiliser en production. En particulier : le client ne mémorise pas les clés publiques des autres utilisateurs d'une session à l'autre : un serveur malveillant pourrait donc fournir sa propre clé à la place de celle d'un destinataire et lire un message privé (même principe qu'un serveur Signal sans vérification des numéros de sécurité) ; le serveur détient la clé privée de chaque canal (schéma imposé par l'énoncé) et peut donc lire les messages de canal ; et si un PC se connecte pour la toute première fois à travers un attaquant **sans** avoir `server.pub`, il enregistre la mauvaise clé (comme avec SSH). Pas de confidentialité persistante pour les messages : quelqu'un qui obtient `<pseudo>.key` peut déchiffrer les messages privés qu'il aurait enregistrés avant (schéma RSA + clé par message imposé par l'énoncé ; le transport, lui, utilise des clés éphémères). Ce fichier est stocké en clair (`chmod 600` n'a pas d'effet sous Windows). Liste complète dans [docs/AUDIT_SECURITE.md](docs/AUDIT_SECURITE.md).
