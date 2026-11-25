# SECSY Chat — Documentation technique

> Architecture, sécurité et protocole réseau. Pour démarrer rapidement, voir le [README](../README.md).

---

## Table des matières

- [Présentation](#présentation)
- [Architecture](#architecture)
- [Fonctionnalités](#fonctionnalités)
- [Sécurité](#sécurité)
- [Installation](#prérequis--installation)
- [Lancement](#lancement)
- [Commandes disponibles](#commandes-disponibles)
- [Structure du projet](#structure-du-projet)
- [Schéma de base de données](#schéma-de-base-de-données)
- [Protocole réseau](#protocole-réseau)
- [Types d'échanges](#types-déchanges)
- [Assistant IA intégré](#assistant-ia-intégré)
- [Tests](#tests)

---

## Présentation

**SECSY Chat** est un système de messagerie en temps réel développé dans le cadre d'un projet académique (UE14). Il met en œuvre une pile de sécurité complète couvrant l'ensemble des itérations du projet :

- **Authentification** par hash Argon2id
- **Échange de clé** Diffie-Hellman (groupe RFC 3526, 2048 bits) pour dériver la clé de transport
- **Chiffrement symétrique** AES-256-GCM pour le transport réseau
- **Chiffrement E2EE par message** via ChaCha20-Poly1305 + RSA-2048-OAEP
- **Intégrité** SHA-256 avec signature RSA PKCS#1 v1.5
- **Identité du serveur** : le Diffie-Hellman est signé par la clé RSA du serveur (anti homme du milieu)
- **Anti-rejeu** : numéro de trame dans AES-GCM, timestamp signé RSA à la connexion (itération 9), horodatage des messages contrôlé

L'interface graphique est une TUI (Text User Interface) construite sur le paquet `secsychat-tui` (Textual), fourni par HELMo.

---

## Architecture

```
┌────────────┐        TCP/4000        ┌─────────────────┐
│  client.py │ ◄────────────────────► │   server.py     │
│  (TUI)     │   JSON chiffré (E2EE)  │  (multi-thread) │
└────────────┘                        └────────┬────────┘
                                               │
                                        SQLite (messenger.db)
                                               │
                                  ┌────────────┴────────────┐
                                  │       common/            │
                                  │  security  database      │
                                  │  data      network       │
                                  │  exchange  message       │
                                  │  event     statement     │
                                  └──────────────────────────┘
```

Le serveur gère chaque connexion client dans un **thread dédié**. Les sections critiques sont protégées par des verrous : le dictionnaire des clients (`clients_lock`), la base SQLite (`database._lock`) et l'envoi vers chaque client (`TransportCipher.lock`, qui garde les trames dans l'ordre de leurs numéros). Le client utilise un **thread de réseau séparé** (`network_worker`) pour ne pas bloquer l'interface TUI.

---

## Fonctionnalités

### Messagerie

- Canaux publics et privés (protégés par mot de passe)
- Messages privés (PM) chiffrés de bout en bout
- Affichage des 20 derniers messages à la connexion ou lors du changement de canal
- Délivrance des messages aux seuls membres du canal actif
- Persistance de tous les messages (canaux et privés) en base SQLite

### Gestion des canaux

- Créer, rejoindre, quitter un canal
- Expulser un membre : `/kick <canal> <membre>` (permanent) ou `/kick <canal> <membre> <secondes>` (temporaire) ; l'expulsion est enregistrée en base (table `channel_ban`) et survit au redémarrage du serveur
- Supprimer un canal : `/delete <nom>` — réservé au créateur
- Canaux système protégés contre suppression et kick : `#general`, `#dev`, `#random`
- Auto-join sur `#general` à chaque connexion
- Redirection automatique vers `#general` en cas de kick ou suppression du canal actif
- La liste des canaux affiche `# canal` pour les publics et `🔒 canal` pour les privés

### Utilisateurs

- Création de compte à la première connexion (mot de passe saisi sans écho, minimum 8 caractères)
- Authentification par mot de passe à chaque connexion suivante ; après 5 échecs sur un pseudo (ou 20 depuis une même adresse IP), attente de 30 s, puis 60 s, 120 s… (15 min maximum)
- Pseudos uniques à la casse près : `bob` est refusé si `Bob` existe déjà
- Suivi de la dernière activité (`last_activity_at`) mis à jour à chaque échange ; l'instruction `UPDATE_USER` (envoyée au plus une fois par minute) la diffuse aux autres clients (`USER_UPDATED`)
- Diffusion en temps réel de la liste des utilisateurs connectés
- Liste des utilisateurs connectés : `/who`

### Persistance client

- La clé RSA privée est persistée dans `<pseudo>.key` et le canal sélectionné (son identifiant) dans `<pseudo>.json` (propriété `context`)
- Au démarrage, le client rejoint automatiquement le dernier canal utilisé
- Les clés RSA publiques sont transmises au serveur et persistées en base

---

## Sécurité

Le projet implémente une pile de sécurité en plusieurs couches, couvrant les itérations 3 à 9.

### 1. Authentification — Argon2id

Les mots de passe ne sont jamais stockés en clair. Ils sont hachés avec **Argon2id** (via `argon2-cffi`) côté serveur avant insertion en base. Les mots de passe des canaux privés sont également hachés avant stockage.

### 2. Échange de clé — Diffie-Hellman (RFC 3526, 2048 bits)

À chaque connexion, un échange **Diffie-Hellman** est effectué entre le client et le serveur pour dériver une **clé de transport symétrique** de 256 bits (via SHA-256). Cette clé chiffre toutes les communications de la session via AES-GCM.

Juste après l'échange, le serveur **signe les deux clés publiques DH** de la session avec sa clé d'identité RSA (`server.key`). Le client vérifie la signature avec `server.pub` **avant** d'envoyer son pseudo et son mot de passe. Sans cette étape, un attaquant placé entre les deux pouvait faire un Diffie-Hellman avec chacun et lire le mot de passe (attaque démontrée, voir l'audit). Si `server.pub` est absent, le client enregistre la clé reçue à la première connexion et affiche son empreinte (même principe que `known_hosts` de SSH).

### 3. Chiffrement du transport — AES-256-GCM

Chaque message réseau post-handshake est chiffré avec **AES-256-GCM** en utilisant la clé dérivée DH (classe `TransportCipher`). Un nonce aléatoire est généré par message. La donnée associée (AAD) contient le **type d'échange**, le **sens** (client → serveur ou serveur → client) et un **numéro de trame** propre à chaque sens. Ce numéro n'est pas envoyé : TCP garde l'ordre, les deux côtés savent lequel attendre. Une trame modifiée, rejouée ou renvoyée dans l'autre sens échoue à la vérification GCM et la connexion est coupée.

### 4. Chiffrement E2EE par message — ChaCha20-Poly1305 + RSA-2048

Pour chaque message de canal ou privé :

- Une **clé symétrique unique** (256 bits) est générée aléatoirement côté client.
- Le contenu est chiffré avec **ChaCha20-Poly1305** (nonce inclus dans le cipher_text).
- La clé symétrique est chiffrée avec la **clé publique RSA-2048 OAEP** du destinataire (canal ou utilisateur).
- Seul le détenteur de la clé privée correspondante peut déchiffrer.
- La taille du contenu en clair est également persistée (`cipher_text_size`).

Ces opérations de chiffrement et de déchiffrement sont intégralement réalisées **côté client**.

> **Précision :** pour un message privé, la clé publique est celle de l'utilisateur (le serveur n'a pas la clé privée correspondante). Pour un message de canal, c'est la clé du canal, générée et stockée par le serveur et distribuée aux membres : le serveur peut donc lire les messages de canal.

### 5. Intégrité — SHA-256 + Signature RSA PKCS#1 v1.5

Chaque message est accompagné :

- D'une **somme de contrôle SHA-256** calculée sur le corps du message (champs hors `integrity`, triés).
- D'une **signature RSA PKCS#1 v1.5** de cette somme avec la clé privée de l'expéditeur.
- Le serveur et le client vérifient tous deux la signature à la réception (clé publique RSA de l'expéditeur).

### 6. Authentification forte — Timestamp signé (itération 9)

À la fin du handshake, le client envoie un **timestamp Unix signé** avec sa clé privée RSA au format `<timestamp>|<signature_base64>`. Le serveur vérifie la signature (clé publique RSA) et que le timestamp est dans une fenêtre de ±5 minutes, protégeant contre les attaques par rejeu. La même fenêtre de ±5 minutes est appliquée à l'horodatage de **chaque message** : un message daté du futur ne peut pas rester épinglé dans l'historique.

### Résumé des algorithmes

| Couche | Algorithme | Bibliothèque |
|---|---|---|
| Hash mot de passe | Argon2id | `argon2-cffi` |
| Échange de clé transport | Diffie-Hellman (RFC 3526, 2048 bits) | stdlib |
| Identité du serveur | Signature RSA PKCS#1 v1.5 du DH | `pycryptodomex` |
| Transport | AES-256-GCM | `pycryptodomex` |
| E2EE contenu | ChaCha20-Poly1305 | `pycryptodomex` |
| Chiffrement clé symétrique | RSA-2048 OAEP | `pycryptodomex` |
| Intégrité | SHA-256 + RSA PKCS#1 v1.5 | `pycryptodomex` |
| Anti-rejeu | Numéro de trame (AAD GCM) + timestamps contrôlés | `pycryptodomex` |
| Validation schémas | JSON Schema | `jsonschema` |

---

## Prérequis & Installation

Voir le [README](../README.md#installation).

---

## Lancement

### Démarrer le serveur

```bash
python server.py
```

Le serveur écoute sur `0.0.0.0:4000`. Les logs sont écrits dans `server.log` et affichés en console. La base de données `messenger.db` est créée automatiquement au premier lancement, ainsi que les canaux système `#general`, `#dev` et `#random`, la clé d'identité `server.key` et sa clé publique `server.pub` (empreinte affichée au démarrage). Une connexion qui ne termine pas sa poignée de main en 15 s est coupée, et une même adresse IP ne peut pas ouvrir plus de 10 connexions simultanées. Un message dont le texte chiffré dépasse 16 Ko est refusé, et une connexion ne peut envoyer que 10 messages toutes les 10 secondes.

### Démarrer un client

```bash
python client.py <adresse_ip> <port> <pseudo>
```

**Exemple — connexion locale :**

```bash
python client.py 127.0.0.1 4000 Alice
```

**Première connexion :** une paire de clés RSA est créée (`<pseudo>.key`) et le compte est créé côté serveur avec le mot de passe saisi (minimum 8 caractères, demandé sans écho). La configuration du canal est persistée dans `<pseudo>.json`. Aux connexions suivantes, le serveur vérifie le mot de passe (Argon2) **et** la signature RSA d'un timestamp avec la clé publique enregistrée à la première connexion.

**Connexions suivantes :** le mot de passe est demandé en console avant le lancement de l'interface TUI. Le dernier canal actif est restauré automatiquement.

> **Remarque :** en cas d'échec de connexion, le client réessaie automatiquement toutes les 2 secondes (jusqu'à 5 tentatives).

---

## Commandes disponibles

### Navigation & Informations

| Commande | Description |
|---|---|
| `/commands` ou `/man` | Afficher la liste des commandes |
| `/users` ou `/who` | Rafraîchir et afficher les utilisateurs connectés |
| `/status` ou `/where` | Afficher le canal actif |

### Canaux

| Commande | Description |
|---|---|
| `/create <nom> [mdp]` | Créer un canal (privé si `mdp` fourni, min. 6 caractères) |
| `/join <nom> [mdp]` | Rejoindre un canal |
| `/leave` | Quitter le canal actuel (redirige vers `#general`) |

### Administration (créateur du canal uniquement)

| Commande | Description |
|---|---|
| `/kick <canal> <membre>` | Expulser définitivement un membre du canal |
| `/kick <canal> <membre> <secondes>` | Expulser temporairement (ex : `/kick projet Bob 300`) |
| `/delete <nom>` | Supprimer un canal (impossible sur les canaux système) |

### Messages privés

| Commande | Description |
|---|---|
| `/pm <pseudo> <message>` | Envoyer un message privé chiffré E2EE |

### Intelligence artificielle

| Commande | Description |
|---|---|
| `/ia <question>` | Poser une question à l'IA (Gemini Flash — rapide) |
| `/ia pro <question>` | Poser une question à l'IA (Gemini Pro — plus précis) |
| `/ia2 <fichier1> [fichier2...] [prompt]` | Analyser un ou plusieurs fichiers (`.txt`, `.pdf`, `.docx`) |
| `@whitehat <question>` | Poser une question rapide à l'IA depuis le canal |

Seuls ces messages partent vers l'IA : un message de canal ordinaire n'est jamais envoyé à Gemini.

---

## Structure du projet

```
secsy-chat/
├── server.py               # Serveur TCP multi-threadé
├── client.py               # Client TUI (Textual)
├── ai_assistant.py         # Assistant IA Gemini (bonus, optionnel, isolé)
├── requirements.txt
├── README.md
├── docs/                   # Documentation (ce fichier, audit de sécurité)
└── common/                 # Modules partagés client/serveur
    ├── __init__.py
    ├── security.py         # Toutes les primitives cryptographiques
    ├── database.py         # Couche d'accès SQLite (CRUD générique)
    ├── data.py             # Couche métier (users, channels, messages)
    ├── network.py          # TCP : send/receive avec en-tête de 11 octets + reconnexion
    ├── exchange.py         # Enum ExchangeType (MESSAGE / STATEMENT / EVENT)
    ├── message.py          # Schéma JSON des messages + validation
    ├── event.py            # Dataclass Event + validation JSON Schema
    └── statement.py        # Dataclass Statement + validation JSON Schema
```

---

## Schéma de base de données

```
user
├── id               TEXT PK
├── name             TEXT UNIQUE
├── secret           TEXT              (hash Argon2id)
├── public_key       TEXT              (clé publique RSA PEM)
├── created_at       DATETIME
└── last_activity_at DATETIME          (mis à jour automatiquement à chaque échange)

channel
├── id          TEXT PK
├── name        TEXT UNIQUE
├── secret      TEXT                   (hash Argon2id du mot de passe)
├── private_key TEXT                   (clé privée RSA PEM du canal)
├── public_key  TEXT                   (clé publique RSA PEM du canal)
├── is_private  INTEGER                (0 = public, 1 = privé)
├── owner_id    TEXT → user(id)
└── created_at  DATETIME

channel_member                         (many-to-many : channel ↔ user)
├── channel_id  TEXT → channel(id)
├── user_id     TEXT → user(id)
└── joined_at   DATETIME

channel_ban                            (expulsions)
├── channel_id  TEXT → channel(id)
├── user_id     TEXT → user(id)
└── until       INTEGER                (fin de l'expulsion, timestamp Unix ; NULL = permanente)

channel_message
├── id                                TEXT PK
├── timestamp                         TIMESTAMP
├── sender_id                         TEXT → user(id)
├── recipient_id                      TEXT → channel(id)
├── payload_cipher_text               TEXT       (ChaCha20-Poly1305, nonce inclus)
├── payload_cipher_text_size          INTEGER    (taille du contenu en clair)
├── payload_cipher_text_encrypted_key TEXT       (clé symétrique chiffrée RSA OAEP)
├── integrity_checksum                TEXT       (SHA-256 du corps)
└── integrity_signature               TEXT       (signature RSA PKCS#1 v1.5, base64)

private_message                        (structure identique à channel_message)
├── id, timestamp
├── sender_id    TEXT → user(id)
├── recipient_id TEXT → user(id)
└── ... (mêmes champs de chiffrement et d'intégrité)
```

---

## Protocole réseau

Chaque échange réseau commence par un **en-tête de 11 octets** : les 10 premiers contiennent la taille N de la charge (big-endian), le 11ᵉ le type d'échange (0 = poignée de main, 1 = message, 2 = instruction, 3 = évènement). La charge, chiffrée en AES-256-GCM, suit. Le type d'échange, le sens et le numéro de trame sont passés en donnée associée (AAD) de AES-GCM : ils ne sont pas chiffrés (le numéro n'est même pas transmis) mais toute modification ou tout rejeu est détecté. Une taille annoncée supérieure à 10 Mo est refusée.

```
┌────────────────┬──────────────┬──────────────────────────┐
│  10 octets     │  1 octet     │  N octets                │
│  taille (N)    │  type        │  charge chiffrée         │
└────────────────┴──────────────┴──────────────────────────┘
```

### Séquence de connexion (handshake complet)

```
Client                                          Serveur
  │                                                │
  │◄── pub_dh_serveur ─────────────────────────── │  ← Diffie-Hellman (groupe RFC 3526, 2048 bits)
  │── pub_dh_client ──────────────────────────────►│  ← dérivation de la clé de transport AES-GCM
  │◄── server.pub | signature(pub_dh_s, pub_dh_c) ─│  ← le client vérifie l'identité du serveur
  │── {pseudo, password} chiffré AES-GCM ─────────►│  ← authent. Argon2 ou création de compte
  │◄── "AUTH_OK|<id>" ou "AUTH_FAIL" ────────────│
  │── clé_publique_RSA (PEM) ─────────────────────►│  ← enregistrée à la 1re connexion, imposée ensuite
  │── timestamp|signature_base64 ─────────────────►│  ← validé avec la clé publique (±5 min)
  │◄── "AUTH_OK_RSA" ────────────────────────────│
  │◄── CHANNEL_JOINED (general) ─────────────────│
  │◄── LAST_MESSAGES (20 derniers) ──────────────│
  │                                                │
  │  ══ Session chiffrée AES-GCM établie ══       │
```

---

## Types d'échanges

Les échanges post-handshake sont typés selon l'enum `ExchangeType` et validés par JSON Schema. Le type est le 11ᵉ octet de l'en-tête.

### MESSAGE — contenu chiffré E2EE (client → serveur → membres du canal)

```json
{
  "timestamp": 1716000000,
  "sender":    { "id": "<NanoId 21 car.>", "name": "Alice" },
  "recipient": { "type": "CHANNEL", "id": "<id du canal>", "name": "general" },
  "payload": {
    "cipher_text": "<base64 nonce+ct+tag>",
    "cipher_text_size": 42,
    "cipher_text_encrypted_key": "<base64 clé RSA OAEP>"
  },
  "integrity": {
    "checksum": "<sha256 hex>",
    "signature": "<rsa_sig_base64>"
  }
}
```

### STATEMENT — instruction client → serveur

```json
{
  "timestamp": 1716000000,
  "payload": {
    "name": "JOIN_CHANNEL",
    "data": { "name": "dev", "secret": "" }
  }
}
```

Instructions disponibles : `GET_CHANNELS`, `GET_USERS`, `GET_LAST_MESSAGES`, `GET_USER_KEY`, `CREATE_CHANNEL`, `JOIN_CHANNEL`, `LEAVE_CHANNEL`, `KICK_CHANNEL_MEMBER`, `DELETE_CHANNEL`, `UPDATE_USER`. Les messages privés sont de vrais messages (`recipient.type = "USER"`), pas des instructions.

### EVENT — notification serveur → client(s)

```json
{
  "timestamp": 1716000000,
  "payload": {
    "name": "CHANNEL_JOINED",
    "data": { "id": "...", "name": "general", "private_key": "...", "public_key": "..." }
  }
}
```

Événements disponibles : `CHANNEL_JOINED`, `CHANNEL_CREATED`, `CHANNEL_DELETED`, `CHANNEL_LIST`, `LAST_MESSAGES`, `UPDATED_USERS`, `USER_UPDATED`, `USER_KEY`, `KICKED`, `KICK_SUCCESS`, `PM_SENT`, `SYSTEM`, `ERROR`. `CHANNEL_DELETED` d'un canal privé n'est envoyé qu'à ses membres.

---

## Assistant IA intégré

Le client embarque un assistant basé sur **Google Gemini**, avec deux profils :

- **WhiteHat-AI** (Gemini Flash) — réponses rapides via `/ia <question>`
- **WhiteHat-AI Pro** (Gemini Pro) — réponses détaillées et structurées via `/ia pro <question>`

La commande `/ia2` permet d'analyser des fichiers locaux (`.txt`, `.pdf`, `.docx`) jusqu'à 40 000 caractères au total. En cas de rate limit sur le modèle Pro, le client bascule automatiquement sur Flash.

> La clé API Gemini se donne par la variable d'environnement `GEMINI_API_KEY` (jamais dans le code) : [https://aistudio.google.com/api-keys](https://aistudio.google.com/api-keys). Sans clé, l'IA est désactivée et le reste du client fonctionne normalement. Voir aussi la section 5 de [AUDIT_SECURITE.md](AUDIT_SECURITE.md) sur ce que cette fonctionnalité implique pour le chiffrement de bout en bout.

---

## Tests

Tests de sécurité automatiques : `python tests/test_securite.py` (voir le README).

Pour tester l'ensemble des fonctionnalités à la main :

1. Lancer le serveur : `python server.py`
2. Ouvrir 2 ou 3 terminaux et lancer des clients avec des pseudos différents.
3. Scénarios recommandés :

| Scénario | Commandes |
|---|---|
| Canal public | Rejoindre `#general` automatiquement, envoyer des messages |
| Canal privé | `/create secretchan monmdp` puis `/join secretchan monmdp` depuis un autre client |
| Message privé | `/pm Bob Salut !` |
| Kick temporaire | `/kick secretchan Bob 60` (expulsion 60 secondes) |
| Administration | `/delete secretchan` (créateur uniquement) |
| IA rapide | `/ia Explique le chiffrement E2EE` |
| IA experte | `/ia pro Quelles sont les limites du Diffie-Hellman classique ?` |
| Analyse fichier | `/ia2 rapport.pdf Résume ce document` |

Les logs serveur sont écrits dans `server.log`, les logs client dans `client.log`.
