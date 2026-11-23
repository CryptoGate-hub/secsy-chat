# Changelog sécurité — Secsy Chat

Ce fichier liste les corrections de sécurité apportées au projet, dans l'ordre
de gravité. Pour chaque point : le problème, pourquoi c'est un problème, et ce
qui a été changé. Fichiers concernés indiqués entre parenthèses.

---

## Partie B — Mise en conformité avec la checklist (audit des 90 critères)

Après les corrections 1 à 5 ci-dessous, le code a été relu critère par critère
(itérations 1 à 9). Ce qui n'était pas conforme à l'énoncé a été corrigé.
Deux tests automatiques de bout en bout (serveur réel + clients) ont été
exécutés : 29/29 puis 12/12 vérifications réussies.

**Protocole (it. 2, 3, 4)**
- **En-tête de 11 octets** (10 pour la taille, 1 pour le type d'échange), comme
  demandé. Avant : 4 octets, le type était caché dans la charge chiffrée. Le type
  est authentifié par AES-GCM (AAD) et une taille > 10 Mo est refusée (`network.py`).
- **Structure exacte des échanges** : instructions et évènements ont maintenant
  un `timestamp` ; les messages ont `sender{id,name}`, `recipient{type,id,name}`,
  `payload` et `integrity` complets.
- **Validation par schémas JSON** réellement appliquée : `parse_message` n'était
  jamais appelé. Le serveur et le client valident maintenant chaque échange
  (`common/message.py`, `statement.py`, `event.py`).
- **Noms alignés sur l'énoncé** : `GET_CHANNELS`, `GET_USERS`, `GET_LAST_MESSAGES`,
  `KICK_CHANNEL_MEMBER`, `CHANNEL_JOINED`, `CHANNEL_CREATED`. `GET_USERS` (`/users`)
  n'était pas géré par le serveur : il l'est.
- **Identifiants NanoId de 21 caractères** (`security.generate_id`) au lieu de
  `u_` / `c_` / `pm_` + hexadécimal.

**Intégrité et E2EE (it. 5, 7, 8)**
- Avant, le destinataire signé d'un message de canal était `"current"` : un message
  signé pour un canal pouvait être rejoué dans un autre. Le **vrai canal (id + nom)
  est maintenant signé**, et le serveur vérifie qu'il correspond au canal de l'émetteur.
- Le serveur vérifie que l'**émetteur annoncé est bien l'utilisateur authentifié**
  (sinon Alice pouvait signer un message « de la part de Bob »).
- Le calcul du checksum est **une seule fonction partagée** (`security.message_checksum`)
  utilisée par le client et le serveur : ils ne peuvent plus diverger.
- Le **client vérifie aussi** checksum + signature à la réception, y compris pour
  l'historique (avant, l'historique était déchiffré sans aucune vérification).
- Les **PM sont de vrais messages** (`recipient.type = USER`, même chemin que les
  messages de canal) et plus une instruction détournée.
- **Livraison des PM** : avant, tous les anciens PM étaient renvoyés à chaque message
  envoyé par le destinataire (doublons, sans signature). Maintenant : livraison
  immédiate si connecté, puis historique à la connexion (20 derniers canal + 20 derniers
  privés, triés par date, 20 plus récents affichés, énoncé 2.3).

**Authentification (it. 3, 9)**
- La clé publique RSA est enregistrée à la **première connexion** puis **imposée** :
  avant, chaque connexion remplaçait la clé enregistrée par celle envoyée, donc la
  signature ne prouvait rien. Une clé différente est refusée.
- Mot de passe saisi **sans écho** (`getpass`), pseudos validés (3-20 caractères) et
  pseudos réservés refusés (`WhiteHat-AI`, `Système`...).
- Clé publique Diffie-Hellman du pair refusée si 0, 1 ou p-1.

**Fichiers locaux (énoncé 3.3)**
- `<pseudo>.key` contient la clé privée ; `<pseudo>.json` ne contient plus que
  `context` (identifiant du canal sélectionné). Avant, la clé privée **et** le hash du
  mot de passe étaient dans le `.json`. Les anciens profils sont migrés automatiquement.

**Autres**
- `last_activity_at` mis à jour à chaque échange (avant : à la connexion seulement).
- Niveaux de log DEBUG / INFO / WARNING / ERROR tous utilisés côté serveur.
- Suppression d'un canal : ses messages sont aussi supprimés (avant : orphelins en base).
- `requirements.txt` corrigé : `pycryptodomex` (le code importe `Cryptodome`) et
  `google-genai` (le code importe `google.genai`). README mis à jour.

**Écarts restants, à connaître pour la défense**
- `UPDATE_USER` (notifier l'activité) n'est pas implémenté ; les évènements `CHANNEL_LIST`
  et `UPDATED_USERS` renvoient une liste au lieu d'un évènement par canal / utilisateur
  (`CHANNEL_CREATED` / `USER_UPDATED` de l'énoncé).
- `/kick <pseudo> [secondes]` agit sur le canal courant (l'énoncé écrit `/kick <canal> <membre>`) ;
  l'instruction envoyée au serveur, elle, porte bien `channel_name` et `member_name`.
- Un PM est chiffré avec la clé du destinataire : l'expéditeur ne peut pas le relire
  dans son historique (limite du schéma imposé par l'énoncé).
- Pas de limitation du nombre d'essais de mot de passe (attaque en ligne possible) ;
  le Diffie-Hellman reste non authentifié (voir partie A, point 2).
- **Le serveur détient la clé privée de chaque canal** (colonne `channel.private_key`, imposée par le schéma
  de l'énoncé) : il peut déchiffrer les messages de canal. Seuls les messages privés sont chiffrés de bout en bout
  au sens strict (le serveur n'a jamais la clé privée RSA des utilisateurs, qui reste dans `<pseudo>.key`).
- La clé privée d'un canal est transmise à chaque membre : c'est le principe de
  l'énoncé, mais un membre expulsé qui l'a déjà reçue pourrait lire de futurs
  messages s'il les interceptait.

---

# Partie A — Corrections de sécurité

## 1. Mot de passe envoyé en clair avant le Diffie-Hellman (CRITIQUE)

**Avant :** `client.py` envoyait `{"pseudo": ..., "password": ...}` directement
sur le socket, **avant** l'échange Diffie-Hellman. Le pseudo et le mot de
passe traversaient donc le réseau sans aucun chiffrement — visibles en clair
avec Wireshark par n'importe qui sur le même réseau.

**Pourquoi c'est grave :** c'est la porte d'entrée du système. Tout le reste
(AES, ChaCha20, RSA) protège très bien le contenu des messages, mais les
identifiants de connexion, eux, n'étaient pas protégés du tout.

**Correction :** l'ordre est inversé. Le Diffie-Hellman a lieu en premier pour
établir la clé de transport, puis le pseudo et le mot de passe sont chiffrés
avec cette clé (AES-GCM, comme tous les échanges qui suivent) avant d'être
envoyés. Aucune nouvelle crypto introduite : on réutilise simplement
`aes_encrypt` / `aes_decrypt`, déjà présents dans `common/security.py`.

**Fichiers :** `server.py` (`_handshake`), `client.py` (`_handshake`).

---

## 2. Nombre premier Diffie-Hellman trop court (256 bits)

**Avant :** `common/security.py` définissait un `P` de 256 bits, bricolé (pas
un groupe standard). Un Diffie-Hellman sur 256 bits est cassable par calcul de
logarithme discret avec du matériel grand public.

**Correction :** remplacement par le groupe **RFC 3526 Group 14** (2048 bits),
un nombre premier standard, documenté publiquement, utilisé dans de nombreux
protocoles réels (VPN, SSH...). Vérifié : c'est bien un nombre premier, et
c'est un « safe prime » (propriété nécessaire pour Diffie-Hellman). L'échange
de clé fonctionne exactement pareil, juste avec un nombre plus grand.

**Fichier :** `common/security.py`.

**Limite restant assumée (hors scope) :** ce Diffie-Hellman n'est pas
authentifié — un attaquant capable de s'interposer activement entre le client
et le serveur (attaque de l'homme du milieu) pourrait en théorie négocier deux
clés distinctes avec chacun. Corriger ça demanderait un mécanisme
d'authentification mutuelle des clés DH (ex. Station-to-Station), hors du
cadre de l'énoncé. À mentionner si le jury pousse la question, mais pas
corrigé ici pour ne pas complexifier inutilement le projet.

---

## 3. Messages privés (PM) sans aucune vérification d'intégrité

**Avant :** contrairement aux messages de canal (vérifiés par checksum SHA-256
+ signature RSA), les messages privés étaient envoyés comme une simple
`Statement` sans aucun champ d'intégrité. Rien ne garantissait qu'un PM reçu
n'avait pas été altéré, ni qu'il venait vraiment de l'expéditeur annoncé.

**Correction :** les PM suivent maintenant le même principe que les messages
de canal :
- Le client qui envoie calcule un checksum SHA-256 (sur l'horodatage,
  l'émetteur, le destinataire et la charge chiffrée) et le signe avec sa clé
  privée RSA.
- Le serveur **vérifie** ce checksum et cette signature avant d'accepter et de
  persister le PM ; il rejette le message sinon (`PM rejeté : intégrité
  invalide`).
- Le serveur transmet la clé publique de l'émetteur au destinataire avec le
  PM, pour que celui-ci puisse **aussi** vérifier la signature avant
  d'afficher le message.

**Fichiers :** `client.py` (envoi et réception des PM), `server.py`
(`_handle_statement`, cas `PRIVATE_MESSAGE`).

---

## 4. Vérification de signature silencieusement ignorée si la clé publique manque

**Avant (`server.py`, `_handle_message`) :**
```python
if pub_key and not security.rsa_verify(...):
    return
```
Si `pub_key` était vide (cas limite), la condition était fausse et le message
passait **sans aucune vérification**, au lieu d'être rejeté.

**Correction :** si la clé publique de l'émetteur est inconnue, le message de
canal est désormais explicitement rejeté (avec un log), au lieu d'être accepté
par défaut.

**Fichier :** `server.py` (`_handle_message`).

---

## 5. Assistant IA (WhiteHat-AI / Gemini) : fuite hors du périmètre E2EE

**Contexte :** fonctionnalité bonus, ajoutée pour se démarquer, hors énoncé.
Remarque reçue en cours : un message envoyé à l'IA part en clair vers les
serveurs de Google, ce qui contourne tout le système de chiffrement de bout en
bout du projet.

**Ce qui a été fait (gérer le risque, pas le nier) :**
- **Isolation** : tout le code Gemini a été sorti de `client.py` vers un
  fichier dédié, `ai_assistant.py`. Il peut être désactivé entièrement en
  changeant une seule constante (`AI_ENABLED = False`).
- **Avertissement explicite** : avant le premier appel à l'IA de la session,
  l'utilisateur voit un message clair expliquant que ce message sort du
  chiffrement de bout en bout et part vers Google.
- **Scope limité** : seul le message explicitement adressé à l'IA (`/ia`,
  `/ia pro`, mention `whitehat`) est envoyé à Gemini — jamais l'historique du
  canal ni les messages d'autres utilisateurs. Les fichiers ne sont envoyés
  que si l'utilisateur les fournit explicitement à l'IA.
- **Gestion des erreurs** : les erreurs 429 (rate limit) et 500/503 (service
  indisponible côté Google) renvoient désormais un message clair à
  l'utilisateur au lieu de planter ou de rester silencieuses.

**Fichiers :** nouveau `ai_assistant.py` ; `client.py` (import + `_use_ai`,
remplace les appels directs à `ask_ai`).

---

## Ce qui n'a volontairement pas été touché

- La contrainte « mot de passe ≥ 8 caractères » côté serveur (`server.py`,
  `_handshake`) n'est pas dans l'énoncé mais n'est pas un problème de
  sécurité — laissée telle quelle. À assumer en défense comme un choix de
  robustesse ajouté par le groupe.
- Pas de réécriture de l'architecture générale (threads, queues, structure des
  fichiers) : toutes les corrections ci-dessus modifient des fonctions
  existantes, sans changer l'organisation du projet.
