import sys, logging, threading, json, os, base64, getpass
import time as t_time

# ==================== CONFIGURATION LOGGING ====================
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler("client.log", encoding='utf-8')]
)
logger = logging.getLogger("Client")

# ==================== IMPORTS ====================
from queue import Queue
from common import network, security
from common.exchange import ExchangeType
from common.message import parse_message
from common.event import parse_event
from secsychat_tui import SecsyChatTui, TuiMessage, TuiMessageType, TuiMessageSenderType

# Assistant IA (bonus, hors énoncé) — isolé dans son propre fichier.
# Voir ai_assistant.py pour l'explication complète (notamment la vulnérabilité
# E2EE identifiée en cours et comment elle est gérée).
from ai_assistant import ask_ai, AI_ENABLED, AI_WARNING

# ==================== FICHIERS LOCAUX (énoncé 3.3) ====================
# <pseudo>.key  : clé privée RSA de l'utilisateur (jamais envoyée au serveur)
# <pseudo>.json : configuration de l'utilisateur ; la seule propriété est "context"
#                 (identifiant du canal sélectionné)

def _load_or_create_keys(pseudo: str) -> tuple:
    """Charge la paire RSA de l'utilisateur, ou la crée à la première connexion.
    Retourne (clé privée, clé publique, True si la paire vient d'être créée)."""
    key_path = f"{pseudo}.key"
    json_path = f"{pseudo}.json"

    # Ancien format (clé privée + hash du mot de passe dans le .json) : on migre vers .key
    if not os.path.exists(key_path) and os.path.exists(json_path):
        try:
            old = json.load(open(json_path, encoding='utf-8'))
            if old.get("rsa_private"):
                open(key_path, "wb").write(old["rsa_private"].encode())
                json.dump({"context": None}, open(json_path, 'w', encoding='utf-8'))
                logger.info("Ancien profil migré vers <pseudo>.key + <pseudo>.json")
        except Exception as e:
            logger.error(f"Migration du profil impossible : {e}")

    if os.path.exists(key_path):
        priv = open(key_path, "rb").read()
        return priv, security.rsa_public_from_private(priv), False

    priv, pub = security.generate_rsa_keypair()
    open(key_path, "wb").write(priv)
    try:
        os.chmod(key_path, 0o600)   # lisible uniquement par l'utilisateur (sans effet sous Windows)
    except OSError:
        pass
    return priv, pub, True


def _load_config(pseudo: str) -> dict:
    """Charge <pseudo>.json (ou une config vide)."""
    try:
        cfg = json.load(open(f"{pseudo}.json", encoding='utf-8'))
        return {"context": cfg.get("context")}
    except Exception:
        return {"context": None}


def _save_profile(pseudo: str, profile: dict):
    """Sauvegarde la configuration : uniquement le contexte (id du canal sélectionné)."""
    json.dump({"context": profile.get("context")}, open(f"{pseudo}.json", 'w', encoding='utf-8'))


# ── Construction et vérification des messages ─────────────────────────────────

def _build_message(sender: dict, recipient: dict, text: str, recipient_pub: str, rsa_priv: bytes) -> bytes:
    """Message E2EE complet (énoncé 3.2.1) : clé ChaCha20 aléatoire par message, clé chiffrée avec la
    clé publique RSA du destinataire (canal ou utilisateur), checksum SHA-256 signé avec RSA.
      sender    = {"id": ..., "name": ...}
      recipient = {"type": "CHANNEL" | "USER", "id": ..., "name": ...}"""
    clear          = text.encode()
    msg_key        = security.generate_encryption_key(256)
    nonce, ct, tag = security.chacha20_encrypt(msg_key, clear)
    payload = {
        "cipher_text":               base64.b64encode(nonce + ct + tag).decode(),
        "cipher_text_size":          len(clear),
        "cipher_text_encrypted_key": base64.b64encode(security.rsa_encrypt(recipient_pub.encode(), msg_key)).decode(),
    }
    ts        = int(t_time.time())
    checksum  = security.message_checksum(ts, sender, recipient, payload)
    signature = base64.b64encode(security.rsa_sign(rsa_priv, checksum.encode())).decode()
    return json.dumps({
        "timestamp": ts, "sender": sender, "recipient": recipient, "payload": payload,
        "integrity": {"checksum": checksum, "signature": signature}
    }).encode()


def _verify_and_decrypt(msg: dict, decrypt_key: bytes, expected_recipient_id: str, known_pubkeys: dict):
    """Vérifie un message reçu puis le déchiffre. Retourne (texte, None) ou (None, raison du rejet).
    Vérifications : destinataire attendu -> checksum recalculé -> signature RSA de l'émetteur -> déchiffrement."""
    try:
        if msg["recipient"]["id"] != expected_recipient_id:
            return None, "destinataire inattendu"

        sender_name = msg["sender"]["name"]
        pub = msg.get("sender_public_key", "")
        if not pub:
            return None, "clé publique de l'émetteur absente"
        # Une clé déjà vue pour cet émetteur ne doit pas changer
        if known_pubkeys.setdefault(sender_name, pub) != pub:
            return None, "clé publique de l'émetteur modifiée"

        integrity = msg["integrity"]
        expected  = security.message_checksum(msg["timestamp"], msg["sender"], msg["recipient"], msg["payload"])
        if integrity["checksum"] != expected:
            return None, "somme de contrôle invalide"
        if not security.rsa_verify(pub.encode(), integrity["checksum"].encode(), base64.b64decode(integrity["signature"])):
            return None, "signature invalide"

        pl             = msg["payload"]
        msg_key        = security.rsa_decrypt(decrypt_key, base64.b64decode(pl["cipher_text_encrypted_key"]))
        blob           = base64.b64decode(pl["cipher_text"])
        nonce, ct, tag = blob[:12], blob[12:-16], blob[-16:]
        clear          = security.chacha20_decrypt(msg_key, nonce, ct, tag)
        if len(clear) != pl["cipher_text_size"]:
            return None, "taille du contenu incohérente"
        return clear.decode(), None
    except Exception as e:
        return None, f"déchiffrement impossible ({e})"


def _send(sock, transport_key: bytes, ex_type: ExchangeType, payload: bytes):
    """Chiffre la charge (AES-GCM) ; le type d'échange voyage dans l'en-tête (et est authentifié)."""
    n, _, ct, tag = security.aes_encrypt(payload, transport_key, aad=bytes([ex_type.value]))
    network.send_message(sock, n + ct + tag, ex_type.value)


def _stmt(name: str, data: dict) -> bytes:
    return json.dumps({"timestamp": int(t_time.time()), "payload": {"name": name, "data": data}}).encode()


def _handshake(sock, pseudo: str, password: str, rsa_pub: bytes, rsa_priv: bytes) -> tuple:
    """DH d'abord (clé de transport), puis identifiants chiffrés + timestamp signé RSA.
    Retourne (clé de transport, identifiant de l'utilisateur).

    Avant : le pseudo et le mot de passe partaient en clair sur le réseau, avant
    même l'échange Diffie-Hellman. N'importe qui pouvait les lire avec Wireshark.
    Maintenant : on établit d'abord la clé de transport (DH), puis on chiffre les
    identifiants avec cette clé (AES-GCM) avant de les envoyer.
    """
    # 1) Diffie-Hellman — toujours en premier
    server_pub    = int(network.receive_message(sock).decode())
    p, g          = security.diffie_hellman_generate_public_parameters()
    my_priv       = security.diffie_hellman_generate_private_key(p)
    my_pub        = security.diffie_hellman_compute_public_key(my_priv, p, g)
    network.send_message(sock, str(my_pub).encode())
    shared        = security.diffie_hellman_compute_shared_secret(my_priv, server_pub, p)
    transport_key = security.diffie_hellman_derive_shared_key(shared)

    # 2) Identifiants — chiffrés avec la clé de transport qu'on vient d'établir
    creds = json.dumps({"pseudo": pseudo, "password": password}).encode()
    nonce, _, ct, tag = security.aes_encrypt(creds, transport_key)
    network.send_message(sock, nonce + ct + tag)

    auth_response = network.receive_message(sock)
    if not auth_response or not auth_response.startswith(b"AUTH_OK|"):
        raise PermissionError("❌ Connexion refusée (mot de passe incorrect ou pseudo invalide).")
    user_id = auth_response.decode().split("|", 1)[1]

    # 3) Clé publique RSA + timestamp signé avec la clé privée
    network.send_message(sock, rsa_pub)
    ts  = str(int(t_time.time()))
    sig = base64.b64encode(security.rsa_sign(rsa_priv, ts.encode())).decode()
    network.send_message(sock, f"{ts}|{sig}".encode())

    if network.receive_message(sock) != b"AUTH_OK_RSA":
        raise PermissionError("❌ Authentification RSA échouée (clé <pseudo>.key différente de celle du compte ?).")

    return transport_key, user_id

def network_worker(q_in: Queue, q_out: Queue, sock, pseudo: str, password: str, profile: dict,
                   rsa_priv: bytes, rsa_pub: bytes, context: str = None):
    """profile = configuration (<pseudo>.json) ; rsa_priv / rsa_pub = paire RSA (<pseudo>.key)"""

    # Canal actuellement sélectionné (le "contexte" de l'énoncé 2.3)
    current_channel = {"id": None, "name": "general", "priv": None, "pub": None}
    session = {"user_id": None}

    try:
        transport_key, session["user_id"] = _handshake(sock, pseudo, password, rsa_pub, rsa_priv)
        logger.info("Handshake réussi.")

        q_in.put(TuiMessage(t_time.time(), "Système",
            "✅ Connecté avec succès ! Tape /commands pour voir les commandes."))

        t_time.sleep(0.6)

        # Demande des listes
        _send(sock, transport_key, ExchangeType.STATEMENT, _stmt("GET_CHANNELS", {}))
        _send(sock, transport_key, ExchangeType.STATEMENT, _stmt("GET_USERS", {}))

    except Exception as e:
        logger.error(f"Handshake failed: {e}")
        q_in.put(TuiMessage(t_time.time(), "Système", f"❌ {str(e)}"))
        t_time.sleep(2)
        return

    pending_pms: dict = {}
    known_pubkeys: dict = {}  # pseudo -> clé publique RSA déjà vue (une clé ne doit jamais changer)
    ai_warning_shown = {"done": False}  # avertissement E2EE affiché une seule fois par session

    def _use_ai(question: str, fichiers: list = None, mode: str = "normal") -> str:
        """Point d'entrée unique vers l'IA : avertit l'utilisateur une fois, puis délègue à ai_assistant."""
        if not AI_ENABLED:
            return "❌ Assistant IA désactivé sur ce client (AI_ENABLED = False dans ai_assistant.py)."
        if not ai_warning_shown["done"]:
            q_in.put(TuiMessage(t_time.time(), "Système", AI_WARNING))
            ai_warning_shown["done"] = True
        return ask_ai(question=question, fichiers=fichiers, mode=mode)

    def _show_incoming(msg: dict, live: bool):
        """Vérifie (destinataire, checksum, signature), déchiffre et affiche un message de canal ou privé."""
        sender_name = msg["sender"]["name"]
        if msg["recipient"]["type"] == "CHANNEL":
            if not current_channel.get("priv"):
                return
            key, expected, label = current_channel["priv"].encode(), current_channel["id"], sender_name
        else:
            key, expected, label = rsa_priv, session["user_id"], f"PM de {sender_name}"

        text, reason = _verify_and_decrypt(msg, key, expected, known_pubkeys)
        if text is None:
            logger.warning(f"Message de {sender_name} ignoré : {reason}")
            if live:
                q_in.put(TuiMessage(t_time.time(), "Système", f"⚠️ Message de {sender_name} ignoré ({reason})"))
            return
        q_in.put(TuiMessage(t_time.time() if live else float(msg["timestamp"]), label, text))

    def listen():
        while True:
            exchange = network.receive_exchange(sock)
            if not exchange:
                q_in.put(TuiMessage(t_time.time(), "Système", "❌ Connexion perdue."))
                break
            try:
                ex_type, raw   = exchange
                nonce, ct, tag = raw[:16], raw[16:-16], raw[-16:]
                data_part      = security.aes_decrypt(ct, transport_key, (nonce, b"", tag), aad=bytes([ex_type]))
                logger.debug(f"Échange de type {ex_type} reçu ({len(data_part)} octets)")

                if ex_type == ExchangeType.EVENT.value:
                    evt = parse_event(data_part)
                    if not evt:
                        logger.warning("Évènement invalide (schéma JSON)")
                        continue
                    name = evt.name
                    d = evt.data

                    if name == "CHANNEL_LIST":
                        channels = d.get("channels", [])
                        clean_channels = [c.strip().replace("# ", "").replace("🔒 ", "").strip()
                                          for c in channels if isinstance(c, str) and c.strip()]
                        q_in.put(TuiMessage(t_time.time(), "", ";".join(clean_channels),
                                            type=TuiMessageType.UPDATED_CHANNELS_EVENT))

                    elif name == "CHANNEL_CREATED":
                        new_ch = d.get("name", "").strip()
                        if new_ch:
                            clean_name = new_ch.replace("# ", "").replace("🔒 ", "").strip()
                            q_in.put(TuiMessage(t_time.time(), "", clean_name,
                                                type=TuiMessageType.NEW_CHANNEL_EVENT))

                    elif name == "CHANNEL_JOINED":
                        current_channel["id"]   = d["id"]
                        current_channel["priv"] = d["private_key"]
                        current_channel["pub"]  = d["public_key"]
                        current_channel["name"] = d.get("name") or current_channel["name"]
                        current_channel.pop("_pending_name", None)
                        # Sauvegarder le canal actif (son identifiant) dans <pseudo>.json
                        profile["context"] = d["id"]
                        _save_profile(pseudo, profile)
                        q_in.put(TuiMessage(t_time.time(), "Système",
                                            f"✅ Canal rejoint : **#{current_channel['name']}**"))

                    elif name == "LAST_MESSAGES":
                        # 20 derniers messages du canal + 20 derniers messages privés (déjà triés par le serveur)
                        for m in d.get("messages", []):
                            parsed = parse_message(json.dumps(m).encode())
                            if parsed:
                                _show_incoming(dict(parsed, sender_public_key=m.get("sender_public_key", "")), live=False)

                    elif name == "USER_KEY":
                        # Clé publique du destinataire reçue : on peut chiffrer et envoyer le PM en attente
                        target_name = d.get("name", "")
                        target_pub  = d.get("public_key", "")
                        target_id   = d.get("id", "")
                        msg_text    = pending_pms.pop(target_name, None)
                        if msg_text and target_pub and target_id:
                            try:
                                payload = _build_message(
                                    {"id": session["user_id"], "name": pseudo},
                                    {"type": "USER", "id": target_id, "name": target_name},
                                    msg_text, target_pub, rsa_priv)
                                _send(sock, transport_key, ExchangeType.MESSAGE, payload)
                            except Exception as e:
                                logger.error(f"Chiffrement PM échoué : {e}")
                                q_in.put(TuiMessage(t_time.time(), "Système", f"❌ Impossible de chiffrer le PM : {e}"))

                    elif name == "KICKED":
                        q_in.put(TuiMessage(t_time.time(), "Système",
                                            d.get("message", "Vous avez été kické du canal.")))
                        # Le serveur envoie CHANNEL_JOINED + LAST_MESSAGES de #general juste après
                        current_channel["priv"] = current_channel["pub"] = None

                    elif name == "KICK_SUCCESS":
                        q_in.put(TuiMessage(t_time.time(), "Système", f"✅ {d.get('target')} a été expulsé."))

                    elif name == "CHANNEL_DELETED":
                        deleted_name = d.get("name", "")
                        q_in.put(TuiMessage(t_time.time(), "Système", f"🗑️ Canal '{deleted_name}' supprimé"))
                        q_in.put(TuiMessage(t_time.time(), "", deleted_name,
                                            type=TuiMessageType.DELETED_CHANNEL_EVENT))
                        if current_channel["id"] == d.get("id"):
                            # Le canal sélectionné n'existe plus : on retourne dans #general
                            current_channel["priv"] = current_channel["pub"] = None
                            current_channel["name"] = "general"
                            q_out.put(TuiMessage(t_time.time(), pseudo, "/join general"))

                    elif name == "PM_SENT":
                        q_in.put(TuiMessage(t_time.time(), "Système",
                                            f"✅ Message privé envoyé à {d.get('target')}"))

                    elif name == "ERROR":
                        q_in.put(TuiMessage(t_time.time(), "Système", f"⚠️ {d.get('message')}"))

                    elif name in ["SYSTEM", "Système"]:
                        msg_text = d.get("message") if isinstance(d, dict) else str(d)
                        q_in.put(TuiMessage(t_time.time(), "Système", msg_text))

                    elif name == "UPDATED_USERS":
                        users = d.get("users", [])
                        clean_users = [u.strip() for u in users if isinstance(u, str) and u.strip()]
                        users_str = ";".join(clean_users)

                        # Contournement du bug TUI (uniquement pour les users)
                        q_in.put(TuiMessage(t_time.time(), "", "",
                                            type=TuiMessageType.UPDATED_USERS_EVENT))
                        if users_str:
                            q_in.put(TuiMessage(t_time.time(), "", users_str,
                                                type=TuiMessageType.UPDATED_USERS_EVENT))

                elif ex_type == ExchangeType.MESSAGE.value:
                    # Message d'un autre utilisateur (canal ou privé), chiffré E2EE
                    msg = parse_message(data_part)
                    if not msg:
                        logger.warning("Message invalide (schéma JSON) — ignoré")
                        continue
                    _show_incoming(dict(msg, sender_public_key=json.loads(data_part).get("sender_public_key", "")), live=True)

            except Exception as e:
                logger.error(f"Erreur réception : {e}")

    threading.Thread(target=listen, daemon=True).start()

    # Rejoindre le dernier canal sélectionné (son identifiant est dans <pseudo>.json, propriété "context").
    # Le serveur t'a déjà placé dans #general ; si tu étais ailleurs, on te remet dans ton canal.
    # (instruction envoyée directement : pas de /join, donc pas de fenêtre "sans clé" côté client)
    if context:
        t_time.sleep(0.4)
        _send(sock, transport_key, ExchangeType.STATEMENT, _stmt("JOIN_CHANNEL", {"id": context}))

    while True:
        tui_msg = q_out.get()
        cmd     = tui_msg.message.strip()
        parts   = cmd.split()

        try:
            if cmd.startswith(("/commands", "/man")):
                help_text = """📋 **Commandes disponibles** :

**Général :**
  /commands ou /man     → Affiche cette aide
  /users ou /who         → Rafraîchir les utilisateurs connectés
  /status ou /where      → Voir le canal actuel

**Canaux :**
  /create <nom> [mdp]    → Crée un canal
  /join <nom> [mdp]      → Rejoint un canal
  /leave                 → Quitte le canal actuel

**Administration :**
  /kick <pseudo>              → Expulse un utilisateur (permanent)
  /kick <pseudo> <secondes>   → Expulse temporairement (ex: /kick Bob 300)
  /delete <nom>               → Supprime un canal (créateur)

**Messages privés :**
  /pm <pseudo> <message> → Envoie un MP chiffré

**Intelligence Artificielle :**
  /ia <question>          → IA Rapide (Flash)
  /ia pro <question>      → IA Experte (Pro)
  /ia2 <fichiers...> [prompt] → Analyse de fichiers (Pro)"""
                
                q_in.put(TuiMessage(t_time.time(), "Système", help_text))

            elif cmd.startswith("/list"):
                q_in.put(TuiMessage(t_time.time(), "Système", 
                    "✅ Les canaux sont mis à jour automatiquement à leur création."))

            elif cmd.startswith("/users") or cmd.startswith("/who"):
                _send(sock, transport_key, ExchangeType.STATEMENT, _stmt("GET_USERS", {}))

            elif cmd.startswith("/status") or cmd.startswith("/where"):
                ch_name = current_channel["name"]
                q_in.put(TuiMessage(t_time.time(), "Système", 
                    f"📍 Vous êtes dans le canal : **#{ch_name}**"))

            elif cmd.startswith("/create ") and len(parts) >= 2:
                ch_name = parts[1]
                current_channel["priv"] = current_channel["pub"] = None
                # Ne pas mettre à jour name ici : on attend CHANNEL_JOINED pour confirmer
                current_channel["_pending_name"] = ch_name
                secret = " ".join(parts[2:]) if len(parts) > 2 else ""
                _send(sock, transport_key, ExchangeType.STATEMENT,
                      _stmt("CREATE_CHANNEL", {"name": ch_name, "secret": secret}))

            elif cmd.startswith("/join ") and len(parts) >= 2:
                ch_name = parts[1]
                current_channel["priv"] = current_channel["pub"] = None
                # Idem : on attend CHANNEL_JOINED avant de valider le canal actif
                current_channel["_pending_name"] = ch_name
                secret = " ".join(parts[2:]) if len(parts) > 2 else ""
                _send(sock, transport_key, ExchangeType.STATEMENT,
                      _stmt("JOIN_CHANNEL", {"name": ch_name, "secret": secret}))

            elif cmd.startswith("/leave"):
                _send(sock, transport_key, ExchangeType.STATEMENT,
                      _stmt("LEAVE_CHANNEL", {"name": current_channel["name"]}))
                current_channel["priv"] = current_channel["pub"] = None
                current_channel["name"] = "general"
                q_in.put(TuiMessage(t_time.time(), "Système", "➡️ Retour automatique vers #general..."))
                
            elif cmd.startswith("/kick ") and len(parts) >= 2:
                target = parts[1]
                duration = ""
                
                if len(parts) >= 3 and parts[2].isdigit():
                    duration = parts[2]
                
                # On envoie le target et la durée séparément (plus propre)
                _send(sock, transport_key, ExchangeType.STATEMENT,
                      _stmt("KICK_CHANNEL_MEMBER", {"channel_name": current_channel["name"],
                                                    "member_name": target, "duration": duration}))
                
                q_in.put(TuiMessage(t_time.time(), "Système", 
                    f"👢 Commande de kick envoyée pour {target}"))

            elif cmd.startswith("/delete ") and len(parts) >= 2:
                _send(sock, transport_key, ExchangeType.STATEMENT,
                      _stmt("DELETE_CHANNEL", {"name": parts[1]}))

            elif cmd.startswith("/pm ") and len(parts) >= 3:
                target = parts[1]
                message_text = " ".join(parts[2:])
                # it.8 — Récupérer la clé publique RSA du destinataire, puis chiffrer E2EE
                _send(sock, transport_key, ExchangeType.STATEMENT,
                      _stmt("GET_USER_KEY", {"name": target}))
                pending_pms[target] = message_text
                q_in.put(TuiMessage(t_time.time(), "Système", f"→ Chiffrement du message pour {target}…"))

            elif cmd.startswith("/ia "):
                question = cmd[4:].strip()
                if question:
                    q_in.put(TuiMessage(t_time.time(), "WhiteHat-AI", "🤔 Réflexion en cours..."))
                    response = _use_ai(question=question, mode="normal")
                    q_in.put(TuiMessage(t_time.time(), "WhiteHat-AI", response))

            elif cmd.startswith(("/ia pro ", "/ia2 ")):
                argument = cmd[8:].strip() if cmd.startswith("/ia pro ") else cmd[5:].strip()
                
                if not argument:
                    q_in.put(TuiMessage(t_time.time(), "WhiteHat-AI 2.0", 
                                      "Usage: /ia pro <question> ou /ia2 <fichiers...> [prompt]"))
                    continue

                parts_list = argument.split()
                files = [p for p in parts_list if os.path.exists(p)]
                prompt = " ".join([p for p in parts_list if p not in files]) or "Analyse ce contenu."

                ai_name = "WhiteHat-AI 2.0"
                q_in.put(TuiMessage(t_time.time(), ai_name, "🤔 Analyse en cours..."))

                response = _use_ai(
                    question=prompt,
                    fichiers=files if files else None,
                    mode="pro"
                )
                q_in.put(TuiMessage(t_time.time(), ai_name, response))

            elif not cmd.startswith("/"):
                if not current_channel.get("pub"):
                    q_in.put(TuiMessage(t_time.time(), "Système", "⚠️ Pas dans un canal. Utilisez /create ou /join"))
                    continue

                # === INTERACTION AVEC LES IA ===
                lower_cmd = cmd.lower().strip()
                if lower_cmd.startswith(("whitehat-ai", "whitehat ai", "@whitehat", "whitehat")):
                    question = cmd.split(maxsplit=1)[1] if len(cmd.split()) > 1 else cmd
                    q_in.put(TuiMessage(t_time.time(), "WhiteHat-AI", "🤔 Réflexion en cours..."))
                    response = _use_ai(question=question, mode="normal")
                    q_in.put(TuiMessage(t_time.time(), "WhiteHat-AI", response))
                    continue

                elif any(keyword in lower_cmd for keyword in ["pro", "ia2", "ia 2"]) and ("whitehat" in lower_cmd or "ia" in lower_cmd):
                    question = cmd.split(maxsplit=1)[1] if len(cmd.split()) > 1 else cmd
                    q_in.put(TuiMessage(t_time.time(), "WhiteHat-AI 2.0", "🤔 Réflexion Pro en cours..."))
                    response = _use_ai(question=question, mode="pro")
                    q_in.put(TuiMessage(t_time.time(), "WhiteHat-AI 2.0", response))
                    continue

                # Message normal dans le canal
                payload = _build_message(
                    {"id": session["user_id"], "name": pseudo},
                    {"type": "CHANNEL", "id": current_channel["id"], "name": current_channel["name"]},
                    cmd, current_channel["pub"], rsa_priv)
                _send(sock, transport_key, ExchangeType.MESSAGE, payload)
                q_in.put(TuiMessage(t_time.time(), pseudo, cmd))

        except Exception as e:
            logger.error(f"Erreur envoi ({cmd!r}) : {e}")

def main():
    if len(sys.argv) < 4:
        print("Usage: python client.py <IP> <PORT> <PSEUDO>")
        sys.exit(1)

    ip, port, pseudo = sys.argv[1], int(sys.argv[2]), sys.argv[3]

    # Clés RSA (<pseudo>.key, créées à la première connexion) et configuration (<pseudo>.json)
    rsa_priv, rsa_pub, first_time = _load_or_create_keys(pseudo)
    profile = _load_config(pseudo)

    # Le mot de passe est demandé via STDIN (sans écho à l'écran)
    if first_time:
        print(f"\n📝 Première connexion de {pseudo} : une paire de clés RSA a été créée ({pseudo}.key).")
        print("   Choisis un mot de passe (minimum 8 caractères). Si le compte existe déjà, entre son mot de passe.\n")
    else:
        print(f"\n🔑 Connexion en tant que {pseudo}")
    password = getpass.getpass("Mot de passe : ")
    if len(password) < 8:
        print("❌ Le mot de passe doit faire au moins 8 caractères.")
        sys.exit(1)

    try:
        sock = network.connect_tcp_server(ip, port)
    except Exception as e:
        print(f"Connexion impossible : {e}")
        sys.exit(1)

    q_in  = Queue()
    q_out = Queue()
    tui   = SecsyChatTui(q_in, q_out, version="1.0.0", user_name=pseudo, channels=[], users=[])

    # Lancement du worker réseau
    network_thread = threading.Thread(
        target=network_worker,
        args=(q_in, q_out, sock, pseudo, password, profile, rsa_priv, rsa_pub, profile.get("context")),
        daemon=True
    )
    network_thread.start()

    tui.run()


if __name__ == "__main__":
    main()