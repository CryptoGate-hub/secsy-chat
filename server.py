import logging, threading, json, base64, time, re
from common import database, network, security, data
from common.exchange import ExchangeType
from common.message import parse_message
from common.statement import parse_statement

# Canaux système protégés
DEFAULT_CHANNELS = {"general", "dev", "random"}
# Pseudos réservés (les IA sont affichées dans la liste des utilisateurs)
RESERVED_NAMES = {"whitehat-ai", "whitehat-ai_2", "système", "systeme", "system"}

logging.basicConfig(
    level=logging.DEBUG,     # DEBUG, INFO, WARNING et ERROR sont tous utilisés dans ce fichier
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[logging.FileHandler("server.log", encoding='utf-8'), logging.StreamHandler()]
)
logger = logging.getLogger("Server")

clients      = {}                 # conn -> infos de la session (pseudo, user_id, cipher, channel_id)
clients_lock = threading.Lock()   # protège "clients" (plusieurs threads y accèdent)

db_conn      = database.connect_to_db("messenger.db")
database.execute_seed(db_conn)
data.db_conn = db_conn

MAX_CLOCK_DRIFT = 300             # 5 minutes (énoncé 2.2.2) : écart toléré pour un timestamp signé
HANDSHAKE_TIMEOUT = 15            # secondes pour terminer la connexion, sinon on coupe
MAX_CONN_PER_IP   = 10            # connexions simultanées maximum depuis une même adresse IP
MAX_CIPHER_LEN   = 16 * 1024     # taille maximale du texte chiffré (base64) d'un message : évite qu'un message
                                 # géant rende l'historique d'un canal impossible à recevoir pour les autres
MAX_KEY_LEN      = 1024          # taille maximale de la clé chiffrée d'un message (RSA-2048 : ~344 caractères)
MSG_BURST, MSG_WINDOW = 10, 10   # au plus 10 messages toutes les 10 secondes par connexion

# Identité du serveur : sa clé privée (server.key) signe chaque Diffie-Hellman.
# server.pub est la clé publique à donner aux clients (ils la vérifient avant d'envoyer
# leur mot de passe) : sans elle, un "homme du milieu" pouvait se faire passer pour le serveur.
SERVER_KEY = security.load_or_create_rsa_key("server.key")
SERVER_PUB = security.rsa_public_from_private(SERVER_KEY)
with open("server.pub", "wb") as _f:
    _f.write(SERVER_PUB)

# Limitation des essais de mot de passe : après 5 échecs sur un pseudo (ou 20 depuis une même IP,
# tous pseudos confondus), attente de 30 s, puis 60 s, 120 s... (15 min maximum)
MAX_FAILED = {"user": 5, "ip": 20, "chan": 5}   # "chan" : essais de mot de passe d'un canal privé, par utilisateur
BASE_DELAY, MAX_DELAY = 30, 900
_failed      = {}                 # ("user", pseudo) ou ("ip", adresse) -> [nombre d'échecs, bloqué jusqu'à]
_failed_lock = threading.Lock()
_conn_per_ip = {}                 # adresse IP -> connexions ouvertes
_conn_lock   = threading.Lock()


def create_default_channels():
    """Crée des canaux publics par défaut s'ils n'existent pas"""
    for ch_name in sorted(DEFAULT_CHANNELS):
        if not data.channel_exists(ch_name):
            priv_k, pub_k = security.generate_rsa_keypair()
            data.create_channel(security.generate_id(), ch_name, "", "system",
                                priv_k.decode(), pub_k.decode(), is_private=False)
            logger.info(f"Canal par défaut créé : #{ch_name}")

create_default_channels()


def _auth_blocked(keys) -> int:
    """Secondes d'attente restantes avant un nouvel essai (0 = autorisé)."""
    now = time.time()
    with _failed_lock:
        return int(max([_failed.get(k, [0, 0])[1] - now for k in keys] + [0]))


def _auth_failed(keys):
    with _failed_lock:
        for k in keys:
            entry = _failed.setdefault(k, [0, 0])
            entry[0] += 1
            limit = MAX_FAILED[k[0]]
            if entry[0] >= limit:
                entry[1] = time.time() + min(BASE_DELAY * 2 ** (entry[0] - limit), MAX_DELAY)


def _auth_succeeded(keys):
    with _failed_lock:
        for k in keys:
            _failed.pop(k, None)


# ====================== AUTHENTIFICATION ======================

def _recv(conn) -> bytes:
    """Lit un échange de la poignée de main ; erreur claire si le client a fermé la connexion."""
    data_bytes = network.receive_message(conn)
    if data_bytes is None:
        raise ConnectionError("connexion fermée pendant la poignée de main")
    return data_bytes


def _handshake(conn, addr) -> tuple:
    """DH d'abord (clé de transport), puis authentification par mot de passe (chiffrée),
    puis authentification par signature RSA d'un timestamp.

    Avant : le pseudo et le mot de passe arrivaient en clair, avant le Diffie-Hellman.
    Maintenant : la clé de transport est établie d'abord, et les identifiants
    voyagent chiffrés (AES-GCM) avec cette clé, comme tous les autres échanges.
    """
    # 1) Diffie-Hellman — toujours en premier
    p, g          = security.diffie_hellman_generate_public_parameters()
    priv          = security.diffie_hellman_generate_private_key(p)
    pub           = security.diffie_hellman_compute_public_key(priv, p, g)
    network.send_message(conn, str(pub).encode())
    cli_pub       = int(_recv(conn).decode())
    shared        = security.diffie_hellman_compute_shared_secret(priv, cli_pub, p)
    transport_key = security.diffie_hellman_derive_shared_key(shared)

    # 1 bis) Le serveur PROUVE son identité : il signe les deux clés DH de la session avec server.key.
    #        Le client vérifie avec server.pub avant d'envoyer quoi que ce soit (anti homme du milieu).
    dh_sig = security.rsa_sign(SERVER_KEY, security.dh_signed_data(pub, cli_pub))
    network.send_message(conn, base64.b64encode(SERVER_PUB) + b"|" + base64.b64encode(dh_sig))
    cipher = security.TransportCipher(transport_key, is_server=True)

    # 2) Identifiants — déchiffrés avec la clé de transport qu'on vient d'établir
    creds  = json.loads(cipher.open(0, _recv(conn)).decode())
    pseudo = str(creds.get("pseudo", ""))
    pwd    = str(creds.get("password", ""))
    keys   = [("user", pseudo.lower()), ("ip", addr[0])]

    wait = _auth_blocked(keys)
    if wait:
        network.send_message(conn, b"AUTH_FAIL")
        raise PermissionError(f"Trop d'essais pour {pseudo!r} / {addr[0]} : bloqué encore {wait} s")

    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,20}", pseudo) or pseudo.lower() in RESERVED_NAMES \
            or data.similar_user_exists(pseudo):   # "bob" refusé si "Bob" existe déjà
        _auth_failed(keys[1:])
        network.send_message(conn, b"AUTH_FAIL")
        raise PermissionError(f"Pseudo invalide, réservé ou trop proche d'un autre : {pseudo!r}")

    if len(pwd) < 8:   # ← Ajout de sécurité minimale
        network.send_message(conn, b"AUTH_FAIL")
        raise PermissionError("Mot de passe trop court")

    user = data.get_user(pseudo)
    if user:
        # Le compte existe : le mot de passe protège l'accès (comparaison Argon2)
        user_id = user[0]
        if not security.argon2_verify_password(pwd, user[1]):
            _auth_failed(keys)
            network.send_message(conn, b"AUTH_FAIL")
            raise PermissionError(f"Mot de passe incorrect pour {pseudo}")
        logger.info(f"Connexion de {pseudo} (compte existant)")
    else:
        # Premier échange : le compte est créé, le mot de passe est stocké haché (Argon2)
        user_id = security.generate_id()
        data.create_user(user_id, pseudo, security.argon2_hash_password(pwd))
        logger.info(f"Nouveau compte créé : {pseudo}")

    network.send_message_as_str(conn, f"AUTH_OK|{user_id}")

    # 3) Authentification cryptographique (it.9) : timestamp signé avec la clé privée RSA
    pub_key_pem = _recv(conn)
    ts_payload  = _recv(conn)
    stored_key  = data.get_user_public_key(pseudo)
    try:
        if stored_key and stored_key.strip() != pub_key_pem.decode().strip():
            # Avant, la clé reçue remplaçait la clé enregistrée : la signature "prouvait" donc
            # seulement que le client connaissait sa propre clé. Maintenant on vérifie
            # avec la clé enregistrée à la 1re connexion.
            raise PermissionError("Clé RSA différente de celle enregistrée pour ce compte")

        ts_str, sig_b64 = ts_payload.decode().split("|", 1)
        if abs(int(time.time()) - int(ts_str)) > MAX_CLOCK_DRIFT:
            raise PermissionError("Timestamp expiré")
        if not security.rsa_verify(pub_key_pem, ts_str.encode(), base64.b64decode(sig_b64)):
            raise PermissionError("Signature RSA invalide")
    except PermissionError:
        _auth_failed(keys)
        network.send_message(conn, b"AUTH_FAIL")
        raise
    except Exception as e:
        _auth_failed(keys)
        network.send_message(conn, b"AUTH_FAIL")
        raise PermissionError(f"Erreur auth RSA : {e}")

    if not stored_key:
        data.set_user_public_key(pseudo, pub_key_pem.decode())   # 1re connexion : on enregistre la clé publique

    _auth_succeeded(keys[:1])
    network.send_message(conn, b"AUTH_OK_RSA")
    data.touch_user(pseudo)
    return pseudo, user_id, cipher


# ====================== ENVOI ======================

def _send(conn, info: dict, ex_type: ExchangeType, payload: bytes):
    """Chiffre la charge (AES-GCM + compteur anti-rejeu) ; le type d'échange voyage dans l'en-tête.
    Le verrou garantit que les trames partent dans l'ordre de leurs numéros, même si plusieurs
    threads écrivent au même client en même temps."""
    cipher = info["cipher"]
    with cipher.lock:
        network.send_message(conn, cipher.seal(ex_type.value, payload), ex_type.value)


def _event(conn, info: dict, name: str, data_dict: dict):
    payload = json.dumps({"timestamp": int(time.time()),
                          "payload": {"name": name, "data": data_dict}}).encode()
    _send(conn, info, ExchangeType.EVENT, payload)


def _error(conn, info: dict, text: str):
    _event(conn, info, "ERROR", {"message": text})


def _get_connected_users() -> list:
    """Retourne la liste des utilisateurs connectés + les IA."""
    with clients_lock:
        real_users = [i["pseudo"] for i in clients.values() if "pseudo" in i]
    return list(dict.fromkeys(real_users + ["WhiteHat-AI", "WhiteHat-AI_2"]))


def _broadcast_user_list():
    users = _get_connected_users()
    with clients_lock:
        for conn, info in list(clients.items()):
            try:
                _event(conn, info, "UPDATED_USERS", {"users": users})
            except Exception:
                pass


def _broadcast_event(name: str, data_dict: dict):
    """Envoie un évènement à tous les clients connectés."""
    with clients_lock:
        for conn, info in list(clients.items()):
            try:
                _event(conn, info, name, data_dict)
            except Exception:
                pass


def _send_channel_joined(conn, info: dict, ch):
    """Le client rejoint un canal : on lui donne l'id, le nom et les clés du canal.
    ch = (id, secret, owner_id, private_key, public_key, is_private, name)"""
    info["channel_id"] = ch[0]
    _event(conn, info, "CHANNEL_JOINED",
           {"id": ch[0], "name": ch[6], "private_key": ch[3], "public_key": ch[4]})


def _send_history(conn, info: dict, channel_id: str, n: int = 20):
    """Énoncé 2.3 : les N derniers messages du canal + les N derniers messages privés,
    triés à nouveau par date, et seuls les N plus récents sont renvoyés."""
    messages = data.get_last_messages(channel_id, n) + data.get_last_private_messages(info["user_id"], n)
    messages.sort(key=lambda m: m["timestamp"])
    _event(conn, info, "LAST_MESSAGES", {"messages": messages[-n:]})


def _enter_channel(conn, info: dict, ch_id: str):
    """Active un canal pour ce client : clés + historique."""
    ch = data.get_channel_by_id(ch_id)
    if ch:
        _send_channel_joined(conn, info, ch)
        _send_history(conn, info, ch_id)


def _send_to_user(user_id: str, ex_type: ExchangeType, payload: bytes):
    """Envoie un échange à toutes les sessions ouvertes d'un utilisateur."""
    with clients_lock:
        targets = [(c, i) for c, i in clients.items() if i.get("user_id") == user_id]
    for c, i in targets:
        try:
            _send(c, i, ex_type, payload)
        except Exception:
            pass


# ====================== INSTRUCTIONS ======================

def _handle_statement(conn, info: dict, payload: bytes):
    stmt = parse_statement(payload)
    if not stmt:
        logger.warning(f"Instruction invalide (schéma JSON) de {info['pseudo']}")
        return
    pseudo, user_id = info["pseudo"], info["user_id"]
    name, d = stmt.name, stmt.data
    logger.debug(f"Instruction {name} de {pseudo}")

    try:
        if name == "GET_CHANNELS":
            public          = data.get_public_channels()
            private_visible = [c for c in data.get_user_channels(user_id) if data.is_private_channel(c)]
            labels = [f"🔒 {c}" if data.is_private_channel(c) else f"# {c}"
                      for c in dict.fromkeys(public + private_visible)]
            _event(conn, info, "CHANNEL_LIST", {"channels": labels})

        elif name == "GET_USERS":
            _event(conn, info, "UPDATED_USERS", {"users": _get_connected_users()})

        elif name == "GET_LAST_MESSAGES":
            ch = data.get_channel(str(d.get("channel_name", "")).strip().lower())
            if not ch or not data.is_member(ch[0], user_id):
                return _error(conn, info, "Canal introuvable ou vous n'en êtes pas membre")
            n = d.get("number", 20)
            _send_history(conn, info, ch[0], max(1, min(int(n), 100)) if isinstance(n, int) else 20)

        elif name == "GET_USER_KEY":
            target_name = str(d.get("name", "")).strip()
            target      = data.get_user(target_name)
            if target and target[2]:
                _event(conn, info, "USER_KEY",
                       {"id": target[0], "name": target_name, "public_key": target[2]})
            else:
                _error(conn, info, f"Clé publique de '{target_name}' introuvable")

        elif name == "CREATE_CHANNEL":
            ch_name = str(d.get("name", "")).strip().lower()
            ch_pass = str(d.get("secret", ""))

            if not re.fullmatch(r"[a-z0-9_-]{1,32}", ch_name):
                return _error(conn, info, "Nom de canal invalide (lettres, chiffres, - et _ ; 32 max)")
            if ch_name in DEFAULT_CHANNELS or data.channel_exists(ch_name):
                return _error(conn, info, f"Le canal '{ch_name}' existe déjà")
            if ch_pass and len(ch_pass) < 6:
                return _error(conn, info, "Le mot de passe du canal doit faire au moins 6 caractères.")

            ch_id = security.generate_id()
            priv_k, pub_k = security.generate_rsa_keypair()
            # secret vide = canal public ; sinon canal privé protégé par un secret haché (Argon2)
            data.create_channel(ch_id, ch_name, security.argon2_hash_password(ch_pass) if ch_pass else "",
                                user_id, priv_k.decode(), pub_k.decode(), is_private=bool(ch_pass))
            data.add_member(ch_id, user_id)

            _enter_channel(conn, info, ch_id)
            if not ch_pass:   # un canal privé n'est annoncé qu'à son créateur
                _broadcast_event("CHANNEL_CREATED", {"id": ch_id, "name": ch_name})
            else:
                _event(conn, info, "CHANNEL_CREATED", {"id": ch_id, "name": ch_name})
            logger.info(f"Canal créé : {ch_name} par {pseudo}")

        elif name == "JOIN_CHANNEL":
            ch_name = str(d.get("name", "")).strip().lower()
            ch_pass = str(d.get("secret", ""))
            # Le client peut aussi rejoindre par identifiant (son "contexte" sauvegardé dans <pseudo>.json)
            ch      = data.get_channel_by_id(d["id"]) if d.get("id") else data.get_channel(ch_name)
            if not ch:
                return _error(conn, info, "Canal introuvable")
            ch_id = ch[0]

            # Expulsion encore active ? (temporaire ou permanente, enregistrée en base)
            remaining = data.ban_remaining(ch_id, user_id)
            if remaining == -1:
                return _error(conn, info, "Vous avez été expulsé définitivement de ce canal.")
            if remaining:
                return _error(conn, info, f"Vous êtes expulsé de ce canal encore {remaining} secondes.")

            if not data.is_member(ch_id, user_id):
                # La clé secrète n'est nécessaire que pour devenir membre une première fois
                if ch[1]:
                    chan_key = [("chan", user_id)]
                    wait = _auth_blocked(chan_key)
                    if wait:
                        return _error(conn, info, f"Trop d'essais : réessaie dans {wait} s")
                    if not security.argon2_verify_password(ch_pass, ch[1]):
                        _auth_failed(chan_key)
                        logger.warning(f"{pseudo} : mauvais secret pour le canal {ch_id}")
                        return _error(conn, info, "Mot de passe incorrect")
                    _auth_succeeded(chan_key)
                data.add_member(ch_id, user_id)
            _enter_channel(conn, info, ch_id)

        elif name == "LEAVE_CHANNEL":
            ch = data.get_channel(str(d.get("name", "")).strip().lower()) if d.get("name") \
                 else data.get_channel_by_id(info.get("channel_id") or "")
            if ch:
                data.remove_member(ch[0], user_id)
            # Retour forcé vers #general
            general = data.get_channel("general")
            if general:
                if not data.is_member(general[0], user_id):
                    data.add_member(general[0], user_id)
                _enter_channel(conn, info, general[0])
                _event(conn, info, "SYSTEM", {"message": "➡️ Retour dans #general"})

        elif name == "DELETE_CHANNEL":
            ch_name = str(d.get("name", "")).strip().lower()
            ch      = data.get_channel(ch_name)
            if not ch:
                return _error(conn, info, "Canal introuvable")
            if ch_name in DEFAULT_CHANNELS:
                return _error(conn, info, f"Impossible de supprimer le canal système '{ch_name}'")
            if ch[2] != user_id:   # owner_id
                return _error(conn, info, "Seul le créateur peut supprimer le canal")

            ch_id = ch[0]
            # Un canal privé n'est annoncé qu'à ses membres : sa suppression aussi
            notify_ids = set(data.get_member_ids(ch_id)) | {user_id} if ch[5] else None
            data.delete_channel(ch_id)
            general = data.get_channel("general")
            with clients_lock:
                for c_conn, c_info in list(clients.items()):
                    if c_info.get("channel_id") == ch_id:
                        c_info["channel_id"] = general[0] if general else None
                    if notify_ids is not None and c_info.get("user_id") not in notify_ids:
                        continue
                    try:
                        _event(c_conn, c_info, "CHANNEL_DELETED", {"id": ch_id, "name": ch_name})
                    except Exception:
                        pass
            logger.info(f"{pseudo} a supprimé '{ch_name}'")

        elif name == "KICK_CHANNEL_MEMBER":
            ch_name = str(d.get("channel_name", "")).strip().lower()
            target  = str(d.get("member_name", "")).strip()
            ch      = data.get_channel(ch_name)
            if not ch:
                return _error(conn, info, "Canal introuvable")
            if ch_name in DEFAULT_CHANNELS:
                return _error(conn, info, f"Impossible de kicker dans le canal système '#{ch_name}'")
            if ch[2] != user_id:   # Seul le créateur peut kicker
                return _error(conn, info, "Seul le créateur peut kicker")

            target_user = data.get_user(target)
            if not target or not target_user or target_user[0] == user_id:
                return _error(conn, info, f"Impossible de kicker '{target}'")
            target_id = target_user[0]
            duration  = int(d["duration"]) if str(d.get("duration", "")).isdigit() else 0

            data.remove_member(ch[0], target_id)
            data.ban_member(ch[0], target_id, int(time.time()) + duration if duration > 0 else None)
            if duration > 0:
                msg = f"Expulsé de #{ch_name} pour {duration} s"
            else:
                msg = f"Expulsé définitivement de #{ch_name}"

            general = data.get_channel("general")
            with clients_lock:
                victims = [(c, i) for c, i in clients.items()
                           if i.get("user_id") == target_id and i.get("channel_id") == ch[0]]
            for c_conn, c_info in victims:
                _event(c_conn, c_info, "KICKED", {"message": msg})
                if general:
                    if not data.is_member(general[0], target_id):
                        data.add_member(general[0], target_id)
                    _enter_channel(c_conn, c_info, general[0])
            _event(conn, info, "KICK_SUCCESS", {"target": target, "duration": duration})
            logger.info(f"{pseudo} a kické '{target}' de '#{ch_name}' ({duration}s)")

        elif name == "UPDATE_USER":
            # Le client signale son activité : last_activity_at est mis à jour et les autres
            # clients en sont informés (évènement USER_UPDATED). Au plus un envoi toutes les 30 s.
            data.touch_user(pseudo)
            if time.time() - info.get("last_user_update", 0) >= 30:
                info["last_user_update"] = time.time()
                _broadcast_event("USER_UPDATED", {"id": user_id, "name": pseudo,
                                                  "last_activity_at": data.get_user_activity(pseudo)})

        else:
            logger.warning(f"Instruction inconnue : {name}")

    except Exception as e:
        logger.error(f"Erreur _handle_statement ({name}) : {e}")


# ====================== MESSAGES (canal ou privés) ======================

def _handle_message(conn, info: dict, payload: bytes):
    """Valide (schéma JSON), authentifie (checksum + signature RSA), persiste et distribue un message."""
    pseudo, user_id = info["pseudo"], info["user_id"]
    msg = parse_message(payload)
    if not msg:
        logger.warning(f"Message invalide (schéma JSON) de {pseudo}")
        return _error(conn, info, "Message invalide")

    sender, recipient, pl, integrity = msg["sender"], msg["recipient"], msg["payload"], msg["integrity"]
    ts = msg["timestamp"]

    # 0) Taille et cadence : un message géant (ou un flot de messages) ne doit pas pouvoir bloquer les autres
    if len(pl["cipher_text"]) > MAX_CIPHER_LEN or len(pl["cipher_text_encrypted_key"]) > MAX_KEY_LEN:
        logger.warning(f"Message rejeté : trop volumineux ({pseudo})")
        return _error(conn, info, "Message trop long")
    now    = time.time()
    recent = [t for t in info.get("msg_times", []) if now - t < MSG_WINDOW]
    if len(recent) >= MSG_BURST:
        logger.warning(f"Message rejeté : trop de messages ({pseudo})")
        return _error(conn, info, "Trop de messages : ralentis un peu")
    info["msg_times"] = recent + [now]

    # 1) L'émetteur annoncé doit être l'utilisateur authentifié sur cette connexion
    #    (sinon un utilisateur pourrait signer un message "de la part de" quelqu'un d'autre)
    if sender["id"] != user_id or sender["name"] != pseudo:
        logger.warning(f"Message rejeté : {pseudo} se fait passer pour {sender['name']}")
        return _error(conn, info, "Message rejeté : émetteur invalide")

    # 1 bis) Horodatage plausible : sinon un message daté de 2099 resterait épinglé dans l'historique
    if abs(int(time.time()) - ts) > MAX_CLOCK_DRIFT:
        logger.warning(f"Message rejeté : horodatage hors délai ({pseudo})")
        return _error(conn, info, "Message rejeté : horodatage invalide (horloge déréglée ?)")

    # 2) Somme de contrôle SHA-256 recalculée, puis signature RSA vérifiée avec la clé publique de l'émetteur
    if integrity["checksum"] != security.message_checksum(ts, sender, recipient, pl):
        logger.warning(f"Message rejeté : checksum invalide ({pseudo})")
        return _error(conn, info, "Message rejeté : somme de contrôle invalide")
    pub_key = data.get_user_public_key(pseudo)
    if not pub_key:
        # Pas de clé publique connue = impossible de vérifier = on rejette (et on n'accepte PAS par défaut)
        logger.warning(f"Message rejeté : clé publique inconnue pour {pseudo}")
        return _error(conn, info, "Message rejeté : clé publique inconnue")
    try:
        signature_ok = security.rsa_verify(pub_key.encode(), integrity["checksum"].encode(),
                                           base64.b64decode(integrity["signature"]))
    except Exception:
        signature_ok = False
    if not signature_ok:
        logger.warning(f"Message rejeté : signature invalide ({pseudo})")
        return _error(conn, info, "Message rejeté : signature invalide")

    # 3) Distribution selon le type de destinataire
    to_forward = json.dumps(dict(msg, sender_public_key=pub_key)).encode()

    if recipient["type"] == "CHANNEL":
        ch = data.get_channel_by_id(recipient["id"])
        # Le canal signé doit exister, être celui où se trouve l'émetteur, et l'émetteur doit en être membre
        if not ch or ch[6] != recipient["name"] or recipient["id"] != info.get("channel_id") \
                or not data.is_member(ch[0], user_id):
            logger.warning(f"Message rejeté : destinataire canal invalide ({pseudo})")
            return _error(conn, info, "Message rejeté : canal invalide")

        data.save_channel_message(security.generate_id(), ts, user_id, ch[0], pl["cipher_text"],
                                  pl["cipher_text_size"], pl["cipher_text_encrypted_key"],
                                  integrity["checksum"], integrity["signature"])
        member_ids = data.get_member_ids(ch[0])
        with clients_lock:
            others = [(c, i) for c, i in clients.items()
                      if c is not conn and i.get("channel_id") == ch[0] and i["user_id"] in member_ids]
        for c, i in others:
            try:
                _send(c, i, ExchangeType.MESSAGE, to_forward)
            except Exception:
                pass
        logger.info(f"Message de {pseudo} sauvegardé et distribué dans #{ch[6]}")

    else:  # USER : message privé
        target = data.get_user_by_id(recipient["id"])
        if not target or target[1] != recipient["name"]:
            return _error(conn, info, f"Utilisateur '{recipient['name']}' introuvable")

        data.save_private_message(security.generate_id(), ts, user_id, target[0], pl["cipher_text"],
                                  pl["cipher_text_size"], pl["cipher_text_encrypted_key"],
                                  integrity["checksum"], integrity["signature"])
        _send_to_user(target[0], ExchangeType.MESSAGE, to_forward)   # livré tout de suite si connecté
        _event(conn, info, "PM_SENT", {"target": target[1]})
        logger.info(f"Message privé de {pseudo} vers {target[1]} sauvegardé")


# ====================== CONNEXION D'UN CLIENT ======================

def handle(conn, addr):
    logger.info(f"Nouvelle connexion : {addr}")
    info = {}
    try:
        conn.settimeout(HANDSHAKE_TIMEOUT)   # une connexion muette ne bloque plus un thread indéfiniment
        pseudo, user_id, cipher = _handshake(conn, addr)
        conn.settimeout(None)
        info = {"pseudo": pseudo, "user_id": user_id, "cipher": cipher, "channel_id": None}
        with clients_lock:
            clients[conn] = info

        # Auto-join du canal #general : clés + 20 derniers messages (canal + privés)
        general = data.get_channel("general")
        if general:
            if not data.is_member(general[0], user_id):
                data.add_member(general[0], user_id)
            _enter_channel(conn, info, general[0])
            logger.info(f"{pseudo} a rejoint automatiquement #general")
        _broadcast_user_list()

        while True:
            exchange = network.receive_exchange(conn)
            if not exchange:
                break
            ex_type, raw = exchange
            try:
                decrypted = cipher.open(ex_type, raw)   # échoue si la trame est modifiée ou rejouée
            except Exception:
                logger.warning(f"Trame invalide ou rejouée de {pseudo} ({addr[0]}) : connexion coupée")
                break
            logger.debug(f"Échange de type {ex_type} reçu de {pseudo} ({len(decrypted)} octets)")
            data.touch_user(pseudo)   # last_activity_at mis à jour à chaque échange

            if ex_type == ExchangeType.STATEMENT.value:
                _handle_statement(conn, info, decrypted)
            elif ex_type == ExchangeType.MESSAGE.value:
                _handle_message(conn, info, decrypted)
            else:
                logger.warning(f"Type d'échange inattendu ({ex_type}) de {pseudo}")

    except PermissionError as e:
        logger.warning(str(e))
    except TimeoutError:
        logger.warning(f"{addr} : poignée de main non terminée en {HANDSHAKE_TIMEOUT} s, connexion coupée")
    except ConnectionError as e:
        logger.info(f"{addr} : {e}")
    except Exception as e:
        logger.error(f"Erreur avec {addr} : {e}")
    finally:
        with clients_lock:
            clients.pop(conn, None)
        try:
            conn.close()
        except Exception:
            pass
        with _conn_lock:
            _conn_per_ip[addr[0]] = _conn_per_ip.get(addr[0], 1) - 1
        logger.info(f"Déconnexion : {info.get('pseudo', addr)}")
        if info.get("pseudo"):
            _broadcast_user_list()


def main():
    srv = network.start_tcp_server('0.0.0.0', 4000)
    logger.info("=" * 50)
    logger.info("  Serveur SecSyChat démarré sur le port 4000")
    logger.info(f"  Empreinte de server.pub : {security.key_fingerprint(SERVER_PUB)}")
    logger.info("=" * 50)
    while True:
        conn, addr = srv.accept()
        with _conn_lock:
            if _conn_per_ip.get(addr[0], 0) >= MAX_CONN_PER_IP:
                logger.warning(f"Trop de connexions depuis {addr[0]} : refusée")
                conn.close()
                continue
            _conn_per_ip[addr[0]] = _conn_per_ip.get(addr[0], 0) + 1
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
