import time
from common import database

db_conn = None


# ====================== UTILISATEURS ======================

def user_exists(name: str) -> bool:
    return len(database.select_data(db_conn, "SELECT 1 FROM user WHERE name=?", (name,))) > 0


def similar_user_exists(name: str) -> bool:
    """Vrai si un AUTRE compte porte le même pseudo à la casse près ("bob" alors que "Bob" existe)."""
    return len(database.select_data(db_conn,
        "SELECT 1 FROM user WHERE name=? COLLATE NOCASE AND name<>?", (name, name))) > 0


def create_user(user_id: str, name: str, hashed_password: str):
    database.insert_data(db_conn, "user",
        ("id", "name", "secret"), (user_id, name, hashed_password))


def get_user(name: str):
    """Retourne (id, secret, public_key) ou None."""
    res = database.select_data(db_conn,
        "SELECT id, secret, public_key FROM user WHERE name=?", (name,))
    return res[0] if res else None


def get_user_by_id(user_id: str):
    """Retourne (id, name, public_key) ou None."""
    res = database.select_data(db_conn,
        "SELECT id, name, public_key FROM user WHERE id=?", (user_id,))
    return res[0] if res else None


def get_user_public_key(name: str) -> str:
    res = database.select_data(db_conn,
        "SELECT public_key FROM user WHERE name=?", (name,))
    return res[0][0] if res else None


def set_user_public_key(name: str, pub_key: str):
    database.update_data(db_conn,
        "UPDATE user SET public_key=? WHERE name=?", (pub_key, name))


def touch_user(name: str):
    """Met à jour last_activity_at à chaque échange (it.3)."""
    database.update_data(db_conn,
        "UPDATE user SET last_activity_at=CURRENT_TIMESTAMP WHERE name=?", (name,))


def get_user_activity(name: str) -> str:
    """Retourne last_activity_at (texte "AAAA-MM-JJ HH:MM:SS", UTC) ou ""."""
    res = database.select_data(db_conn, "SELECT last_activity_at FROM user WHERE name=?", (name,))
    return res[0][0] if res else ""


# ====================== CANAUX ======================

def channel_exists(name: str) -> bool:
    return len(database.select_data(db_conn,
        "SELECT 1 FROM channel WHERE name=?", (name,))) > 0


def create_channel(ch_id: str, name: str, hashed_secret: str, owner_id: str,
                   priv_key: str = "", pub_key: str = "", is_private: bool = False):
    database.insert_data(db_conn, "channel",
        ("id", "name", "secret", "owner_id", "private_key", "public_key", "is_private"),
        (ch_id, name, hashed_secret, owner_id, priv_key, pub_key, 1 if is_private else 0))


def get_channel(name: str):
    """Retourne (id, secret, owner_id, private_key, public_key, is_private) ou None."""
    res = database.select_data(db_conn,
        "SELECT id, secret, owner_id, private_key, public_key, is_private FROM channel WHERE name=?",
        (name,))
    return res[0] if res else None


def get_channel_by_id(ch_id: str):
    """Retourne (id, secret, owner_id, private_key, public_key, is_private, name) ou None."""
    res = database.select_data(db_conn,
        "SELECT id, secret, owner_id, private_key, public_key, is_private, name FROM channel WHERE id=?",
        (ch_id,))
    return res[0] if res else None


def get_public_channels() -> list:
    res = database.select_data(db_conn,
        "SELECT name FROM channel WHERE is_private=0 ORDER BY name")
    return [r[0] for r in res]


def get_all_channels() -> list:
    res = database.select_data(db_conn, "SELECT name FROM channel ORDER BY name")
    return [r[0] for r in res]


def is_private_channel(name: str) -> bool:
    res = database.select_data(db_conn,
        "SELECT is_private FROM channel WHERE name=?", (name,))
    return bool(res[0][0]) if res else False


def get_user_channels(user_id: str) -> list:
    """Canaux auxquels l'utilisateur appartient."""
    res = database.select_data(db_conn, """
        SELECT c.name FROM channel c
        JOIN channel_member m ON c.id = m.channel_id
        WHERE m.user_id = ? ORDER BY c.name
    """, (user_id,))
    return [r[0] for r in res]


def delete_channel(channel_id: str):
    """Supprime un canal, ses membres et ses messages."""
    database.delete_data(db_conn, "DELETE FROM channel_message WHERE recipient_id=?", (channel_id,))
    database.delete_data(db_conn, "DELETE FROM channel_member WHERE channel_id=?", (channel_id,))
    database.delete_data(db_conn, "DELETE FROM channel_ban WHERE channel_id=?", (channel_id,))
    database.delete_data(db_conn, "DELETE FROM channel WHERE id=?", (channel_id,))


# ====================== MEMBRES ======================

def add_member(channel_id: str, user_id: str):
    database.insert_data(db_conn, "channel_member",
        ("channel_id", "user_id"), (channel_id, user_id))


def remove_member(channel_id: str, user_id: str):
    database.delete_data(db_conn,
        "DELETE FROM channel_member WHERE channel_id=? AND user_id=?",
        (channel_id, user_id))


def is_member(channel_id: str, user_id: str) -> bool:
    return len(database.select_data(db_conn,
        "SELECT 1 FROM channel_member WHERE channel_id=? AND user_id=?",
        (channel_id, user_id))) > 0


def get_member_ids(channel_id: str) -> list:
    res = database.select_data(db_conn,
        "SELECT user_id FROM channel_member WHERE channel_id=?", (channel_id,))
    return [r[0] for r in res]


# ====================== EXPULSIONS ======================

def ban_member(channel_id: str, user_id: str, until: int = None):
    """Expulse un membre : until = fin de l'expulsion (timestamp Unix), None = permanente."""
    database.delete_data(db_conn, "DELETE FROM channel_ban WHERE channel_id=? AND user_id=?",
                         (channel_id, user_id))
    database.insert_data(db_conn, "channel_ban", ("channel_id", "user_id", "until"),
                         (channel_id, user_id, until))


def ban_remaining(channel_id: str, user_id: str):
    """None = pas expulsé ; -1 = expulsion permanente ; sinon secondes restantes."""
    res = database.select_data(db_conn,
        "SELECT until FROM channel_ban WHERE channel_id=? AND user_id=?", (channel_id, user_id))
    if not res:
        return None
    until = res[0][0]
    if until is None:
        return -1
    if until > time.time():
        return max(1, int(until - time.time()))   # jamais 0 tant que l'expulsion court
    database.delete_data(db_conn, "DELETE FROM channel_ban WHERE channel_id=? AND user_id=?",
                         (channel_id, user_id))   # expulsion temporaire terminée
    return None


# ====================== MESSAGES DE CANAL ======================

def save_channel_message(msg_id: str, ts: int, sender_id: str, recipient_id: str,
                         cipher_text: str, cipher_size: int, encrypted_key: str,
                         checksum: str, signature: str):
    """Persiste un message de canal en BDD (it.4)."""
    database.insert_data(db_conn, "channel_message",
        ("id", "timestamp", "sender_id", "recipient_id", "payload_cipher_text",
         "payload_cipher_text_size", "payload_cipher_text_encrypted_key",
         "integrity_checksum", "integrity_signature"),
        (msg_id, ts, sender_id, recipient_id, cipher_text,
         cipher_size, encrypted_key, checksum, signature))


def _row_to_message(row, recipient_type: str) -> dict:
    """Transforme une ligne SQL en message complet (structure de l'énoncé, 3.2.1)."""
    return {
        "timestamp": int(row[0]),
        "sender":    {"id": row[1], "name": row[2]},
        "recipient": {"type": recipient_type, "id": row[3], "name": row[4]},
        "payload":   {"cipher_text": row[5], "cipher_text_size": row[6],
                      "cipher_text_encrypted_key": row[7]},
        "integrity": {"checksum": row[8], "signature": row[9]},
        "sender_public_key": row[10] or ""   # pour que le client puisse vérifier la signature
    }


def get_last_messages(channel_id: str, n: int = 20) -> list:
    """Retourne les N derniers messages d'un canal, en ordre chronologique (it.6)."""
    res = database.select_data(db_conn, """
        SELECT m.timestamp, u.id, u.name, c.id, c.name,
               m.payload_cipher_text, m.payload_cipher_text_size, m.payload_cipher_text_encrypted_key,
               m.integrity_checksum, m.integrity_signature, u.public_key
        FROM channel_message m
        JOIN user u    ON m.sender_id = u.id
        JOIN channel c ON m.recipient_id = c.id
        WHERE m.recipient_id = ?
        ORDER BY m.timestamp DESC LIMIT ?
    """, (channel_id, n))
    return [_row_to_message(r, "CHANNEL") for r in reversed(res)]


# ====================== MESSAGES PRIVÉS ======================

def save_private_message(msg_id: str, ts: int, sender_id: str, recipient_id: str,
                         cipher_text: str, cipher_size: int, encrypted_key: str,
                         checksum: str, signature: str):
    """Persiste un message privé en BDD (it.8)."""
    database.insert_data(db_conn, "private_message",
        ("id", "timestamp", "sender_id", "recipient_id", "payload_cipher_text",
         "payload_cipher_text_size", "payload_cipher_text_encrypted_key",
         "integrity_checksum", "integrity_signature"),
        (msg_id, ts, sender_id, recipient_id, cipher_text,
         cipher_size, encrypted_key, checksum, signature))

def get_last_private_messages(user_id: str, n: int = 20) -> list:
    """Retourne les N derniers messages privés reçus par cet utilisateur, en ordre chronologique."""
    res = database.select_data(db_conn, """
        SELECT m.timestamp, s.id, s.name, r.id, r.name,
               m.payload_cipher_text, m.payload_cipher_text_size, m.payload_cipher_text_encrypted_key,
               m.integrity_checksum, m.integrity_signature, s.public_key
        FROM private_message m
        JOIN user s ON m.sender_id = s.id
        JOIN user r ON m.recipient_id = r.id
        WHERE m.recipient_id = ?
        ORDER BY m.timestamp DESC LIMIT ?
    """, (user_id, n))
    return [_row_to_message(r, "USER") for r in reversed(res)]
