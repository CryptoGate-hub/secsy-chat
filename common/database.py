import sqlite3
import logging
from sqlite3 import Connection
from typing import List, Tuple

logger = logging.getLogger("Database")


def connect_to_db(path: str) -> Connection:
    """Se connecte à une base de données SQLite et retourne la connection créée"""
    conn = sqlite3.connect(path, check_same_thread=False)
    logger.info(f"Connexion DB établie : {path}")
    return conn


def close_connection(connection: Connection):
    """Ferme la connexion à la base de données"""
    if connection:
        connection.close()


def insert_data(connection: Connection, table: str, columns: Tuple, data: Tuple):
    """Insère un tuple au sein d'une table"""
    placeholders = ", ".join(["?" for _ in data])
    query = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})"
    try:
        connection.execute(query, data)
        connection.commit()
    except Exception as e:
        logger.error(f"Erreur insertion dans {table} : {e}")


def update_data(connection: Connection, query: str, params: Tuple = ()) -> int:
    """Met à jour un ou plusieurs tuples"""
    try:
        cur = connection.execute(query, params)
        connection.commit()
        return cur.rowcount
    except Exception as e:
        logger.error(f"Erreur update : {e}")
        return 0


def delete_data(connection: Connection, query: str, params: Tuple = ()) -> int:
    """Supprime un ou plusieurs tuples"""
    try:
        cur = connection.execute(query, params)
        connection.commit()
        return cur.rowcount
    except Exception as e:
        logger.error(f"Erreur delete : {e}")
        return 0


def select_data(connection: Connection, query: str, params: Tuple = ()) -> List[Tuple]:
    """Sélectionne des tuples"""
    try:
        return connection.execute(query, params).fetchall()
    except Exception as e:
        logger.error(f"Erreur select : {e}")
        return []


def execute_script(connection, path: str):
    """Exécute un script SQL depuis un fichier"""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            connection.executescript(f.read())
        connection.commit()
    except Exception as e:
        logger.error(f"Erreur execute_script : {e}")


def execute_seed(connection):
    """Crée toutes les tables si elles n'existent pas encore (it.3 → it.8)"""
    try:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS user (
                id               TEXT PRIMARY KEY,
                name             TEXT UNIQUE NOT NULL,
                secret           TEXT NOT NULL,
                public_key       TEXT,
                created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_activity_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS channel (
                id          TEXT PRIMARY KEY,
                name        TEXT UNIQUE NOT NULL,
                secret      TEXT NOT NULL,
                private_key TEXT,
                public_key  TEXT,
                is_private  INTEGER DEFAULT 0,
                owner_id    TEXT,
                created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS channel_member (
                channel_id TEXT NOT NULL,
                user_id    TEXT NOT NULL,
                joined_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (channel_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS channel_message (
                id                                TEXT PRIMARY KEY,
                timestamp                         TIMESTAMP    NOT NULL,
                sender_id                         TEXT         NOT NULL,
                recipient_id                      TEXT         NOT NULL,
                payload_cipher_text               TEXT         NOT NULL,
                payload_cipher_text_size          INTEGER      NOT NULL,
                payload_cipher_text_encrypted_key TEXT         NOT NULL,
                integrity_checksum                TEXT         NOT NULL,
                integrity_signature               TEXT         NOT NULL,
                FOREIGN KEY (sender_id)    REFERENCES user(id),
                FOREIGN KEY (recipient_id) REFERENCES channel(id)
            );

            CREATE TABLE IF NOT EXISTS private_message (
                id                                TEXT PRIMARY KEY,
                timestamp                         TIMESTAMP NOT NULL,
                sender_id                         TEXT      NOT NULL,
                recipient_id                      TEXT      NOT NULL,
                payload_cipher_text               TEXT      NOT NULL,
                payload_cipher_text_size          INTEGER   NOT NULL,
                payload_cipher_text_encrypted_key TEXT      NOT NULL,
                integrity_checksum                TEXT      NOT NULL,
                integrity_signature               TEXT      NOT NULL,
                FOREIGN KEY (sender_id)    REFERENCES user(id),
                FOREIGN KEY (recipient_id) REFERENCES user(id)
            );
        """)
        connection.commit()
        logger.info("Seed exécuté avec succès.")
    except Exception as e:
        logger.error(f"Erreur lors du seed : {e}")
