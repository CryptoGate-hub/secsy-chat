import secrets, hashlib, json, os, threading
from typing import Tuple
from argon2 import PasswordHasher
from Cryptodome.Cipher import AES, ChaCha20_Poly1305
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256

ph = PasswordHasher()

# --- Argon2 ---
def argon2_hash_password(plain: str) -> str:
    return ph.hash(plain)

def argon2_verify_password(plain: str, hashed: str) -> bool:
    try: return ph.verify(hashed, plain)
    except: return False

# --- AES-GCM (chiffrement transport Diffie-Hellman) ---
def aes_encrypt(data: bytes, key: bytes, aad: bytes = b"") -> Tuple:
    """aad = donnée "associée" : non chiffrée mais authentifiée (ex. : le type d'échange de l'en-tête)."""
    cipher = AES.new(key, AES.MODE_GCM)
    if aad:
        cipher.update(aad)
    ct, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, b"", ct, tag

def aes_decrypt(data: bytes, key: bytes, params: Tuple, aad: bytes = b"") -> bytes:
    nonce, _, tag = params
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    return cipher.decrypt_and_verify(data, tag)

# --- ChaCha20-Poly1305 (chiffrement E2EE par message) ---
def chacha20_encrypt(key: bytes, plaintext: bytes) -> Tuple:
    cipher = ChaCha20_Poly1305.new(key=key)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, ct, tag

def chacha20_decrypt(key: bytes, nonce: bytes, ct: bytes, tag: bytes) -> bytes:
    return ChaCha20_Poly1305.new(key=key, nonce=nonce).decrypt_and_verify(ct, tag)

# --- Diffie-Hellman ---
# Groupe standard RFC 3526 "Group 14" (2048 bits, "safe prime"), reconnu et documenté publiquement.
# L'ancien P (256 bits, bricolé) était cassable par calcul de logarithme discret
# avec du matériel grand public : trop court pour un échange de clé sérieux.
P = int(
    "FFFFFFFF" "FFFFFFFF" "C90FDAA2" "2168C234" "C4C6628B" "80DC1CD1"
    "29024E08" "8A67CC74" "020BBEA6" "3B139B22" "514A0879" "8E3404DD"
    "EF9519B3" "CD3A431B" "302B0A6D" "F25F1437" "4FE1356D" "6D51C245"
    "E485B576" "625E7EC6" "F44C42E9" "A637ED6B" "0BFF5CB6" "F406B7ED"
    "EE386BFB" "5A899FA5" "AE9F2411" "7C4B1FE6" "49286651" "ECE45B3D"
    "C2007CB8" "A163BF05" "98DA4836" "1C55D39A" "69163FA8" "FD24CF5F"
    "83655D23" "DCA3AD96" "1C62F356" "208552BB" "9ED52907" "7096966D"
    "670C354E" "4ABC9804" "F1746C08" "CA18217C" "32905E46" "2E36CE3B"
    "E39E772C" "180E8603" "9B2783A2" "EC07A28F" "B5C55DF0" "6F4C52C9"
    "DE2BCBF6" "95581718" "3995497C" "EA956AE5" "15D22618" "98FA0510"
    "15728E5A" "8AACAA68" "FFFFFFFF" "FFFFFFFF", 16
)
G = 2

def diffie_hellman_generate_public_parameters() -> Tuple[int, int]:
    return P, G

def diffie_hellman_generate_private_key(p: int) -> int:
    return secrets.randbelow(p - 4) + 2

def diffie_hellman_compute_public_key(priv: int, p: int, g: int) -> int:
    return pow(g, priv, p)

def diffie_hellman_compute_shared_secret(priv: int, peer_pub: int, p: int) -> int:
    # Une clé publique 0, 1 ou p-1 donnerait un secret prévisible : on la refuse.
    if not 2 <= peer_pub <= p - 2:
        raise ValueError("Clé publique Diffie-Hellman invalide")
    return pow(peer_pub, priv, p)

def diffie_hellman_derive_shared_key(shared_secret: int, key_length: int = 32) -> bytes:
    # Dérivation propre via SHA-256 (bien mieux que str()[:32])
    return hashlib.sha256(str(shared_secret).encode()).digest()[:key_length]

# --- Chiffrement du transport : AES-GCM + compteur anti-rejeu ---
class TransportCipher:
    """Chiffre / déchiffre les échanges d'une session (clé de transport issue du Diffie-Hellman).

    Anti-rejeu : chaque sens (client -> serveur, serveur -> client) a son propre compteur.
    Le compteur n'est PAS envoyé sur le réseau : TCP garantit l'ordre, donc les deux côtés
    savent quel numéro attendre. Il est mis dans la donnée associée (AAD) d'AES-GCM avec le
    type d'échange et le sens. Une trame rejouée (ou renvoyée dans l'autre sens) porte un
    ancien numéro : la vérification GCM échoue et la connexion est coupée.
    """
    def __init__(self, key: bytes, is_server: bool):
        self.key       = key
        self.send_dir  = b"S" if is_server else b"C"
        self.recv_dir  = b"C" if is_server else b"S"
        self.send_seq  = 0
        self.recv_seq  = 0
        self.lock      = threading.Lock()   # plusieurs threads peuvent envoyer sur la même connexion

    @staticmethod
    def _aad(ex_type: int, direction: bytes, seq: int) -> bytes:
        return bytes([ex_type]) + direction + seq.to_bytes(8, "big")

    def seal(self, ex_type: int, payload: bytes) -> bytes:
        """À appeler en tenant self.lock, juste avant l'envoi (l'ordre des numéros = l'ordre d'envoi)."""
        nonce, _, ct, tag = aes_encrypt(payload, self.key, self._aad(ex_type, self.send_dir, self.send_seq))
        self.send_seq += 1
        return nonce + ct + tag

    def open(self, ex_type: int, frame: bytes) -> bytes:
        """Déchiffre une trame reçue ; lève une exception si elle est modifiée, rejouée ou hors d'ordre."""
        nonce, ct, tag = frame[:16], frame[16:-16], frame[-16:]
        data = aes_decrypt(ct, self.key, (nonce, b"", tag), self._aad(ex_type, self.recv_dir, self.recv_seq))
        self.recv_seq += 1
        return data


# --- Identité du serveur (authentifie le Diffie-Hellman) ---
def load_or_create_rsa_key(path: str) -> bytes:
    """Charge une clé privée RSA depuis un fichier, ou la crée (clé d'identité du serveur : server.key)."""
    if os.path.exists(path):
        return open(path, "rb").read()
    priv, _ = generate_rsa_keypair()
    with open(path, "wb") as f:
        f.write(priv)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return priv

def key_fingerprint(pub_pem: bytes) -> str:
    """Empreinte courte d'une clé publique (à comparer à l'œil, comme pour SSH)."""
    h = hashlib.sha256(RSA.import_key(pub_pem).publickey().export_key()).hexdigest()[:32]
    return ":".join(h[i:i + 4] for i in range(0, len(h), 4))

def dh_signed_data(server_dh_pub: int, client_dh_pub: int) -> bytes:
    """Ce que le serveur signe : les DEUX clés publiques Diffie-Hellman de la session.
    Une signature d'une ancienne session ne peut donc pas être réutilisée."""
    return f"SECSY-DH|{server_dh_pub}|{client_dh_pub}".encode()


# --- RSA (paires de clés E2EE + signature) ---
def generate_rsa_keypair() -> Tuple[bytes, bytes]:
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()

def rsa_encrypt(pub_pem: bytes, data: bytes) -> bytes:
    return PKCS1_OAEP.new(RSA.import_key(pub_pem)).encrypt(data)

def rsa_decrypt(priv_pem: bytes, data: bytes) -> bytes:
    try: return PKCS1_OAEP.new(RSA.import_key(priv_pem)).decrypt(data)
    except: return b""

def rsa_sign(priv_pem: bytes, data: bytes) -> bytes:
    return pkcs1_15.new(RSA.import_key(priv_pem)).sign(SHA256.new(data))

def rsa_verify(pub_pem: bytes, data: bytes, signature: bytes) -> bool:
    try:
        pkcs1_15.new(RSA.import_key(pub_pem)).verify(SHA256.new(data), signature)
        return True
    except: return False

# --- SHA-256 (somme de contrôle it.7) ---
def sha256_checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def generate_encryption_key(size: int = 256) -> bytes:
    return secrets.token_bytes(size // 8)


# --- Identifiants NanoId (21 caractères, alphabet URL-safe) ---
_NANOID_ALPHABET = "_-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

def generate_id(size: int = 21) -> str:
    """Génère un identifiant au format NanoId (aléatoire cryptographique)."""
    return "".join(secrets.choice(_NANOID_ALPHABET) for _ in range(size))

# --- Intégrité d'un message (somme de contrôle SHA-256 + signature RSA) ---
def message_checksum(timestamp: int, sender: dict, recipient: dict, payload: dict) -> str:
    """Somme de contrôle calculée sur le timestamp, l'émetteur, le destinataire et la charge.

    Le client ET le serveur appellent cette même fonction : ils ne peuvent donc
    pas se tromper sur ce qui est signé. Le destinataire (id, nom) fait partie
    de ce qui est signé : un message ne peut pas être rejoué dans un autre canal.
    """
    body = {"timestamp": timestamp, "sender": sender, "recipient": recipient, "payload": payload}
    return sha256_checksum(json.dumps(body, sort_keys=True).encode())

def rsa_public_from_private(priv_pem: bytes) -> bytes:
    """Retrouve la clé publique à partir de la clé privée (fichier <pseudo>.key)."""
    return RSA.import_key(priv_pem).publickey().export_key()
