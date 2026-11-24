"""
Tests de sécurité de bout en bout de Secsy Chat.

Lance un VRAI serveur (port 4000, dossier temporaire : ta base et tes clés ne sont pas touchées)
et des clients sans interface qui réutilisent les modules de common/.
Chaque test rejoue une attaque corrigée pendant l'audit : un FAIL = une protection a régressé.

Utilisation (depuis la racine du projet) :  python tests/test_securite.py
"""
import base64, json, os, select, socket, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from common import network, security   # noqa: E402

HOST, PORT = "127.0.0.1", 4000


class Client:
    """Client minimal : même poignée de main que client.py, sans TUI."""

    def __init__(self, pseudo, pw="Password123", priv=None):
        self.pseudo, self.pw = pseudo, pw
        self.priv = priv or security.generate_rsa_keypair()[0]
        self.pub = security.rsa_public_from_private(self.priv)
        self.ch = {}

    def connect(self) -> bool:
        s = self.sock = socket.create_connection((HOST, PORT), timeout=10)
        srv_pub = int(network.receive_message(s).decode())
        p, g = security.diffie_hellman_generate_public_parameters()
        priv = security.diffie_hellman_generate_private_key(p)
        pub = security.diffie_hellman_compute_public_key(priv, p, g)
        network.send_message(s, str(pub).encode())
        key = security.diffie_hellman_derive_shared_key(
            security.diffie_hellman_compute_shared_secret(priv, srv_pub, p))
        pem_b64, sig_b64 = network.receive_message(s).split(b"|", 1)
        if not security.rsa_verify(base64.b64decode(pem_b64), security.dh_signed_data(srv_pub, pub),
                                   base64.b64decode(sig_b64)):
            raise RuntimeError("signature du serveur invalide")
        self.cipher = security.TransportCipher(key, is_server=False)
        creds = json.dumps({"pseudo": self.pseudo, "password": self.pw}).encode()
        network.send_message(s, self.cipher.seal(0, creds))
        resp = network.receive_message(s)
        if not resp or not resp.startswith(b"AUTH_OK|"):
            return False
        self.uid = resp.decode().split("|", 1)[1]
        network.send_message(s, self.pub)
        ts = str(int(time.time()))
        sig = base64.b64encode(security.rsa_sign(self.priv, ts.encode())).decode()
        network.send_message(s, f"{ts}|{sig}".encode())
        return network.receive_message(s) == b"AUTH_OK_RSA"

    def send(self, ex_type, payload):
        with self.cipher.lock:
            network.send_message(self.sock, self.cipher.seal(ex_type, payload), ex_type)

    def stmt(self, name, data=None):
        self.send(2, json.dumps({"timestamp": int(time.time()),
                                 "payload": {"name": name, "data": data or {}}}).encode())

    def drain(self, secs=1.0):
        """Lit ce qui arrive pendant `secs` secondes. 'CLOSED' = le serveur a coupé la connexion."""
        events, end = [], time.time() + secs
        while time.time() < end:
            ready, _, _ = select.select([self.sock], [], [], max(0.05, end - time.time()))
            if not ready:
                break
            ex = network.receive_exchange(self.sock)
            if ex is None:
                events.append(("CLOSED", None))
                break
            ex_type, raw = ex
            try:
                body = json.loads(self.cipher.open(ex_type, raw))
            except Exception:
                events.append(("BAD_FRAME", None))
                break
            if ex_type == 3:
                name, data = body["payload"]["name"], body["payload"]["data"]
                if name == "CHANNEL_JOINED":
                    self.ch = data
                events.append((name, data))
            else:
                events.append(("MESSAGE", body))
        return events

    def message(self, text=None, raw_cipher=None):
        """Message de canal complet (chiffré, checksum, signature). raw_cipher = texte chiffré imposé."""
        key = security.generate_encryption_key(256)
        if raw_cipher is None:
            nonce, ct, tag = security.chacha20_encrypt(key, text.encode())
            raw_cipher, size = nonce + ct + tag, len(text)
        else:
            size = 1
        payload = {"cipher_text": base64.b64encode(raw_cipher).decode(), "cipher_text_size": size,
                   "cipher_text_encrypted_key": base64.b64encode(
                       security.rsa_encrypt(self.ch["public_key"].encode(), key)).decode()}
        sender = {"id": self.uid, "name": self.pseudo}
        recipient = {"type": "CHANNEL", "id": self.ch["id"], "name": self.ch["name"]}
        ts = int(time.time())
        checksum = security.message_checksum(ts, sender, recipient, payload)
        signature = base64.b64encode(security.rsa_sign(self.priv, checksum.encode())).decode()
        return json.dumps({"timestamp": ts, "sender": sender, "recipient": recipient, "payload": payload,
                           "integrity": {"checksum": checksum, "signature": signature}}).encode()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


BARRIER_PREFIX = "Canal introuvable ou vous"   # réponse du serveur à GET_LAST_MESSAGES sur un canal inexistant


def sync(client, timeout=90):
    """Attend que le serveur ait traité TOUT ce que ce client a envoyé avant.
    Le serveur traite les échanges d'une connexion dans l'ordre : on envoie une instruction qui répond
    toujours la même erreur, et on lit jusqu'à cette réponse. Évite les délais fixes (machine lente ou rapide).
    Retourne tous les évènements reçus avant la réponse ('TIMEOUT' ou 'CLOSED' en cas de souci)."""
    client.stmt("GET_LAST_MESSAGES", {"channel_name": "__synchro__"})
    events, end = [], time.time() + timeout
    while time.time() < end:
        for e in client.drain(0.5):
            if e[0] == "ERROR" and e[1].get("message", "").startswith(BARRIER_PREFIX):
                return events
            events.append(e)
            if e[0] == "CLOSED":
                return events
    events.append(("TIMEOUT", None))
    return events


def wait_for(client, name, timeout=30):
    """Lit jusqu'à recevoir un évènement de ce nom (ou 'CLOSED'/'MESSAGE')."""
    events, end = [], time.time() + timeout
    while time.time() < end:
        events += client.drain(0.5)
        if any(e[0] == name for e in events) or any(e[0] == "CLOSED" for e in events):
            break
    return events


results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS  " if ok else "FAIL  ") + name + (f"   ({detail})" if detail else ""), flush=True)


def errors(events, fragment):
    return [e for e in events if e[0] == "ERROR" and fragment in e[1].get("message", "")]


def run_tests():
    alice, bobby = Client("alice"), Client("bobby")
    check("connexion alice et bobby", alice.connect() and bobby.connect())
    sync(alice); sync(bobby)

    # 1. Fonctionnement normal
    alice.send(1, alice.message("salut bobby"))
    check("un message normal est relayé", any(e[0] == "MESSAGE" for e in wait_for(bobby, "MESSAGE")))

    # 2. Rejeu d'une trame du transport
    frame = json.dumps({"timestamp": int(time.time()), "payload": {"name": "GET_USERS", "data": {}}}).encode()
    with alice.cipher.lock:
        sealed = alice.cipher.seal(2, frame)
        network.send_message(alice.sock, sealed, 2)
        network.send_message(alice.sock, sealed, 2)   # même trame, renvoyée telle quelle
    names = [e[0] for e in wait_for(alice, "CLOSED")]
    check("rejeu de trame : traitée une seule fois puis connexion coupée",
          names.count("UPDATED_USERS") == 1 and "CLOSED" in names, str(names))
    alice.close()
    alice = Client("alice", priv=alice.priv); alice.connect(); sync(alice)

    # 3. Essais de mot de passe d'un canal privé
    alice.stmt("CREATE_CHANNEL", {"name": "secret", "secret": "abc123"}); sync(alice)
    wrong = blocked = 0
    for i in range(10):
        bobby.stmt("JOIN_CHANNEL", {"name": "secret", "secret": f"essai{i:03d}"})
        ev = sync(bobby)
        wrong += len(errors(ev, "incorrect"))
        blocked += len(errors(ev, "Trop d'essais"))
    check("mot de passe de canal : blocage après 5 échecs", wrong == 5 and blocked == 5, f"faux={wrong}, bloqués={blocked}")
    bobby.stmt("JOIN_CHANNEL", {"name": "secret", "secret": "abc123"})
    check("le bon mot de passe est refusé pendant le blocage",
          not any(e[0] == "CHANNEL_JOINED" for e in sync(bobby)))

    # 4. Kick d'un utilisateur qui se trouve dans un AUTRE canal
    alice.stmt("CREATE_CHANNEL", {"name": "room"}); sync(alice)
    bobby.stmt("JOIN_CHANNEL", {"name": "room"}); sync(bobby)
    bobby.stmt("JOIN_CHANNEL", {"name": "dev"}); sync(bobby)
    alice.stmt("KICK_CHANNEL_MEMBER", {"channel_name": "room", "member_name": "bobby", "duration": "60"})
    wait_for(alice, "KICK_SUCCESS")      # le serveur envoie les évènements de la victime AVANT celui-ci
    check("kick de #room : bobby (dans #dev) n'est pas déplacé",
          not any(e[0] == "KICKED" for e in sync(bobby)))

    # 5. Messages géants : refusés, et l'historique reste lisible pour les nouveaux arrivants
    alice.stmt("JOIN_CHANNEL", {"name": "general"}); sync(alice)
    refused = 0
    for _ in range(3):
        alice.send(1, alice.message(raw_cipher=os.urandom(4_500_000)))
        refused += len(errors(sync(alice), "trop long"))
    carol = Client("carol"); carol.connect()
    ev = wait_for(carol, "LAST_MESSAGES")
    check("messages géants refusés, historique reçu normalement",
          refused == 3 and any(e[0] == "LAST_MESSAGES" for e in ev) and not any(e[0] == "CLOSED" for e in ev),
          f"refusés={refused}/3")
    carol.close()

    # 6. Rafale de messages, puis retour à la normale
    for i in range(15):
        alice.send(1, alice.message(f"rafale {i}"))
    check("rafale de 15 messages : limitée", len(errors(sync(alice), "Trop de messages")) >= 1)
    time.sleep(10.5)
    alice.send(1, alice.message("x" * 1500))
    check("un message de 1500 caractères reste accepté", not errors(sync(alice), ""))

    # 7. Création de canaux en masse
    mass = Client("masse"); mass.connect(); sync(mass)
    for i in range(12):
        mass.stmt("CREATE_CHANNEL", {"name": f"spam{i}"})
    ev = sync(mass)
    created = sum(1 for e in ev if e[0] == "CHANNEL_CREATED")
    check("création de canaux limitée (5 par minute)", created == 5 and len(errors(ev, "Trop de canaux")) == 7,
          f"créés={created}/12")

    for c in (alice, bobby, mass):
        c.close()


def main():
    probe = socket.socket()
    if probe.connect_ex((HOST, PORT)) == 0:
        sys.exit("Le port 4000 est déjà utilisé (un serveur tourne ?). Arrête-le puis relance les tests.")
    probe.close()
    with tempfile.TemporaryDirectory() as tmp:
        server = subprocess.Popen([sys.executable, os.path.join(ROOT, "server.py")], cwd=tmp,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(40):                      # attend que le serveur écoute
                s = socket.socket()
                if s.connect_ex((HOST, PORT)) == 0:
                    s.close(); break
                s.close(); time.sleep(0.25)
            else:
                sys.exit("Le serveur ne démarre pas.")
            run_tests()
        finally:
            server.terminate()
            server.wait()
    print(f"\n{sum(results)}/{len(results)} tests réussis")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
