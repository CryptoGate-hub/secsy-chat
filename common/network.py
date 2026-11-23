import socket, struct, time


def start_tcp_server(ip: str, port: int) -> socket.socket:
    """
    Démarre un socket TCP qui écoute en mode "serveur" sur une IPv4 et un port précis
    :param ip l'adresse IPv4 sur laquelle écouter
    :param port le port sur lequel écouter
    :return le socket "server" créé
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(5)                    # Permet de gérer plusieurs connexions en attente
    return s


def connect_tcp_server(ip: str, port: int, retry: int = 5) -> socket.socket:
    """
    Crée un socket TCP qui tente de se connecter à un serveur en utilisant une IPv4 et un port précis.
    En cas d'échec, une nouvelle tentative de connexion a lieu après <retry> secondes
    :param ip l'adresse IPv4 à utiliser pour se connecter
    :param port le port à utiliser pour se connecter
    :param retry le nombre de seconde à attendre avant de tenter une nouvelle connexion
    :return: le socket "client" créé
    """
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((ip, int(port)))
            s.settimeout(None)   # Désactive le timeout après connexion réussie
            return s
        except Exception:
            retry -= 1
            if retry <= 0:
                raise
            time.sleep(2)


# En-tête de 11 octets : 10 octets = taille de la charge, 1 octet = type d'échange
# (0 = pas un échange : poignée de main ; 1 = message ; 2 = instruction ; 3 = évènement)
HEADER_SIZE   = 11
SIZE_BYTES    = 10
MAX_PAYLOAD   = 10 * 1024 * 1024   # 10 Mo : refuse les tailles absurdes annoncées par un pair malveillant


def send_message(sock: socket.socket, message: bytes, ex_type: int = 0):
    """
    Envoie un message sur le réseau avec un en-tête de 11 octets (taille sur 10 octets + type sur 1 octet)
    :param sock le socket à utiliser pour envoyer le message
    :param message le message à envoyer en bytes
    :param ex_type le type d'échange (1 octet, 0 par défaut)
    """
    if not message:
        return
    try:
        header = len(message).to_bytes(SIZE_BYTES, "big") + bytes([ex_type])
        sock.sendall(header + message)
    except OSError:
        pass  # La gestion d'erreur sera faite dans le caller (la lecture suivante échouera)


def receive_exchange(sock: socket.socket) -> tuple | None:
    """
    Réceptionne un échange complet : lit l'en-tête de 11 octets puis la charge
    :param sock le socket à utiliser pour réceptionner
    :return (type d'échange, charge en bytes) ou None si la connexion est fermée / invalide
    """
    header = _recv_exact(sock, HEADER_SIZE)
    if not header:
        return None
    size    = int.from_bytes(header[:SIZE_BYTES], "big")
    ex_type = header[SIZE_BYTES]
    if size > MAX_PAYLOAD:
        return None
    if size == 0:
        return ex_type, b""
    payload = _recv_exact(sock, size)
    if payload is None:
        return None
    return ex_type, payload


def receive_message(sock: socket.socket) -> bytes | None:
    """
    Réceptionne un message sur le réseau (en-tête de 11 octets) et renvoie uniquement la charge
    :param sock le socket à utiliser pour réceptionner le message
    :return le message réceptionné en bytes
    """
    exchange = receive_exchange(sock)
    return exchange[1] if exchange else None


def send_message_as_str(sock: socket.socket, message: str):
    """
    Envoie un message sur le réseau (version string)
    :param socket le socket à utiliser pour envoyer le message
    :param message le message à envoyer en tant que chaîne de caractères
    """
    if not message:
        return
    send_message(sock, message.encode('utf-8'))


def receive_message_as_str(sock: socket.socket) -> str | None:
    """
    Réceptionne un message sur le réseau (version string)
    :param socket le socket à utiliser pour réceptionner le message
    :return le message réceptionné en tant que chaîne de caractères
    """
    data = receive_message(sock)
    return data.decode('utf-8') if data else None


def _recv_exact(sock: socket.socket, n: int) -> bytes | None:
    """Lit exactement n octets depuis le socket."""
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        except OSError:
            return None
    return buf