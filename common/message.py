import json, jsonschema
from typing import Optional

# Structure d'un message (charge déchiffrée de l'échange de type 1) — voir énoncé 3.2.1
_STR = {"type": "string"}

SCHEMA = {
    "type": "object",
    "required": ["timestamp", "sender", "recipient", "payload", "integrity"],
    "properties": {
        "timestamp": {"type": "integer"},
        "sender": {
            "type": "object", "required": ["id", "name"],
            "properties": {"id": _STR, "name": _STR}
        },
        "recipient": {
            "type": "object", "required": ["type", "id", "name"],
            "properties": {"type": {"enum": ["USER", "CHANNEL"]}, "id": _STR, "name": _STR}
        },
        "payload": {
            "type": "object",
            "required": ["cipher_text", "cipher_text_size", "cipher_text_encrypted_key"],
            "properties": {
                "cipher_text": _STR,
                "cipher_text_size": {"type": "integer", "minimum": 0},
                "cipher_text_encrypted_key": _STR
            }
        },
        "integrity": {
            "type": "object", "required": ["checksum", "signature"],
            "properties": {"checksum": _STR, "signature": _STR}
        }
    }
}


def parse_message(payload: bytes) -> Optional[dict]:
    """Décode un message JSON et le valide avec le schéma. Retourne le dict, ou None si invalide."""
    try:
        d = json.loads(payload.decode('utf-8'))
        jsonschema.validate(d, SCHEMA)
        return d
    except Exception:
        return None
