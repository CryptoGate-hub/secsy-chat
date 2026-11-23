import json, jsonschema
from dataclasses import dataclass
from typing import Any

SCHEMA = {
    "type": "object",
    "required": ["timestamp", "payload"],
    "properties": {
        "timestamp": {"type": "integer"},
        "payload": {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {"type": "string"},
                "data": {"type": "object"}
            }
        }
    }
}

@dataclass
class Statement:
    name: str
    data: Any

def parse_statement(payload: bytes) -> Statement:
    try:
        d = json.loads(payload.decode('utf-8'))
        jsonschema.validate(d, SCHEMA)
        return Statement(name=d["payload"]["name"], data=d["payload"].get("data", {}))
    except Exception:
        return None