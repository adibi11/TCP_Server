from dataclasses import dataclass


@dataclass
class Client:
    client_id: bytes
    name: str
    public_key: bytes | None = None
    aes_key: bytes | None = None
