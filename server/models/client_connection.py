import socket
from enum import IntEnum


class ClientConnection:
    TIMEOUT_SECONDS = 300

    def __init__(self, client_socket: socket.socket, address):
        self.socket = client_socket
        self.address = address
        self.client_id: bytes | None = None
        self.state = ConnectionState.NEW
        self.socket.settimeout(self.TIMEOUT_SECONDS)
        self.pending_filename = None

    @property
    def is_identified(self) -> bool:
        return self.client_id is not None

    def identify(self, client_id: bytes):
        self.client_id = client_id

    def close(self):
        self.socket.close()


class ConnectionState(IntEnum):
    NEW = 1  # Connection has been established but the client has not yet registered
    REGISTERED = 2  # Serves as a pending state for the client to exchange keys.
    READY = 3  # Client has completed the key exchange and is ready to send files.
