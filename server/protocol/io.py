from models.client_connection import ClientConnection
from protocol.codes import ResponseCode
from protocol.response import (
    AckResponse,
    AESKeyResponse,
    FileReceivedResponse,
    RegistrationFailureResponse,
    RegistrationSuccessResponse,
    ResponseHeader,
    ServerErrorResponse,
)

"""This module provides functions for sending and receiving data over a socket connection. 
It includes functions to receive an exact number of bytes from a socket, send various types of responses to clients, and handle errors. 
The functions ensure that the correct data is sent and received according to the protocol specifications."""


def recv_exact(socket, size: int) -> bytes:
    data = bytearray()

    while len(data) < size:
        chunk = socket.recv(size - len(data))

        if not chunk:
            raise ConnectionError("Client disconnected")

        data.extend(chunk)

    return bytes(data)


def send_registration_success(connection: ClientConnection, client_id: bytes):
    response = RegistrationSuccessResponse(client_id)
    connection.socket.sendall(response.to_bytes())


def send_aes_key_response(
    connection: ClientConnection, client_id: bytes, encrypted_aes_key: bytes
):
    response = AESKeyResponse(client_id, encrypted_aes_key)
    connection.socket.sendall(response.to_bytes())


def send_registration_failure(connection: ClientConnection):
    response = RegistrationFailureResponse()
    connection.socket.sendall(response.to_bytes())


def send_reconnect_success(connection, client_id: bytes, encrypted_key: bytes):
    payload = client_id + encrypted_key
    send_response(connection, ResponseCode.RECONNECT_SUCCESS, payload)


def send_reconnect_failure(connection):
    send_response(connection, ResponseCode.RECONNECT_FAILURE, b"")


def send_file_received(
    connection: ClientConnection,
    client_id: bytes,
    encrypted_size: int,
    filename: str,
    crc: int,
):
    response = FileReceivedResponse(client_id, encrypted_size, filename, crc)

    connection.socket.sendall(response.to_bytes())


def send_response(connection, code: ResponseCode, payload: bytes):
    header = ResponseHeader(version=3, code=code, payload_size=len(payload))
    connection.socket.sendall(header.to_bytes() + payload)


def send_crc_ack(connection: ClientConnection, client_id: bytes):
    response = AckResponse(client_id)
    connection.socket.sendall(response.to_bytes())


def send_server_error(connection: ClientConnection):
    response = ServerErrorResponse()
    connection.socket.sendall(response.to_bytes())
