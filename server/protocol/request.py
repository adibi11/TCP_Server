import struct
from dataclasses import dataclass
from typing import ClassVar

from protocol.codes import RequestCode


@dataclass
class RequestHeader:
    client_id: bytes
    version: int
    code: RequestCode
    payload_size: int

    FORMAT: ClassVar[str] = "<16sBHI"
    SIZE: ClassVar[int] = struct.calcsize(FORMAT)

    @classmethod
    def from_bytes(cls, data: bytes) -> "RequestHeader":
        if len(data) != cls.SIZE:
            raise ValueError(
                f"Invalid header size: expected {cls.SIZE}, got {len(data)}"
            )

        client_id, version, code, payload_size = struct.unpack(cls.FORMAT, data)

        return cls(
            client_id=client_id,
            version=version,
            code=RequestCode(code),
            payload_size=payload_size,
        )


@dataclass
class Request:
    header: RequestHeader


@dataclass
class RegistrationRequest(Request):
    name: str


@dataclass
class PublicKeyRequest(Request):
    name: str
    public_key: bytes


@dataclass
class ReconnectRequest(Request):
    name: str


@dataclass
class FileRequest(Request):
    content_size: int
    original_file_size: int
    packet_number: int
    total_packets: int
    file_name: str
    encrypted_content: bytes


@dataclass
class CRCOKRequest:
    header: RequestHeader
    filename: str


@dataclass
class CRCRetryRequest:
    header: RequestHeader
    filename: str


@dataclass
class CRCAbortRequest:
    header: RequestHeader
    filename: str


@dataclass
class SendFileRequest:
    header: object
    encrypted_size: int
    original_size: int
    packet_number: int
    total_packets: int
    filename: str
    encrypted_content: bytes

    @classmethod
    def from_payload(cls, header, payload: bytes):
        if len(payload) < 267:
            raise ValueError("SEND_FILE payload too short")
        # Unpack the payload to extract the encrypted size, original size, packet number, total packets, filename, and encrypted content.
        # The filename is extracted from the payload and decoded from bytes to a string.
        # The method also performs validation checks on the extracted values to ensure they are valid.
        # If any validation fails, it raises a ValueError with an appropriate message.
        # Finally, it returns an instance of SendFileRequest with the extracted values.
        encrypted_size = int.from_bytes(payload[0:4], "little")
        original_size = int.from_bytes(payload[4:8], "little")
        packet_number = int.from_bytes(payload[8:10], "little")
        total_packets = int.from_bytes(payload[10:12], "little")

        filename = payload[12:267].split(b"\0", 1)[0].decode("ascii")
        encrypted_content = payload[267:]

        if encrypted_size != len(encrypted_content):
            raise ValueError("Encrypted content size mismatch")

        if packet_number != 1 or total_packets != 1:
            raise ValueError("Multi-packet transfer not implemented yet")

        if (
            not filename
            or "/" in filename
            or "\\" in filename
            or filename in (".", "..")
        ):
            raise ValueError("Invalid filename")

        return cls(
            header,
            encrypted_size,
            original_size,
            packet_number,
            total_packets,
            filename,
            encrypted_content,
        )
