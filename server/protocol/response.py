import struct
from dataclasses import dataclass
from typing import ClassVar

from protocol.codes import ResponseCode
from protocol.exceptions import ProtocolError

"""
This module defines the response structures used in the protocol. Each response structure is represented as a dataclass."""


@dataclass
class ResponseHeader:
    version: int
    code: ResponseCode
    payload_size: int
    # A class variable that defines the format for struct packing and unpacking.
    # It specifies that the version is an unsigned char (B), the code is an unsigned short (H), and the payload size is an unsigned int (I).
    FORMAT: ClassVar[str] = "<BHI"

    def to_bytes(self) -> bytes:
        return struct.pack(self.FORMAT, self.version, self.code, self.payload_size)


@dataclass
class RegistrationSuccessResponse:
    client_id: bytes

    def to_bytes(self) -> bytes:
        # The to_bytes method converts the RegistrationSuccessResponse instance into bytes. It creates a ResponseHeader with the appropriate version,
        # code, and payload size, and then concatenates the header bytes with the client_id bytes to form the complete response.
        header = ResponseHeader(
            version=3,
            code=ResponseCode.REGISTER_SUCCESS,
            payload_size=len(self.client_id),
        )

        return header.to_bytes() + self.client_id


@dataclass
class AESKeyResponse:
    client_id: bytes
    encrypted_aes_key: bytes

    def to_bytes(self) -> bytes:
        payload = self.client_id + self.encrypted_aes_key
        header = ResponseHeader(
            version=3, code=ResponseCode.AES_KEY, payload_size=len(payload)
        )

        return header.to_bytes() + payload


@dataclass
class RegistrationFailureResponse:
    def to_bytes(self) -> bytes:
        header = ResponseHeader(
            version=3, code=ResponseCode.REGISTER_FAILURE, payload_size=0
        )

        return header.to_bytes()


@dataclass
class FileReceivedResponse:
    client_id: bytes
    encrypted_size: int
    filename: str
    crc: int

    def to_bytes(self) -> bytes:
        filename_bytes = self.filename.encode("ascii")

        if len(self.client_id) != 16:
            raise ProtocolError("Invalid client ID")

        if len(filename_bytes) >= 255:
            raise ProtocolError("Filename too long")

        payload = (
            self.client_id
            + struct.pack("<I", self.encrypted_size)
            + filename_bytes.ljust(255, b"\0")
            + struct.pack("<I", self.crc)
        )

        header = ResponseHeader(
            version=3, code=ResponseCode.FILE_RECEIVED, payload_size=len(payload)
        )

        return header.to_bytes() + payload


@dataclass
class AckResponse:
    client_id: bytes

    def to_bytes(self) -> bytes:
        if len(self.client_id) != 16:
            raise ProtocolError("Invalid client ID")

        header = ResponseHeader(version=3, code=ResponseCode.ACK, payload_size=16)

        return header.to_bytes() + self.client_id


@dataclass
class ServerErrorResponse:
    def to_bytes(self) -> bytes:
        header = ResponseHeader(
            version=3, code=ResponseCode.SERVER_ERROR, payload_size=0
        )

        return header.to_bytes()
