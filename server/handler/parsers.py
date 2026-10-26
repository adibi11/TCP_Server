from protocol.codes import RequestCode
from protocol.exceptions import ProtocolError, ReconnectError, RegistrationError
from protocol.request import (
    CRCAbortRequest,
    CRCOKRequest,
    CRCRetryRequest,
    PublicKeyRequest,
    ReconnectRequest,
    RegistrationRequest,
    Request,
    RequestHeader,
    SendFileRequest,
)

NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160


"""This module provides functions to parse incoming requests from clients. It defines various request types and their corresponding parsing functions. 
The main function, parse_request, takes a RequestHeader and payload as input and returns the appropriate Request object based on the request code. 
Each specific request type has its own parsing function that validates the payload size and extracts relevant information."""

"""Parses a null-terminated ASCII string from the given bytes. It splits the data at the first null byte and decodes the resulting bytes to a string."""


def parse_string(data: bytes) -> str:
    return data.split(b"\0", 1)[0].decode("ascii")


"""Parses an incoming request based on the provided RequestHeader and payload."""


def parse_request(header: RequestHeader, payload: bytes) -> Request:
    ## Match the request code in the header to determine the appropriate parsing function.
    match header.code:
        case RequestCode.REGISTER:
            return parse_registration(header, payload)

        case RequestCode.PUBLIC_KEY:
            return parse_public_key(header, payload)

        case RequestCode.RECONNECT:
            return parse_reconnect(header, payload)

        case RequestCode.SEND_FILE:
            return parse_file(header, payload)

        case RequestCode.CRC_OK:
            return parse_crc_ok(header, payload)

        case RequestCode.CRC_RETRY:
            return parse_crc_retry(header, payload)

        case RequestCode.CRC_ABORT:
            return parse_crc_abort(header, payload)

        case _:
            raise ProtocolError(f"Unknown request code: {header.code}")


"""Parses a registration request, validating the payload size and extracting the client's name."""


def parse_registration(header: RequestHeader, payload: bytes) -> RegistrationRequest:
    if len(payload) != NAME_SIZE:
        raise RegistrationError(
            f"Invalid registration payload size: expected {NAME_SIZE}, got {len(payload)}"
        )

    name = parse_string(payload)
    return RegistrationRequest(header=header, name=name)


"""Parses a public key request, validating the payload size and extracting the client's name and public key."""


def parse_public_key(header: RequestHeader, payload: bytes) -> PublicKeyRequest:
    expected_size = NAME_SIZE + PUBLIC_KEY_SIZE

    if len(payload) != expected_size:
        raise ProtocolError(
            f"Invalid public key payload size: expected {expected_size}, got {len(payload)}"
        )

    name = parse_string(payload[:NAME_SIZE])
    public_key = payload[NAME_SIZE:]

    return PublicKeyRequest(header=header, name=name, public_key=public_key)


"""Parses a reconnect request, validating the payload size and extracting the client's name."""


def parse_reconnect(header: RequestHeader, payload: bytes) -> ReconnectRequest:
    if len(payload) != NAME_SIZE:
        raise ReconnectError(
            f"Invalid reconnect payload size: expected {NAME_SIZE}, got {len(payload)}"
        )

    name = parse_string(payload)
    return ReconnectRequest(header=header, name=name)


"""Parses a file request, validating the payload size and extracting the relevant file information."""


def parse_file(header: RequestHeader, payload: bytes):
    return SendFileRequest.from_payload(header, payload)


"""Parses a CRC OK request, validating the payload size and extracting the filename."""


def parse_crc_ok(header: RequestHeader, payload: bytes):
    filename = parse_crc_filename(payload)
    return CRCOKRequest(header, filename)


"""Parses a CRC Retry request, validating the payload size and extracting the filename."""


def parse_crc_retry(header: RequestHeader, payload: bytes):
    filename = parse_crc_filename(payload)
    return CRCRetryRequest(header, filename)


"""Parses a CRC Abort request, validating the payload size and extracting the filename."""


def parse_crc_abort(header: RequestHeader, payload: bytes):
    filename = parse_crc_filename(payload)
    return CRCAbortRequest(header, filename)


"""Parses the filename from the CRC request payload, ensuring it is null-terminated and valid."""


def parse_crc_filename(payload: bytes) -> str:
    if len(payload) != 255:
        raise ProtocolError("Invalid CRC payload size")

    if b"\0" not in payload:
        raise ProtocolError("Filename must be null-terminated")

    filename = payload.split(b"\0", 1)[0].decode("ascii")

    if not filename or "/" in filename or "\\" in filename:
        raise ProtocolError("Invalid filename")

    return filename
