"""This module defines custom exceptions for protocol-related errors."""


class ProtocolError(Exception):
    """Base class for protocol-related errors."""


class RegistrationError(ProtocolError):
    """Registration failed (1601)."""


class ReconnectError(ProtocolError):
    """Reconnection failed (1606)."""


class InvalidRequestError(ProtocolError):
    """Invalid request or protocol state (1607)."""


class ServerProcessingError(ProtocolError):
    """Server failed to process a request (1607)."""
