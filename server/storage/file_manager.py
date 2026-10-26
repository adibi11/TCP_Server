from pathlib import Path

from protocol.exceptions import ProtocolError


def validate_filename(filename: str) -> str:
    """Validates that a filename is safe for saving on the server."""

    if not filename or filename in (".", ".."):
        raise ProtocolError("Invalid filename")

    # Reject directory separators and null bytes.
    if "/" in filename or "\\" in filename or "\x00" in filename:
        raise ProtocolError("Filename must not contain path separators")

    # Reject path traversal sequences.
    if ".." in filename:
        raise ProtocolError("Filename contains invalid path traversal sequence")

    # Reject filenames that could be interpreted as absolute paths.
    if Path(filename).is_absolute():
        raise ProtocolError("Absolute file paths are not allowed")

    return filename
