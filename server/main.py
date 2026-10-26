from pathlib import Path

from server import Server

DEFAULT_PORT = 1369

"""Main file to initialize the server"""


def load_server_port() -> int:
    """Load the server port from the info.port file. If the file does not exist or contains an invalid port, return the default port."""
    path = Path(__file__).resolve().parent / "info.port"

    try:
        port = int(path.read_text(encoding="utf-8").strip())

        if not 1 <= port <= 65535:
            raise ValueError("Port out of range")

        return port

    except (OSError, ValueError) as exc:
        print(f"Warning: Cannot read info.port ({exc}). Using port {DEFAULT_PORT}")
        return DEFAULT_PORT


def main():
    port = load_server_port()
    server = Server(port)

    try:
        server.run()
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
