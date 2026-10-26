import socket
import threading
import uuid
from pathlib import Path

from crypto.crypto import decrypt_with_aes, encrypt_with_rsa, generate_aes_key
from handler.crc import calculate_crc
from handler.parsers import parse_request
from models.client import Client
from models.client_connection import ClientConnection, ConnectionState
from protocol.codes import RequestCode
from protocol.exceptions import (
    InvalidRequestError,
    ProtocolError,
    ReconnectError,
    RegistrationError,
    ServerProcessingError,
)
from protocol.io import (
    recv_exact,
    send_aes_key_response,
    send_crc_ack,
    send_file_received,
    send_reconnect_failure,
    send_reconnect_success,
    send_registration_failure,
    send_registration_success,
    send_server_error,
)
from protocol.request import (
    CRCAbortRequest,
    CRCOKRequest,
    CRCRetryRequest,
    PublicKeyRequest,
    RequestHeader,
)
from storage.file_manager import validate_filename

"""Server class to handle client connections and requests"""


class Server:
    def __init__(self, port: int):
        self.port = port
        """Dictionary to store clients by their UUIDs. Key: client_id (bytes), Value: Client object"""
        self.clients = {}
        """Dictionary to store active connections by client UUIDs. Key: client_id (bytes), Value: ClientConnection object"""
        self.connections = {}
        """Lock to synchronize access to the clients dictionary"""
        self.clients_lock = threading.Lock()
        self.connections_lock = threading.Lock()
        self.running = False

    def run(self):
        """Run the server and listen for incoming connections"""
        host = "0.0.0.0"

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((host, self.port))
        self.socket.listen()
        self.socket.settimeout(0.5)

        self.running = True
        print(f"Server is running on {host}:{self.port}")
        """Using a boolean value to gracefully stop the server when needed. The server will continue to accept connections until self.running is set to False."""
        while self.running:
            try:
                # Accept new client connections, with a timeout to allow for graceful shutdown
                client_socket, client_address = self.socket.accept()
            except TimeoutError:
                continue
            except OSError:
                if not self.running:
                    break
                raise

            print(f"Accepted connection from {client_address}")
            # Create a new ClientConnection object for the accepted client socket and address and start a new thread to handle the client connection
            connection = ClientConnection(client_socket, client_address)

            thread = threading.Thread(
                target=self.handle_client, args=(connection,), daemon=True
            )
            thread.start()

    def stop(self):
        self.running = False

        if hasattr(self, "socket"):
            self.socket.close()

        print("Server stopped")

    def handle_client(self, connection: ClientConnection):
        """Process requests until the client disconnects or times out."""
        try:
            while True:
                try:
                    # Receive the request header and payload from the client socket
                    header_bytes = recv_exact(connection.socket, RequestHeader.SIZE)
                    header = RequestHeader.from_bytes(header_bytes)

                    payload = recv_exact(connection.socket, header.payload_size)
                    # Parse the request and validate it. If the request is invalid, raise an InvalidRequestError.
                    request = parse_request(header, payload)

                    if request is None:
                        raise InvalidRequestError("Unsupported request")

                    self.handle_request(connection, request)

                    print(
                        f"Handled request {request.header.code} "
                        f"from client {connection.client_id}"
                    )
                # Catche exceptions related to protocol errors and handle them gracefully
                except ProtocolError as exc:
                    self.handle_protocol_error(connection, exc)
                    print(f"Protocol error: {exc}")
                    continue

                except ValueError as exc:
                    print(f"Invalid request format: {exc}")
                    send_server_error(connection)
                    break

        except TimeoutError:
            print(f"Client {connection.client_id} timed out")

        except (ConnectionError, OSError) as exc:
            print(f"Connection closed: {exc}")

        finally:
            self.cleanup_connection(connection)

    """Handle protocol-related errors by sending appropriate responses to the client."""

    def handle_protocol_error(self, connection, error):
        if isinstance(error, RegistrationError):
            send_registration_failure(connection)

        elif isinstance(error, ReconnectError):
            send_reconnect_failure(connection)

        elif isinstance(error, (InvalidRequestError, ServerProcessingError)):
            send_server_error(connection)

    """Remove the connection from the active connections dictionary if it is identified. This method is called when a client disconnects or times out."""

    def remove_connection(self, connection: ClientConnection):
        if not connection.is_identified:
            return
        # Use a lock to synchronize access to the connections dictionary and remove the connection if it is identified. This method is called when a client disconnects or times out.
        with self.connections_lock:
            client_id = connection.client_id

            if self.connections.get(client_id) is connection:
                del self.connections[client_id]

    """"Validate the request based on the connection state and request code. If the request is invalid, raise a ProtocolError."""

    def validate_request(self, connection, request):
        code = request.header.code
        state = connection.state

        # Registration and reconnection require a new connection
        if code in (RequestCode.REGISTER, RequestCode.RECONNECT):
            if state != ConnectionState.NEW:
                if code == RequestCode.REGISTER:
                    raise RegistrationError("Registration requires NEW state")
                raise ReconnectError("Reconnection requires NEW state")
            return

        # All other requests require a matching client ID
        if request.header.client_id != connection.client_id:
            raise InvalidRequestError("Client ID does not match connection")

        # Public key exchange requires a registered client
        if code == RequestCode.PUBLIC_KEY:
            if state != ConnectionState.REGISTERED:
                raise InvalidRequestError(
                    "Public key exchange requires REGISTERED state"
                )

        # File transfer requests require a ready connection
        elif code in (
            RequestCode.SEND_FILE,
            RequestCode.CRC_OK,
            RequestCode.CRC_RETRY,
            RequestCode.CRC_ABORT,
        ):
            if state != ConnectionState.READY:
                raise InvalidRequestError("File transfer requests require READY state")

        else:
            raise InvalidRequestError(f"Unsupported request code: {code}")

    """Identify the request code and call the appropriate handler method."""

    # We implement the handlers inside the server in order to have access to the clients and connections dictionaries.
    def handle_request(self, connection: ClientConnection, request):
        # Validate the request based on the connection state and request code. If the request is invalid, raise a ValueError.
        self.validate_request(connection, request)
        print(
            f"Handling request {request.header.code} from client {connection.client_id}"
        )
        match request.header.code:
            case RequestCode.REGISTER:
                self.handle_registration(connection, request)

            case RequestCode.PUBLIC_KEY:
                self.handle_public_key(connection, request)

            case RequestCode.RECONNECT:
                self.handle_reconnect(connection, request)

            case RequestCode.SEND_FILE:
                self.handle_send_file(connection, request)

            case RequestCode.CRC_OK:
                self.handle_crc_ok(connection, request)

            case RequestCode.CRC_RETRY:
                self.handle_crc_retry(connection, request)

            case RequestCode.CRC_ABORT:
                self.handle_crc_abort(connection, request)

    """"Cleanup the connection on diconnection or timeout"""

    def cleanup_connection(self, connection: ClientConnection):
        # If the connection is in REGISTERED state, remove the client from the clients dictionary. Then remove the connection from the connections dictionary and close the socket.
        # Beacuse REGISTER state means the client has requested to connect nut has not been fully identified yet
        if connection.state == ConnectionState.REGISTERED:
            self.remove_client(connection.client_id)

        self.remove_connection(connection)
        connection.close()

    def remove_client(self, client_id: bytes):
        if client_id is None:
            return

        with self.clients_lock:
            self.clients.pop(client_id, None)

    def find_client_by_name(self, name: str):
        with self.clients_lock:
            for client in self.clients.values():
                if client.name == name:
                    return client

        return None

    def handle_registration(self, connection, request):
        # Check if the connection is in NEW state. If not raise a Registration error
        if connection.state != ConnectionState.NEW:
            raise RegistrationError("Registration is only allowed in NEW state")
        # Find the client and create a uuid
        if self.find_client_by_name(request.name) is not None:
            raise RegistrationError("Client with this name is already registered")
        print(f"Registering new client with name {request.name}")
        client_id = uuid.uuid4().bytes
        client = Client(client_id=client_id, name=request.name)
        # set the client in the clients dictionary
        with self.clients_lock:
            self.clients[client_id] = client

        # Update the connection state and identify the client
        connection.identify(client_id)
        connection.state = ConnectionState.REGISTERED
        # Add the connection to the connections dictionary and send a registration success response to the client
        with self.connections_lock:
            self.connections[client_id] = connection
        print(f"Client {request.name} registered with ID {client_id.hex()}")
        send_registration_success(connection, client_id)

    def find_client(self, client_id: bytes) -> Client | None:
        with self.clients_lock:
            return self.clients.get(client_id)

    """Handle the public key exchange request from the client."""

    def handle_public_key(
        self, connection: ClientConnection, request: PublicKeyRequest
    ):
        # Check if the connection is in REGISTERED state. If not raise a ValueError
        if connection.state != ConnectionState.REGISTERED:
            raise RegistrationError("Public key is only allowed after registration")

        # Find the client by its ID and validate the request. If the client is not found or the request is invalid, raise a ValueError.
        client = self.find_client(connection.client_id)

        if client is None:
            raise RegistrationError("Client not found")

        if request.header.client_id != client.client_id:
            raise RegistrationError("Client ID does not match")

        if request.name != client.name:
            raise RegistrationError("Client name does not match")

        # Generate an AES key and encrupt it with the public key
        aes_key = generate_aes_key()
        encrypted_aes_key = encrypt_with_rsa(request.public_key, aes_key)

        # Update the client object with the public key and AES key, send an AES key response to the client, and update the connection state to READY.
        client.public_key = request.public_key
        client.aes_key = aes_key

        send_aes_key_response(connection, client.client_id, encrypted_aes_key)
        connection.state = ConnectionState.READY

    """Handle the reconnect request from the client."""

    def handle_reconnect(self, connection, request):
        # Check if the connection is in NEW state. If not, send a reconnect failure response to the client and return.
        if connection.state != ConnectionState.NEW:
            raise ReconnectError("Reconnect is only allowed in NEW state")

        client_id = request.header.client_id
        print(f"Reconnect request: UUID={client_id.hex()}, name={request.name}")

        # Use a lock to synchronize access to the clients dictionary and validate the client information.
        # If the client is not found or the information does not match, raise a ReconnectError.
        with self.clients_lock:
            client = self.clients.get(client_id)

            if client is None or client.name != request.name or not client.public_key:
                raise ReconnectError("Invalid client information")
        # Use a lock to synchronize access to the connections dictionary and check if the client is already connected.
        # If so, raise a ReconnectError. Otherwise, add the connection to the connections dictionary and identify the client.
        with self.connections_lock:
            if client_id in self.connections:
                raise ReconnectError("Client is already connected")

            self.connections[client_id] = connection
            connection.identify(client_id)

        try:
            # Generate a new AES key, encrypt it with the client's public key, and update the client object with the new AES key.
            aes_key = generate_aes_key()
            encrypted_key = encrypt_with_rsa(client.public_key, aes_key)

            with self.clients_lock:
                client.aes_key = aes_key

            send_reconnect_success(connection, client_id, encrypted_key)
            # Update the connection state to READY and print the reconnect success message along with the client UUID and state.
            connection.state = ConnectionState.READY

            print(f"Reconnect successful: {client.name}, UUID: {client_id.hex()}")
            print(f"Client UUID: {connection.client_id.hex()}")
            print(f"State: {connection.state}")

            with self.connections_lock:
                print(f"Active connections: {len(self.connections)}")
        # Catch any exceptions that occur during the reconnect process, remove the connection from the connections dictionary,
        # and re-raise the exception to be handled by the caller.
        except Exception:
            self.remove_connection(connection)
            raise

    """Handle the send file request from the client."""

    def handle_send_file(self, connection, request):
        # Check if the connection is in READY state. If not, raise a ProtocolError.
        if connection.state != ConnectionState.READY:
            raise ProtocolError("Client is not ready")
        if (
            connection.pending_filename is not None
            and connection.pending_filename != request.filename
        ):
            raise ProtocolError("Client tried to send multiple files simultaneously")

        client = self.clients.get(connection.client_id)

        if client is None or client.aes_key is None:
            raise ProtocolError("Client AES key not found")

        if request.header.client_id != connection.client_id:
            raise ProtocolError("Client ID mismatch")
        # Decrypt the file content using the client's AES key
        decrypted = decrypt_with_aes(request.encrypted_content, client.aes_key)
        ##Temporary CRC calculation for debugging purposes

        # crc = calculate_crc(decrypted) ^ 1

        # Calculate the CRC of the decrypted file content and compare it with the original size. If they do not match, raise a ProtocolError.
        crc = calculate_crc(decrypted)
        print(f"Server CRC: {crc}")
        if len(decrypted) != request.original_size:
            raise ProtocolError("Original file size mismatch")

        # Create a directory for the received files using the client UUID and save the decrypted file content to the specified filename.
        filename = validate_filename(request.filename)

        output_dir = Path("received_files") / connection.client_id.hex()
        output_dir.mkdir(parents=True, exist_ok=True)

        output_path = output_dir / filename
        output_path.write_bytes(decrypted)

        print(f"Received file: {request.filename}")
        print(f"Encrypted size: {request.encrypted_size}")
        print(f"Decrypted size: {len(decrypted)}")
        print(f"Saved to: {output_path}")
        connection.pending_filename = request.filename
        send_file_received(
            connection,
            connection.client_id,
            request.encrypted_size,
            request.filename,
            crc,
        )

    """Handle the CRC_OK request from the client."""

    def handle_crc_ok(self, connection, request: CRCOKRequest):
        # Validate that the pending file transfer matches the filename in the CRC_OK request. If they do not match, raise a ProtocolError.
        self.validate_pending_file(connection, request.filename)
        # Clear the pending filename and send a CRC acknowledgment to the client. Print a message indicating that the CRC has been confirmed for the specified filename.
        connection.pending_filename = None
        send_crc_ack(connection, connection.client_id)

        print(f"CRC confirmed: {request.filename}")

    """Handle the CRC_RETRY request from the client."""

    def handle_crc_retry(self, connection, request: CRCRetryRequest):
        self.validate_pending_file(connection, request.filename)

        connection.pending_filename = None

        print(f"CRC mismatch: {request.filename}, waiting for retry")

    def handle_crc_abort(self, connection, request: CRCAbortRequest):
        self.validate_pending_file(connection, request.filename)

        connection.pending_filename = None
        send_crc_ack(connection, connection.client_id)

        print(f"File transfer aborted: {request.filename}")

    def validate_pending_file(self, connection, filename):
        print(f"Pending: {connection.pending_filename!r}")
        print(f"Received: {filename!r}")

        if connection.pending_filename != filename:
            raise ProtocolError(f"No pending file transfer for {filename}")
