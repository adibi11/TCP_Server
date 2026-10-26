#include "client.h"
#include <stdexcept>
#include <limits>

#include "file_manager.h"

#include <filesystem>




// Client constructor initializes Winsock and sets up the client with the specified host and port
Client::Client(const std::string& host, uint16_t port, const std::string& name)
    : host(host), port(port), name(name) {

    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        throw std::runtime_error("WSAStartup failed");
}

// Client destructor cleans up the socket and Winsock resources
Client::~Client() {
    if (socket != INVALID_SOCKET)
        closesocket(socket);

    WSACleanup();
}

// Connects to the server using the specified host and port
void Client::connectToServer() {
	// Resolve the server address and port
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* result = nullptr;
    std::string portString = std::to_string(port);

    if (getaddrinfo(host.c_str(), portString.c_str(), &hints, &result) != 0)
        throw std::runtime_error("Could not resolve server address");

	// Attempt to connect to one of the resolved addresses
    for (addrinfo* addr = result; addr != nullptr; addr = addr->ai_next) {
        SOCKET candidate = ::socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

        if (candidate == INVALID_SOCKET)
            continue;
		// Attempt to connect to the server
        if (::connect(candidate, addr->ai_addr, static_cast<int>(addr->ai_addrlen)) == 0) {
            socket = candidate;
            break;
        }
		// If connection fails, close the candidate socket and try the next address
        closesocket(candidate);
    }

	// Free the address information after attempting to connect
    freeaddrinfo(result);

    if (socket == INVALID_SOCKET)
        throw std::runtime_error("Could not connect to server");
}


// Sends all data in the provided vector to the server, ensuring that all bytes are sent
void Client::sendAll(const std::vector<uint8_t>& data) {
    size_t sent = 0;
	// Send data in chunks to handle large payloads and ensure all bytes are sent
    while (sent < data.size()) {
		// Calculate the remaining bytes to send and determine the chunk size
        size_t remaining = data.size() - sent;
        int chunkSize = static_cast<int>(std::min(remaining, static_cast<size_t>(std::numeric_limits<int>::max())));

        int result = send(socket, reinterpret_cast<const char*>(data.data() + sent), chunkSize, 0);

        if (result == SOCKET_ERROR || result == 0)
            throw std::runtime_error("Failed to send data");

        sent += result;
    }
}


// Receives exactly 'size' bytes from the server, handling partial reads and ensuring all requested bytes are received
std::vector<uint8_t> Client::recvExact(size_t size) {
    std::vector<uint8_t> data(size);
    size_t received = 0;

	// Receive data in chunks to handle large payloads and ensure all requested bytes are received
    while (received < size) {
		// Calculate the remaining bytes to receive and determine the chunk size
        size_t remaining = size - received;
        int chunkSize = static_cast<int>(std::min(remaining, static_cast<size_t>(std::numeric_limits<int>::max())));

        int result = recv(socket, reinterpret_cast<char*>(data.data() + received), chunkSize, 0);

        if (result == SOCKET_ERROR || result == 0)
            throw std::runtime_error("Connection closed while receiving data");

        received += result;
    }

    return data;
}

// Sends a request to the server with the specified request code and payload, ensuring that the payload size does not exceed the maximum allowed size
void Client::sendRequest(RequestCode code, const std::vector<uint8_t>& payload) {
    if (payload.size() > UINT32_MAX)
        throw std::runtime_error("Payload too large");

    RequestHeader header;
    header.clientId = clientId;
    header.code = code;
    header.payloadSize = static_cast<uint32_t>(payload.size());


    std::cout << "Sending request " << static_cast<int>(code)
        << " with UUID " << uuidToHex(clientId) << std::endl;

	// Serialize the header and append the payload to create the complete request data
    auto data = serializeHeader(header);
    data.insert(data.end(), payload.begin(), payload.end());

    sendAll(data);
}

// Receives a response from the server, parsing the response header and payload, and ensuring that the response is valid and within acceptable size limits
Response Client::receiveResponse() {
	// Receive the response header (7 bytes) from the server and parse it into a ResponseHeader structure
    auto bytes = recvExact(7);

    std::array<uint8_t, 7> headerBytes{};
    std::copy(bytes.begin(), bytes.end(), headerBytes.begin());

    ResponseHeader header = parseResponseHeader(headerBytes);

	// Validate the response header version and payload size to ensure compatibility and prevent excessive memory allocation
    if (header.version != 3)
        throw std::runtime_error("Unsupported server version");

    if (header.payloadSize > 1024 * 1024)
        throw std::runtime_error("Response payload too large");

	// Receive the response payload based on the size specified in the header
    auto payload = recvExact(header.payloadSize);
    Response response{ header, std::move(payload) };

    if (response.header.code == ResponseCode::SERVER_ERROR) {
        throw std::runtime_error("Server returned error 1607");
    }

    return response;
}


// Registers the client with the server, sending the client's name and receiving a unique client ID (UUID) in response, 
// ensuring that the registration is successful and valid
void Client::registerClient() {

	// Send the registration request with the client's name as the payload
    sendRequest(RequestCode::REGISTER, serializeName(name));
	// Receive the response from the server and validate the registration result
    Response response = receiveResponse();

    if (response.header.code != ResponseCode::REGISTER_SUCCESS)
        throw std::runtime_error("Registration failed");

    if (response.payload.size() != clientId.size())
        throw std::runtime_error("Invalid registration response");
    std::copy(response.payload.begin(), response.payload.end(), clientId.begin());

    std::cout << "Registered with UUID: " << uuidToHex(clientId) << std::endl;
    std::copy(response.payload.begin(), response.payload.end(), clientId.begin());
}

// Converts a 16-byte UUID to its hexadecimal string representation
std::string uuidToHex(const std::array<uint8_t, 16>& id) {
    std::ostringstream stream;

    for (uint8_t byte : id)
        stream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);

    return stream.str();
}

// Exchanges public keys with the server, sending the client's public key and receiving an encrypted AES key in response,
// ensuring that the response is valid and matches the expected client ID
void Client::exchangeKeys() {
	// Serialize the client's name and prepare the payload for the key exchange request
    std::vector<uint8_t> payload = serializeName(name);

    std::string publicKey = crypto.getPublicKey();

    if (publicKey.size() != 160)
        throw std::runtime_error("Invalid RSA public key size");

    payload.insert(payload.end(), publicKey.begin(), publicKey.end());

	// Send the public key to the server and receive the response containing the encrypted AES key
    sendRequest(RequestCode::PUBLIC_KEY, payload);

	// Receive the response from the server and validate the key exchange result
    Response response = receiveResponse();

    if (response.header.code != ResponseCode::AES_KEY)
        throw std::runtime_error("Key exchange failed");

    if (response.payload.size() != 144)
        throw std::runtime_error("Invalid AES response size");

    if (!std::equal(clientId.begin(), clientId.end(), response.payload.begin()))
        throw std::runtime_error("Client ID mismatch in AES response");
    std::string encryptedKey( response.payload.begin() + 16, response.payload.end());

    aesKey = crypto.decryptWithRSA(encryptedKey);

    if (aesKey.size() != 32)
        throw std::runtime_error("Invalid AES key size");

    std::cout << "AES key decrypted successfully: "
        << aesKey.size() << " bytes" << std::endl;
    std::cout << "Received encrypted AES key" << std::endl;
}


// Loads the client's identity from storage, importing the private key and setting the client's name and ID
bool Client::loadIdentity() {
	// Check if the identity storage exists, and if not, return false indicating that no identity was loaded
    if (!storage.exists())
        return false;

	// Load the client's identity from storage, which includes the name, client ID, and private key
    ClientIdentity identity = storage.load();
	// Import the private key into the CryptoManager for cryptographic operations
    crypto.importPrivateKey(identity.privateKey);
	// Set the client's name and ID based on the loaded identity
    name = identity.name;
    clientId = identity.clientId;

    std::cout << "Loaded identity: " << uuidToHex(clientId) << std::endl;
    return true;
}


// Saves the client's identity to storage, including the name, client ID, and private key

// Saves the client identity, optionally replacing previously stored credentials.
void Client::saveIdentity(bool override) const {
    ClientIdentity identity{
        name,
        clientId,
        crypto.exportPrivateKey()
    };

    if (override)
        storage.replace(identity);
    else
        storage.save(identity);

    std::cout << "Identity saved successfully" << std::endl;
}


// Reconnects the client to the server, sending a reconnect request and receiving an encrypted AES key in response,
void Client::reconnect() {
	// Send the reconnect request with the client's name as the payload
    sendRequest(RequestCode::RECONNECT, serializeName(name));
	// Receive the response from the server and validate the reconnect result
    Response response = receiveResponse();

    if (response.header.code == ResponseCode::RECONNECT_FAILURE) {
        std::cout << "Reconnect rejected. Registering as a new client...\n";

        registerClient();
        exchangeKeys();
        saveIdentity(true); // Allow replacing the previous identity.

        return;
    }
    if (response.header.code != ResponseCode::RECONNECT_SUCCESS)
        throw std::runtime_error("Unexpected reconnect response");

    if (response.payload.size() != 144)
        throw std::runtime_error("Invalid reconnect response size");

    if (!std::equal(clientId.begin(), clientId.end(), response.payload.begin()))
        throw std::runtime_error("Client ID mismatch");

	// Extract the encrypted AES key from the response payload, which starts after the 16-byte client ID and decrypt it using the client's private RSA key
    std::string encryptedKey(response.payload.begin() + 16, response.payload.end());

    aesKey = crypto.decryptWithRSA(encryptedKey);

    if (aesKey.size() != 32)
        throw std::runtime_error("Invalid AES key size");

    std::cout << "Reconnected successfully with UUID: "
        << uuidToHex(clientId) << std::endl;
}

// Builds the payload for sending a file to the server, including the filename, original size, and encrypted data
std::vector<uint8_t> Client::buildFilePayload(
    const std::string& filename,
    uint32_t originalSize,
    const std::string& encrypted
) {
	// Validate the filename to ensure it is not empty, does not exceed 255 characters, and contains only ASCII characters
    if (filename.empty() || filename.size() >= 255)
        throw std::runtime_error("Invalid filename");

    if (!std::all_of(filename.begin(), filename.end(),
        [](unsigned char c) { return c > 0 && c <= 127; }))
        throw std::runtime_error("Filename must be ASCII");
	// Validate the encrypted data size to ensure it does not exceed the maximum allowed size for a 32-bit unsigned integer
    if (encrypted.size() > UINT32_MAX)
        throw std::runtime_error("Encrypted file too large");

	// Prepare the payload vector to hold the serialized data for sending the file
    std::vector<uint8_t> payload;

    auto appendLE = [&](uint32_t value, int bytes) {
        for (int i = 0; i < bytes; ++i)
            payload.push_back(static_cast<uint8_t>(
                (value >> (8 * i)) & 0xFF
                ));
        };

    appendLE(static_cast<uint32_t>(encrypted.size()), 4);
    appendLE(originalSize, 4);
    appendLE(1, 2);  // Packet number
    appendLE(1, 2);  // Total packets

    payload.insert(payload.end(), filename.begin(), filename.end());
    payload.resize(267, 0);

    payload.insert(payload.end(), encrypted.begin(), encrypted.end());

    return payload;
}


/**
 * @brief Validates the server's response to an encrypted file transfer.
 *
 * Verifies that the server returned a FILE_RECEIVED response and
 * that the response payload matches the file sent by the client.
 *
 */
bool Client::verifyFileResponse(
    const Response& response,
    const std::string& filename,
    uint32_t encryptedSize,
    uint32_t localCRC
) {
    // Verify that the server acknowledged receiving the file.
    if (response.header.code != ResponseCode::FILE_RECEIVED)
        throw std::runtime_error("Expected FILE_RECEIVED response");

    const auto& payload = response.payload;

    // Validate the expected fixed-size response payload.
    if (payload.size() != 279)
        throw std::runtime_error("Invalid FILE_RECEIVED payload size");

    // Ensure the response belongs to the current client.
    if (!std::equal(clientId.begin(), clientId.end(), payload.begin()))
        throw std::runtime_error("Response client ID mismatch");

    // Read a 32-bit unsigned integer in little-endian byte order.
    auto readLE32 = [&](size_t offset) -> uint32_t {
        uint32_t value = 0;

        for (int i = 0; i < 4; ++i) {
            value |= static_cast<uint32_t>(
                payload[offset + i]
                ) << (8 * i);
        }

        return value;
        };

    // Verify the encrypted file size reported by the server.
    uint32_t receivedSize = readLE32(16);

    if (receivedSize != encryptedSize)
        throw std::runtime_error("Encrypted size mismatch");

    // Extract the filename from its fixed-size, null-terminated field.
    std::string receivedFilename(
        payload.begin() + 20,
        payload.begin() + 275
    );

    receivedFilename.resize(receivedFilename.find('\0'));

    if (receivedFilename != filename)
        throw std::runtime_error("Filename mismatch");

    // Compare the server's checksum with the locally calculated CRC.
    uint32_t serverCRC = readLE32(275);

    std::cout << "Local CRC: " << localCRC << '\n';
    std::cout << "Server CRC: " << serverCRC << '\n';

    return serverCRC == localCRC;
}

// Receives an ACK response from the server and verifies that it matches the expected client ID, 
// throwing an exception if the response is invalid or mismatched
void Client::receiveAndVerifyAck() {
	// Receive the ACK response from the server
    Response response = receiveResponse();
	// Verify that the response code is ACK and that the payload size is correct
    if (response.header.code != ResponseCode::ACK)
        throw std::runtime_error("Expected ACK response");

    if (response.payload.size() != 16)
        throw std::runtime_error("Invalid ACK payload size");

    if (!std::equal(
        clientId.begin(),
        clientId.end(),
        response.payload.begin()
    )) {
        throw std::runtime_error("ACK client ID mismatch");
    }
}


//Transfer the file and handle the file CRC state machine in the client side
void Client::transferFile(
    const std::vector<uint8_t>& payload,
    const std::string& filename,
    uint32_t encryptedSize,
    uint32_t localCRC
) {
    constexpr int MAX_ATTEMPTS = 3;

    //For 3 iterations, send the file and try to match the CRC.
    //Continues to the next iteration only if the response CRC does not match the client CRC
    for (int attempt = 1; attempt <= MAX_ATTEMPTS; ++attempt) {
        std::cout << "File transfer attempt "
            << attempt << "/" << MAX_ATTEMPTS << '\n';

        //Send the file payload
        sendRequest(RequestCode::SEND_FILE, payload);

        //Receive the server response
        Response response = receiveResponse();

        //Validate the response from the server
        if (verifyFileResponse(
            response,
            filename,
            encryptedSize,
            localCRC
        )) {
            //Send a response to the server that the CRC is matching the correct client one
            sendRequest(
                RequestCode::CRC_OK,
                serializeName(filename)
            );
			//Receive the response and verify the answer from the server
            receiveAndVerifyAck();

            std::cout << "File transfer completed successfully!\n";
            return;
        }
		//If the CRC does not match, retry the transfer up to the maximum number of attempts
        if (attempt < MAX_ATTEMPTS) {
            std::cout << "CRC mismatch. Retrying...\n";

            sendRequest(
                RequestCode::CRC_RETRY,
                serializeName(filename)
            );
        }
		//If the maximum number of attempts is reached, abort the transfer and throw an exception
        else {
            std::cout << "CRC mismatch. Maximum retries reached.\n";

            sendRequest(
                RequestCode::CRC_ABORT,
                serializeName(filename)
            );

            receiveAndVerifyAck();

            throw std::runtime_error(
                "File transfer failed after 4 attempts"
            );
        }
    }
}


//Main file transfer funcion
void Client::sendFile(const std::string& path) {
    //Get the file that the user has requested tto transfer
    std::string data = FileManager::readFile(path);

    if (data.size() > UINT32_MAX)
        throw std::runtime_error("Original file too large");

    //Encrypt it with the AES key
    std::string encrypted = crypto.encryptWithAES(data, aesKey);

    std::string filename =
        std::filesystem::path(path).filename().string();
    //Calculate the CRC
    uint32_t crc = FileManager::calculateCRC(data);
    //Build the file payload
    std::vector<uint8_t> payload = buildFilePayload(
        filename,
        static_cast<uint32_t>(data.size()),
        encrypted
    );
    //Transfer the file
    transferFile(
        payload,
        filename,
        static_cast<uint32_t>(encrypted.size()),
        crc
    );
}