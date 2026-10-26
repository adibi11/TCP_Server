#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>
#include <limits>
#include <iomanip>
#include <sstream>


#include "protocol.h"
#include "crypto.h"
#include "identity_storage.h"

#pragma comment(lib, "Ws2_32.lib")

struct Response {
    ResponseHeader header;
    std::vector<uint8_t> payload;
};

class Client {
public:
    Client(const std::string& host, uint16_t port, const std::string& name);
    ~Client();

    void connectToServer();
    void sendRequest(RequestCode code, const std::vector<uint8_t>& payload);
    Response receiveResponse();
	void registerClient();
    void exchangeKeys();
    bool loadIdentity();
    void saveIdentity(bool overide = false) const;
	void reconnect();
	void sendFile(const std::string& filePath);

private:
    void sendAll(const std::vector<uint8_t>& data);
    std::vector<uint8_t> recvExact(size_t size);
    std::vector<uint8_t> buildFilePayload(
        const std::string& filename,
        uint32_t originalSize,
        const std::string& encrypted
    );

    bool verifyFileResponse(
        const Response& response,
        const std::string& filename,
        uint32_t encryptedSize,
        uint32_t localCRC
    );

    void transferFile(
        const std::vector<uint8_t>& payload,
        const std::string& filename,
        uint32_t encryptedSize,
        uint32_t localCRC
    );

    void receiveAndVerifyAck();

    SOCKET socket = INVALID_SOCKET;
    std::string host;
    uint16_t port;
    std::array<uint8_t, 16> clientId{};
    CryptoManager crypto;
    std::string name;
    std::string aesKey;
    IdentityStorage storage;
};

std::string uuidToHex(const std::array<uint8_t, 16>& id);