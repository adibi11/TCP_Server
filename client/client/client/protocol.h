#pragma once
#include <cstdint>
#include <array>
#include <vector>
#include <string>
#include <stdexcept> 
#include <algorithm>

//Request codes for client-server communication
enum class RequestCode : uint16_t {
    REGISTER = 825,
    PUBLIC_KEY = 826,
    RECONNECT = 827,
    SEND_FILE = 828,
    CRC_OK = 900,
    CRC_RETRY = 901,
    CRC_ABORT = 902
};

struct RequestHeader {
    std::array<uint8_t, 16> clientId{};
    uint8_t version = 3;
    RequestCode code;
    uint32_t payloadSize;
};

//Response codes for server-client communication
enum class ResponseCode : uint16_t {
    REGISTER_SUCCESS = 1600,
    REGISTER_FAILURE = 1601,
    AES_KEY = 1602,
    FILE_RECEIVED = 1603,
    ACK = 1604,
    RECONNECT_SUCCESS = 1605,
    RECONNECT_FAILURE = 1606,
    SERVER_ERROR = 1607
};

struct ResponseHeader {
    uint8_t version;
    ResponseCode code;
    uint32_t payloadSize;
};

ResponseHeader parseResponseHeader(const std::array<uint8_t, 7>& data);

std::vector<uint8_t> serializeHeader(const RequestHeader& header);

std::vector<uint8_t> serializeName(const std::string& name);