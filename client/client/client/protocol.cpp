
#include "protocol.h"

// Serializes a request header into a byte vector using little-endian encoding.
std::vector<uint8_t> serializeHeader(const RequestHeader& header) {
    std::vector<uint8_t> data;

    // Append the 16-byte client identifier and protocol version.
    data.insert(data.end(), header.clientId.begin(), header.clientId.end());
    data.push_back(header.version);

    // Serialize the request code as a 16-bit little-endian integer.
    uint16_t code = static_cast<uint16_t>(header.code);

    data.push_back(static_cast<uint8_t>(code));
    data.push_back(static_cast<uint8_t>(code >> 8));

    // Serialize the payload size as a 32-bit little-endian integer.
    for (int i = 0; i < 4; ++i)
        data.push_back(static_cast<uint8_t>(header.payloadSize >> (8 * i)));

    return data;
}

// Parses a 7-byte server response header into its structured representation.
ResponseHeader parseResponseHeader(const std::array<uint8_t, 7>& data) {
    ResponseHeader header;

    // Extract the protocol version.
    header.version = data[0];

    // Decode the 16-bit response code from little-endian bytes.
    uint16_t code = static_cast<uint16_t>(data[1]) |
        (static_cast<uint16_t>(data[2]) << 8);

    header.code = static_cast<ResponseCode>(code);

    // Decode the 32-bit payload size from little-endian bytes.
    header.payloadSize = 0;

    for (int i = 0; i < 4; ++i)
        header.payloadSize |= static_cast<uint32_t>(data[3 + i]) << (8 * i);

    return header;
}

// Validates and serializes an ASCII client name into a 255-byte null-padded field.
std::vector<uint8_t> serializeName(const std::string& name) {
    if (name.empty() || name.size() >= 255)
        throw std::invalid_argument("Invalid client name");

    // Reject null characters and non-ASCII bytes.
    if (std::any_of(name.begin(), name.end(), [](unsigned char c) {
        return c == 0 || c > 127;
        }))
        throw std::invalid_argument("Client name must be ASCII");

    // Copy the name into a fixed-size field padded with null bytes.
    std::vector<uint8_t> payload(255, 0);
    std::copy(name.begin(), name.end(), payload.begin());

    return payload;
}
 