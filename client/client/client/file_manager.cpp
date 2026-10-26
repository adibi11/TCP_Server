#include "file_manager.h"

#include <fstream>
#include <iterator>
#include <stdexcept>

//Reads a file from the client machine to send to the server
std::string FileManager::readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary);

    if (!file)
        throw std::runtime_error("Failed to open file: " + path);

    return std::string(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );
}

//Calculate the file CRC to match later in front of the server
uint32_t FileManager::calculateCRC(const std::string& data) 
{
    constexpr uint32_t polynomial = 0x04C11DB7;
    uint32_t crc = 0;

    auto update = [&](uint8_t byte) {
        crc ^= static_cast<uint32_t>(byte) << 24;

        for (int i = 0; i < 8; ++i) {
            if (crc & 0x80000000)
                crc = (crc << 1) ^ polynomial;
            else
                crc <<= 1;
        }
        };

    for (unsigned char byte : data)
        update(byte);

    size_t length = data.size();

    while (length > 0) {
        update(static_cast<uint8_t>(length & 0xFF));
        length >>= 8;
    }

    return ~crc;
}