#pragma once

#include <string>
#include <cstdint>

class FileManager {
public:
    static std::string readFile(const std::string& path);
    static uint32_t calculateCRC(const std::string& data);
};