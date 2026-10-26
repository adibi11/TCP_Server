#pragma once
#include <array>
#include <string>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <cctype>
#include <array>
#include <cstdint>
#include <string>


struct ClientIdentity {
    std::string name;
    std::array<uint8_t, 16> clientId;
    std::string privateKey;
};

struct ServerInfo {
    std::string ip;
    uint16_t port;
    std::string clientName;
};

class IdentityStorage {
public:
    bool exists() const;
    ClientIdentity load() const;
    void save(const ClientIdentity& identity) const;
    void replace(const ClientIdentity& identity) const;

    ServerInfo getServerInfo() const;

private:
    std::string path = "info.me";
    std::string keyPath = "key.priv";
    std::string configPath = "json.transfer";
};