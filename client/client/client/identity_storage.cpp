
#include "identity_storage.h"

#include <fstream>
#include <stdexcept>
#include <regex>
#include <sstream>

// Converts a 16-byte UUID into a hexadecimal string.
static std::string toHex(const std::array<uint8_t, 16>& id) {
    std::ostringstream stream;

    for (uint8_t byte : id)
        stream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);

    return stream.str();
}

// Converts a hexadecimal UUID string into a 16-byte array.
static std::array<uint8_t, 16> fromHex(const std::string& hex) {
    if (hex.size() != 32)
        throw std::runtime_error("Invalid UUID length");

    std::array<uint8_t, 16> id{};

    for (size_t i = 0; i < id.size(); ++i) {
        std::string pair = hex.substr(i * 2, 2);

        // Ensure both characters are valid hexadecimal digits.
        if (!std::all_of(pair.begin(), pair.end(), [](unsigned char c) {
            return std::isxdigit(c);
            }))
            throw std::runtime_error("Invalid UUID format");

        id[i] = static_cast<uint8_t>(std::stoul(pair, nullptr, 16));
    }

    return id;
}

// Checks whether the client identity file exists.
bool IdentityStorage::exists() const {
    return std::filesystem::exists(path);
}

// Saves the client's identity and private RSA key to separate files.
void IdentityStorage::save(const ClientIdentity& identity) const {
    if (exists() || std::filesystem::exists(keyPath))
        throw std::runtime_error("Identity files already exist");

    std::ofstream file(path, std::ios::out | std::ios::trunc);

    if (!file)
        throw std::runtime_error("Failed to create identity file");

    // Write the client name, UUID, and private key.
    file << identity.name << '\n';
    file << toHex(identity.clientId) << '\n';
    file << identity.privateKey << '\n';

    if (!file)
        throw std::runtime_error("Failed to write identity file");

    file.close();

    // Store an additional copy of the private key.
    std::ofstream keyFile(keyPath, std::ios::out | std::ios::trunc);

    if (!keyFile)
        throw std::runtime_error("Failed to create private key file");

    keyFile << identity.privateKey << '\n';

    if (!keyFile)
        throw std::runtime_error("Failed to write private key file");
}



// Replaces the stored client identity and private key after a new registration.
void IdentityStorage::replace(const ClientIdentity& identity) const {
    // Overwrite the existing identity file.
    std::ofstream file(path, std::ios::out | std::ios::trunc);

    if (!file)
        throw std::runtime_error("Failed to open identity file for replacement");

    file << identity.name << '\n';
    file << toHex(identity.clientId) << '\n';
    file << identity.privateKey << '\n';

    if (!file)
        throw std::runtime_error("Failed to replace identity file");

    file.close();

    // Overwrite the separate private key file.
    std::ofstream keyFile(keyPath, std::ios::out | std::ios::trunc);

    if (!keyFile)
        throw std::runtime_error("Failed to open private key file for replacement");

    keyFile << identity.privateKey << '\n';

    if (!keyFile)
        throw std::runtime_error("Failed to replace private key file");
}


// Loads the saved client identity and verifies that both private key copies match.
ClientIdentity IdentityStorage::load() const {
    std::ifstream file(path);

    if (!file)
        throw std::runtime_error("Failed to open identity file");

    ClientIdentity identity;
    std::string uuid;

    // Read the stored identity fields.
    if (!std::getline(file, identity.name) ||
        !std::getline(file, uuid) ||
        !std::getline(file, identity.privateKey))
        throw std::runtime_error("Invalid identity file");

    if (identity.name.empty() || identity.privateKey.empty())
        throw std::runtime_error("Invalid identity data");

    identity.clientId = fromHex(uuid);

    std::ifstream keyFile(keyPath);

    if (!keyFile)
        throw std::runtime_error("Missing private key file");

    std::string savedKey;

    if (!std::getline(keyFile, savedKey) || savedKey.empty())
        throw std::runtime_error("Invalid private key file");

    // Ensure the private key is consistent across both files.
    if (savedKey != identity.privateKey)
        throw std::runtime_error("Private key mismatch between files");

    return identity;
}

// Reads and validates the server connection settings from the configuration file.
ServerInfo IdentityStorage::getServerInfo() const {
    std::ifstream file(configPath);

    if (!file) {
        throw std::runtime_error("Missing configuration file: " + configPath);
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();

    // Extract a string field from the configuration content.
    auto getString = [&](const std::string& key) -> std::string {
        std::regex pattern("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
        std::smatch match;

        if (!std::regex_search(content, match, pattern)) {
            throw std::runtime_error("Missing or invalid field: " + key);
        }

        return match[1].str();
        };

    // Extract and validate the server port.
    std::regex portPattern(R"("port"\s*:\s*(\d+))");
    std::smatch portMatch;

    if (!std::regex_search(content, portMatch, portPattern)) {
        throw std::runtime_error("Missing or invalid port");
    }

    unsigned long port = std::stoul(portMatch[1].str());

    if (port == 0 || port > 65535) {
        throw std::runtime_error("Invalid server port");
    }

    ServerInfo info{
        getString("ip"),
        static_cast<uint16_t>(port),
        getString("client")
    };

    // Validate the required server and client information.
    if (info.ip.empty()) {
        throw std::runtime_error("Server IP cannot be empty");
    }

    if (info.clientName.empty() || info.clientName.size() > 100) {
        throw std::runtime_error("Invalid client name");
    }

    return info;
}
