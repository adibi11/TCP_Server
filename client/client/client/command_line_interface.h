#pragma once

#include "client.h"
#include "identity_storage.h"

#include <string>

// Provides an interactive command-line interface for the file transfer client.
class CommandLineInterface {
public:
    explicit CommandLineInterface(const ServerInfo& serverInfo);

    // Starts the command loop and processes user input.
    void run();

private:
    ServerInfo serverInfo;
    Client client;
    bool connected = false;

    // Displays all supported commands.
    void printHelp() const;

    // Parses and executes a command entered by the user.
    bool executeCommand(const std::string& input);

    // Establishes a connection and performs registration or reconnection.
    void handleConnect();

    // Sends an encrypted file to the server.
    void handleSend(const std::string& filepath);

    // Displays the current client connection status.
    void handleStatus() const;
};
