
#include "command_line_interface.h"

#include <iostream>
#include <sstream>
#include <stdexcept>

// Initializes the interface with the server configuration.
CommandLineInterface::CommandLineInterface(const ServerInfo& serverInfo)
    : serverInfo(serverInfo),
    client(serverInfo.ip, serverInfo.port, serverInfo.clientName) {
}

// Starts the interactive command loop.
void CommandLineInterface::run() {
    std::cout << "\nSecure File Transfer Client\n";
    std::cout << "Type 'help' to see available commands.\n";

    std::string input;

    while (true) {
        std::cout << "\n> ";

        if (!std::getline(std::cin, input))
            break;

        try {
            if (!executeCommand(input))
                break;
        }
        catch (const std::exception& exc) {
            std::cerr << "Error: " << exc.what() << '\n';
        }
    }

    std::cout << "Client terminated.\n";
}

// Displays the available commands.
void CommandLineInterface::printHelp() const {
    std::cout
        << "\nAvailable commands:\n"
        << "  connect          - Connect to the server\n"
        << "  send <filepath>  - Send an encrypted file\n"
        << "  status           - Show connection status\n"
        << "  help             - Show available commands\n"
        << "  exit             - Exit the application\n";
}

// Parses and executes a user command.
bool CommandLineInterface::executeCommand(const std::string& input) {
    std::istringstream stream(input);
    std::string command;

    stream >> command;

    if (command == "exit")
        return false;

    if (command == "help") {
        printHelp();
    }
    else if (command == "connect") {
        handleConnect();
    }
    else if (command == "status") {
        handleStatus();
    }
    else if (command == "send") {
        std::string filepath;
        std::getline(stream >> std::ws, filepath);

        if (filepath.empty())
            throw std::invalid_argument("Missing file path");

        // Allow paths enclosed in double quotes.
        if (filepath.size() >= 2 &&
            filepath.front() == '"' &&
            filepath.back() == '"') {
            filepath = filepath.substr(1, filepath.size() - 2);
        }

        handleSend(filepath);
    }
    else if (!command.empty()) {
        std::cout << "Unknown command: " << command << '\n';
    }

    return true;
}

// Connects to the server and establishes the client's encryption keys.

// Connects to the server and establishes the client's encryption keys.
void CommandLineInterface::handleConnect() {
    if (connected) {
        std::cout << "Client is already connected.\n";
        return;
    }

    std::cout << "Connecting to "
        << serverInfo.ip << ":" << serverInfo.port << "...\n";

    // Check whether the client already has a saved identity.
    bool hasIdentity = client.loadIdentity();

    // Establish the TCP connection.
    client.connectToServer();

    if (hasIdentity) {
        // Reuse the existing identity and request a new AES key.
        std::cout << "Reconnecting existing client...\n";
        client.reconnect();
    }
    else {
        // Register a new identity and perform the initial key exchange.
        std::cout << "Registering new client...\n";
        client.registerClient();
        client.exchangeKeys();
        client.saveIdentity();
    }

    connected = true;
    std::cout << "Connection established successfully.\n";
}


// Sends a file using the established encrypted connection.
void CommandLineInterface::handleSend(const std::string& filepath) {
    if (!connected) {
        throw std::runtime_error(
            "Not connected. Use 'connect' first."
        );
    }

    std::cout << "Sending file: " << filepath << '\n';

    client.sendFile(filepath);

    std::cout << "File transfer completed.\n";
}

// Displays the configured server and current connection status.
void CommandLineInterface::handleStatus() const {
    std::cout
        << "\nClient: " << serverInfo.clientName
        << "\nServer: " << serverInfo.ip << ":" << serverInfo.port
        << "\nStatus: " << (connected ? "CONNECTED" : "DISCONNECTED")
        << '\n';
}
