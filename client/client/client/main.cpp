
#include "command_line_interface.h"
#include "identity_storage.h"

#include <exception>
#include <iostream>

// Initializes the client configuration and starts the command-line interface.
int main() {
    try {
        IdentityStorage storage;
        ServerInfo serverInfo = storage.getServerInfo();

        CommandLineInterface cli(serverInfo);
        cli.run();
    }
    catch (const std::exception& exc) {
        std::cerr << "Fatal error: " << exc.what() << '\n';
        return 1;
    }

    return 0;
}
