#include "cli.h"
#include <iostream>

int main(int argc, char* argv[]) {
    try {
        ProcessScope::CLI cli;
        return cli.Run(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown fatal error occurred" << std::endl;
        return 1;
    }
}
