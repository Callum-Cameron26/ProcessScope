cmake_minimum_required(VERSION 3.16)
project(ProcessScope VERSION 1.0.0 LANGUAGES CXX)

# Set C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler-specific options
if(MSVC)
    # Enable all warnings and treat warnings as errors for better code quality
    add_compile_options(/W4 /WX)
    
    # Enable specific security features
    add_compile_options(/sdl)
    
    # Use static runtime library
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    
    # Define Windows version
    add_definitions(-DWINVER=0x0601 -D_WIN32_WINNT=0x0601) # Windows 7+
else()
    # GCC/Clang options
    add_compile_options(-Wall -Wextra -Werror)
    add_compile_options(-fno-exceptions)
endif()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/third_party)

# Source files
set(SOURCES
    src/main.cpp
    src/cli.cpp
    src/util.cpp
    src/process_enum.cpp
    src/module_enum.cpp
    src/thread_enum.cpp
    src/memory_scan.cpp
    src/signer_verify.cpp
    src/risk_score.cpp
)

# Header files (for IDE organization)
set(HEADERS
    src/cli.h
    src/util.h
    src/process_enum.h
    src/module_enum.h
    src/thread_enum.h
    src/memory_scan.h
    src/signer_verify.h
    src/risk_score.h
)

# Create executable
add_executable(ProcessScope ${SOURCES} ${HEADERS})

# Windows-specific libraries
if(WIN32)
    target_link_libraries(ProcessScope
        kernel32
        user32
        advapi32
        shell32
        ole32
        oleaut32
        wintrust
        crypt32
        psapi
        version
    )
endif()

# Set output directory
set_target_properties(ProcessScope PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin/Debug
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin/Release
)

# Copy third_party directory to build directory
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/third_party DESTINATION ${CMAKE_BINARY_DIR})

# Installation rules
install(TARGETS ProcessScope
    RUNTIME DESTINATION bin
)

# Create reports directory in build directory
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/reports)

# Custom target to run tests (placeholder for future tests)
add_custom_target(run_tests
    COMMAND ${CMAKE_BINARY_DIR}/bin/ProcessScope.exe --help
    DEPENDS ProcessScope
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running ProcessScope help command"
)

# Print configuration information
message(STATUS "ProcessScope Configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Target Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "  Compiler: ${CMAKE_CXX_COMPILER_ID}")
