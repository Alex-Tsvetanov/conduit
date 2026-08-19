cmake_minimum_required(VERSION 3.20)
project(conduit LANGUAGES CXX VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

option(CONDUIT_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

add_library(conduit
    src/bytes.cpp
    src/crypto.cpp
    src/net.cpp
    src/trace.cpp
    src/value.cpp
    src/scram.cpp
    src/pg_message.cpp
    src/pg_connection.cpp
    src/mysql_packet.cpp
    src/mysql_connection.cpp
)
target_include_directories(conduit PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

if(MSVC)
    target_compile_options(conduit PRIVATE /W4)
else()
    target_compile_options(conduit PRIVATE -Wall -Wextra -Wpedantic)
endif()
if(CONDUIT_WARNINGS_AS_ERRORS)
    if(MSVC)
        target_compile_options(conduit PRIVATE /WX)
    else()
        target_compile_options(conduit PRIVATE -Werror)
    endif()
endif()

if(WIN32)
    target_link_libraries(conduit PUBLIC ws2_32)
endif()
find_package(Threads REQUIRED)
target_link_libraries(conduit PUBLIC Threads::Threads)

# --- optional baseline: libpq, only if it is already on the machine ----------
# The library never depends on it. It is used solely by the benchmark for a
# side by side comparison, and the benchmark reports its absence explicitly.
find_package(PostgreSQL QUIET)
if(PostgreSQL_FOUND)
    message(STATUS "conduit: libpq found, benchmark will include the libpq baseline")
else()
    message(STATUS "conduit: libpq not found, benchmark runs without the libpq baseline")
endif()

# --- optional baseline: the vendor MySQL client, same rule as libpq ----------
# Looked for by hand rather than with a find module, because the Debian package
# installs the headers under a directory the standard modules do not search.
find_path(MYSQLCLIENT_INCLUDE_DIR mysql.h
    PATH_SUFFIXES mysql mariadb mysql/mysql)
find_library(MYSQLCLIENT_LIBRARY NAMES mysqlclient mariadb libmariadb)
if(MYSQLCLIENT_INCLUDE_DIR AND MYSQLCLIENT_LIBRARY)
    set(CONDUIT_MYSQLCLIENT_FOUND TRUE)
    message(STATUS "conduit: MySQL client found at ${MYSQLCLIENT_LIBRARY}, "
                   "benchmark will include the libmysqlclient baseline")
else()
    set(CONDUIT_MYSQLCLIENT_FOUND FALSE)
    message(STATUS "conduit: MySQL client not found, benchmark runs without that baseline")
endif()

enable_testing()
add_subdirectory(tests)
add_subdirectory(examples)
add_subdirectory(benchmarks)
