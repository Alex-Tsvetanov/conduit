add_executable(conduit_bench bench.cpp)
target_link_libraries(conduit_bench PRIVATE conduit)
if(NOT MSVC)
    target_compile_options(conduit_bench PRIVATE -Wall -Wextra)
endif()

# The libpq baseline is optional and additive: without it the benchmark runs and
# reports that no baseline was available.
if(PostgreSQL_FOUND)
    target_link_libraries(conduit_bench PRIVATE PostgreSQL::PostgreSQL)
    target_compile_definitions(conduit_bench PRIVATE CONDUIT_HAVE_LIBPQ=1)
endif()

if(CONDUIT_MYSQLCLIENT_FOUND)
    target_include_directories(conduit_bench PRIVATE ${MYSQLCLIENT_INCLUDE_DIR})
    target_link_libraries(conduit_bench PRIVATE ${MYSQLCLIENT_LIBRARY})
    target_compile_definitions(conduit_bench PRIVATE CONDUIT_HAVE_MYSQLCLIENT=1)
endif()

# GetProcessMemoryInfo, used for the peak resident set on Windows.
if(WIN32)
    target_link_libraries(conduit_bench PRIVATE psapi)
endif()

add_custom_target(bench
    COMMAND conduit_bench
    DEPENDS conduit_bench
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    USES_TERMINAL
    COMMENT "Running the Conduit measurements against the compose environment")

# A standalone check, not part of the measurements. It answers whether symmetric
# transfer grows the stack on the compiler in use, which is the question that
# separated a compiler defect from the one in this project. See the file header.
add_executable(symmetric_transfer_check symmetric_transfer_check.cpp)
if(NOT MSVC)
    target_compile_options(symmetric_transfer_check PRIVATE -Wall -Wextra)
endif()
