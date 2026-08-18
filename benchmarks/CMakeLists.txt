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

add_custom_target(bench
    COMMAND conduit_bench
    DEPENDS conduit_bench
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    USES_TERMINAL
    COMMENT "Running the Conduit measurements against the compose environment")
