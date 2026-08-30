add_executable(conduit_tests
    test_main.cpp
    test_bytes.cpp
    test_crypto.cpp
    test_loop.cpp
    test_tls.cpp
    test_pg_protocol.cpp
    test_mysql_protocol.cpp
    test_types.cpp
    test_pool.cpp
)
target_link_libraries(conduit_tests PRIVATE conduit)
target_include_directories(conduit_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
if(MSVC)
    target_compile_options(conduit_tests PRIVATE /W4)
else()
    target_compile_options(conduit_tests PRIVATE -Wall -Wextra)
endif()

add_test(NAME unit COMMAND conduit_tests)
set_tests_properties(unit PROPERTIES LABELS "unit")

# Integration tests need the servers from docker-compose.yml. They are a
# separate binary behind a separate CTest label, so the default `ctest` run
# passes on a machine with no database at all.
add_executable(conduit_integration_tests
    test_main.cpp
    integration/test_pg_live.cpp
    integration/test_mysql_live.cpp
)
target_link_libraries(conduit_integration_tests PRIVATE conduit)
target_include_directories(conduit_integration_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
if(NOT MSVC)
    target_compile_options(conduit_integration_tests PRIVATE -Wall -Wextra)
endif()

add_test(NAME integration COMMAND conduit_integration_tests)
set_tests_properties(integration PROPERTIES LABELS "integration")
