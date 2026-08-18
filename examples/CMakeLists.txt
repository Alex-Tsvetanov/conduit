add_executable(conduit_demo demo.cpp)
target_link_libraries(conduit_demo PRIVATE conduit)
if(NOT MSVC)
    target_compile_options(conduit_demo PRIVATE -Wall -Wextra)
endif()

# One command to see the system work end to end. It needs the compose
# environment, and says so when it cannot reach a server.
add_custom_target(demo
    COMMAND conduit_demo
    DEPENDS conduit_demo
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    USES_TERMINAL
    COMMENT "Running the Conduit demonstration against the compose environment")
