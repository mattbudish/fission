add_executable(server server.c)
target_link_libraries(server microhttpd uv jansson)