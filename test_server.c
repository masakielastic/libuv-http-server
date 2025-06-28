#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include "httpserver.h"

#define RESPONSE "Hello, World from TLS HTTP Server!"

void handle_request(struct http_request_s* request) {
    printf("=== New Request ===\n");
    printf("Method: %s\n", http_request_method(request));
    printf("URL: %s\n", http_request_target(request));
    
    // Print some headers
    const char* user_agent = http_request_header(request, "User-Agent");
    if (user_agent) {
        printf("User-Agent: %s\n", user_agent);
    }
    
    const char* host = http_request_header(request, "Host");
    if (host) {
        printf("Host: %s\n", host);
    }
    
    // Print body if present
    const char* body = http_request_body(request);
    size_t body_len = http_request_body_length(request);
    if (body && body_len > 0) {
        printf("Body (%zu bytes): %s\n", body_len, body);
    }
    
    printf("==================\n");
    
    // Create response
    struct http_response_s* response = http_response_init();
    http_response_status(response, 200);
    http_response_header(response, "Content-Type", "text/plain");
    http_response_header(response, "Server", "libuv-httpserver/1.0");
    http_response_body(response, RESPONSE, sizeof(RESPONSE) - 1);
    
    // Send response
    int result = http_respond(request, response);
    if (result != 0) {
        printf("Failed to send response\n");
    }
    
    // Cleanup response
    http_response_destroy(response);
}

int main() {
    printf("Starting TLS HTTP Server...\n");
    
    struct http_server_s* server = http_server_init(8443, handle_request);
    if (!server) {
        printf("Failed to initialize server\n");
        return 1;
    }
    
    printf("Server initialized successfully\n");
    printf("Test with: curl -k https://localhost:8443\n");
    printf("Press Ctrl+C to stop the server\n");
    
    int result = http_server_listen(server);
    
    printf("Server stopped with code: %d\n", result);
    http_server_destroy(server);
    
    return result;
}