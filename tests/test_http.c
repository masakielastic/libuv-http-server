#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include "httpserver.h"

#define RESPONSE "Hello from plain HTTP server!"

void handle_request(struct http_request_s* request) {
    printf("=== HTTP Request ===\n");
    printf("Method: %s\n", http_request_method(request));
    printf("URL: %s\n", http_request_target(request));
    
    const char* user_agent = http_request_header(request, "User-Agent");
    if (user_agent) {
        printf("User-Agent: %s\n", user_agent);
    }
    
    const char* host = http_request_header(request, "Host");
    if (host) {
        printf("Host: %s\n", host);
    }
    
    printf("==================\n");
    
    // Create response
    struct http_response_s* response = http_response_init();
    http_response_status(response, 200);
    http_response_header(response, "Content-Type", "text/plain");
    http_response_header(response, "Server", "plain-httpserver/1.0");
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
    printf("Starting plain HTTP Server...\n");
    
    struct http_server_s* server = http_server_init_http(8080, handle_request);
    if (!server) {
        printf("Failed to initialize HTTP server\n");
        return 1;
    }
    
    printf("HTTP server initialized successfully\n");
    printf("Test with: curl http://localhost:8080\n");
    printf("Press Ctrl+C to stop the server\n");
    
    int result = http_server_listen(server);
    
    printf("Server stopped with code: %d\n", result);
    http_server_destroy(server);
    
    return result;
}