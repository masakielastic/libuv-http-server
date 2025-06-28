#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include "httpserver.h"

#define RESPONSE "Hello from mkcert TLS server!"

void handle_request(struct http_request_s* request) {
    printf("=== mkcert Request ===\n");
    printf("Method: %s\n", http_request_method(request));
    printf("URL: %s\n", http_request_target(request));
    
    const char* user_agent = http_request_header(request, "User-Agent");
    if (user_agent) {
        printf("User-Agent: %s\n", user_agent);
    }
    
    printf("===================\n");
    
    // Create response
    struct http_response_s* response = http_response_init();
    http_response_status(response, 200);
    http_response_header(response, "Content-Type", "text/plain");
    http_response_header(response, "Server", "mkcert-httpserver/1.0");
    http_response_body(response, RESPONSE, sizeof(RESPONSE) - 1);
    
    // Send response
    int result = http_respond(request, response);
    if (result != 0) {
        printf("Failed to send response\n");
    }
    
    // Cleanup response
    http_response_destroy(response);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <cert.pem> <key.pem>\n", argv[0]);
        printf("Example: %s localhost.pem localhost-key.pem\n", argv[0]);
        return 1;
    }
    
    const char* cert_file = argv[1];
    const char* key_file = argv[2];
    
    printf("Starting mkcert TLS HTTP Server...\n");
    printf("Certificate: %s\n", cert_file);
    printf("Private Key: %s\n", key_file);
    
    struct http_server_s* server = http_server_init_with_certs(8443, handle_request, cert_file, key_file);
    if (!server) {
        printf("Failed to initialize server with certificates\n");
        return 1;
    }
    
    printf("Server initialized successfully with mkcert certificates\n");
    printf("Test with: curl https://localhost:8443\n");
    printf("Press Ctrl+C to stop the server\n");
    
    int result = http_server_listen(server);
    
    printf("Server stopped with code: %d\n", result);
    http_server_destroy(server);
    
    return result;
}