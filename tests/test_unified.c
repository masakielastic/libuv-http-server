#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include "httpserver.h"

#define RESPONSE "Hello from unified API!"

void handle_request(struct http_request_s* request) {
    printf("=== Unified API Request ===\n");
    printf("Method: %s\n", http_request_method(request));
    printf("URL: %s\n", http_request_target(request));
    
    const char* user_agent = http_request_header(request, "User-Agent");
    if (user_agent) {
        printf("User-Agent: %s\n", user_agent);
    }
    
    printf("===========================\n");
    
    // Create response
    struct http_response_s* response = http_response_init();
    http_response_status(response, 200);
    http_response_header(response, "Content-Type", "text/plain");
    http_response_header(response, "Server", "unified-httpserver/2.0");
    http_response_body(response, RESPONSE, sizeof(RESPONSE) - 1);
    
    // Send response
    int result = http_respond(request, response);
    if (result != 0) {
        printf("Failed to send response\n");
    }
    
    // Cleanup response
    http_response_destroy(response);
}

void demo_http() {
    printf("=== HTTP Server Demo ===\n");
    
    // Method 1: Using unified API with helper function
    http_server_config_t config = http_server_config_http(8080, handle_request);
    http_server_t* server = http_server_create(&config);
    
    if (!server) {
        printf("Failed to create HTTP server\n");
        return;
    }
    
    printf("HTTP server created using unified API\n");
    printf("Test with: curl http://localhost:8080\n");
    printf("Press Ctrl+C to stop\n");
    
    http_server_listen(server);
    http_server_destroy(server);
}

void demo_https_self_signed() {
    printf("=== HTTPS Self-Signed Demo ===\n");
    
    // Method 2: Using unified API with direct config
    http_server_config_t config = {0};
    config.port = 8443;
    config.handler = handle_request;
    config.tls_enabled = 1;
    config.cert_file = NULL;  // Use self-signed
    config.key_file = NULL;
    
    http_server_t* server = http_server_create(&config);
    
    if (!server) {
        printf("Failed to create HTTPS server\n");
        return;
    }
    
    printf("HTTPS server created using unified API (self-signed)\n");
    printf("Test with: curl -k https://localhost:8443\n");
    printf("Press Ctrl+C to stop\n");
    
    http_server_listen(server);
    http_server_destroy(server);
}

void demo_https_mkcert() {
    printf("=== HTTPS mkcert Demo ===\n");
    
    // Method 3: Using unified API with mkcert certificates
    http_server_config_t config = http_server_config_https(8443, handle_request, 
                                                           "localhost+2.pem", 
                                                           "localhost+2-key.pem");
    http_server_t* server = http_server_create(&config);
    
    if (!server) {
        printf("Failed to create HTTPS server with mkcert\n");
        return;
    }
    
    printf("HTTPS server created using unified API (mkcert)\n");
    printf("Test with: curl https://localhost:8443\n");
    printf("Press Ctrl+C to stop\n");
    
    http_server_listen(server);
    http_server_destroy(server);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <mode>\n", argv[0]);
        printf("Modes:\n");
        printf("  http        - HTTP server on port 8080\n");
        printf("  https       - HTTPS server on port 8443 (self-signed)\n");
        printf("  mkcert      - HTTPS server on port 8443 (mkcert certs)\n");
        return 1;
    }
    
    if (strcmp(argv[1], "http") == 0) {
        demo_http();
    } else if (strcmp(argv[1], "https") == 0) {
        demo_https_self_signed();
    } else if (strcmp(argv[1], "mkcert") == 0) {
        demo_https_mkcert();
    } else {
        printf("Unknown mode: %s\n", argv[1]);
        return 1;
    }
    
    return 0;
}