#ifndef HTTPSERVER_H
#define HTTPSERVER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// Forward declarations
struct http_server_s;
struct http_request_s;
struct http_response_s;
struct http_server_config_s;

// Request handler callback type
typedef void (*http_request_handler_t)(struct http_request_s* request);

// HTTP server structure (opaque)
typedef struct http_server_s http_server_t;

// HTTP request structure (opaque)
typedef struct http_request_s http_request_t;

// HTTP response structure (opaque)
typedef struct http_response_s http_response_t;

// HTTP server configuration structure
typedef struct http_server_config_s {
    int port;
    http_request_handler_t handler;
    int tls_enabled;           // 0 = HTTP, 1 = HTTPS
    const char* cert_file;     // NULL for self-signed, path for custom cert
    const char* key_file;      // NULL for self-signed, path for custom key
} http_server_config_t;

// Unified server management functions
http_server_t* http_server_create(const http_server_config_t* config);
int http_server_listen(http_server_t* server);
void http_server_destroy(http_server_t* server);

// Legacy compatibility functions (deprecated but still available)
http_server_t* http_server_init(int port, http_request_handler_t handler);
http_server_t* http_server_init_with_certs(int port, http_request_handler_t handler, 
                                          const char* cert_file, const char* key_file);
http_server_t* http_server_init_http(int port, http_request_handler_t handler);

// Helper functions for configuration
http_server_config_t http_server_config_default(int port, http_request_handler_t handler);
http_server_config_t http_server_config_http(int port, http_request_handler_t handler);
http_server_config_t http_server_config_https(int port, http_request_handler_t handler, 
                                              const char* cert_file, const char* key_file);

// Request functions
const char* http_request_method(http_request_t* request);
const char* http_request_target(http_request_t* request);
const char* http_request_header(http_request_t* request, const char* name);
const char* http_request_body(http_request_t* request);
size_t http_request_body_length(http_request_t* request);

// Response functions
http_response_t* http_response_init(void);
void http_response_status(http_response_t* response, int status);
void http_response_header(http_response_t* response, const char* name, const char* value);
void http_response_body(http_response_t* response, const char* body, size_t length);
int http_respond(http_request_t* request, http_response_t* response);
void http_response_destroy(http_response_t* response);

// Implementation details (when HTTPSERVER_IMPL is defined)
#ifdef HTTPSERVER_IMPL

#include <uv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include "llhttp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Internal structures
struct http_server_s {
    uv_tcp_t tcp;
    uv_loop_t* loop;
    SSL_CTX* ssl_ctx;
    http_request_handler_t handler;
    int port;
    int tls_enabled;  // 1 for HTTPS, 0 for HTTP
};

struct http_connection_s {
    uv_tcp_t tcp;
    SSL* ssl;
    BIO* read_bio;
    BIO* write_bio;
    llhttp_t parser;
    llhttp_settings_t parser_settings;
    int handshake_complete;
    int shutdown_sent;
    http_server_t* server;
    int tls_enabled;  // copied from server
    
    // Parsed request data
    char* method;
    char* url;
    char* headers[64][2];  // name-value pairs
    int header_count;
    char* body;
    size_t body_length;
    size_t body_capacity;
    
    // Response data
    http_response_t* pending_response;
};

struct http_request_s {
    struct http_connection_s* connection;
    const char* method;
    const char* url;
    const char* body;
    size_t body_length;
};

struct http_response_s {
    int status_code;
    char* headers[64][2];  // name-value pairs
    int header_count;
    char* body;
    size_t body_length;
};

// Internal function declarations (only in implementation file)

#endif // HTTPSERVER_IMPL

#ifdef __cplusplus
}
#endif

#endif // HTTPSERVER_H