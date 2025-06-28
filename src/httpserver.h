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

// Constants
#define MAX_HEADERS 64

// Memory pool configuration
#define MEMORY_POOL_SMALL_SIZE 256
#define MEMORY_POOL_MEDIUM_SIZE 8192
#define MEMORY_POOL_LARGE_SIZE 65536
#define MEMORY_POOL_SMALL_COUNT 1024
#define MEMORY_POOL_MEDIUM_COUNT 256
#define MEMORY_POOL_LARGE_COUNT 64
#define MEMORY_POOL_CONNECTION_COUNT 128

// Error codes
typedef enum {
    HTTP_SERVER_SUCCESS = 0,
    HTTP_SERVER_ERROR_MEMORY = -1,
    HTTP_SERVER_ERROR_INVALID_PARAM = -2,
    HTTP_SERVER_ERROR_SSL_INIT = -3,
    HTTP_SERVER_ERROR_SSL_HANDSHAKE = -4,
    HTTP_SERVER_ERROR_SSL_IO = -5,
    HTTP_SERVER_ERROR_HTTP_PARSE = -6,
    HTTP_SERVER_ERROR_NETWORK = -7,
    HTTP_SERVER_ERROR_CERT_LOAD = -8,
    HTTP_SERVER_ERROR_BUFFER_OVERFLOW = -9,
    HTTP_SERVER_ERROR_CONNECTION_LIMIT = -10,
    HTTP_SERVER_ERROR_UNKNOWN = -99
} http_server_error_t;

// Error handling macros
#define HTTP_LOG_ERROR(fmt, ...) \
    fprintf(stderr, "[ERROR] %s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#define HTTP_LOG_WARN(fmt, ...) \
    fprintf(stderr, "[WARN] %s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#define HTTP_LOG_INFO(fmt, ...) \
    fprintf(stdout, "[INFO] " fmt "\n", ##__VA_ARGS__)

#define HTTP_CHECK_MALLOC(ptr, action) \
    do { \
        if (!(ptr)) { \
            HTTP_LOG_ERROR("Memory allocation failed"); \
            action; \
        } \
    } while(0)

#define HTTP_CHECK_PARAM(cond, retval) \
    do { \
        if (!(cond)) { \
            HTTP_LOG_ERROR("Invalid parameter: %s", #cond); \
            return (retval); \
        } \
    } while(0)

#define HTTP_RETURN_ERROR(code, fmt, ...) \
    do { \
        HTTP_LOG_ERROR(fmt, ##__VA_ARGS__); \
        return (code); \
    } while(0)

// Resource management macros (RAII-style)
#define HTTP_CLEANUP_DECLARE(name) \
    void cleanup_##name(void** ptr)

#define HTTP_CLEANUP_DEFINE(name, cleanup_code) \
    void cleanup_##name(void** ptr) { \
        if (ptr && *ptr) { \
            cleanup_code; \
            *ptr = NULL; \
        } \
    }

#define HTTP_AUTO_CLEANUP(type, name, cleanup_func) \
    type name __attribute__((cleanup(cleanup_func))) = NULL

#define HTTP_DEFER(cleanup_func, resource) \
    void* _defer_##__LINE__ __attribute__((cleanup(cleanup_func))) = (resource)

// Memory pool structures
typedef struct memory_block_s {
    void* ptr;
    size_t size;
    int in_use;
    struct memory_block_s* next;
} memory_block_t;

typedef struct memory_pool_s {
    memory_block_t* blocks;
    size_t block_size;
    size_t block_count;
    size_t allocated_count;
    size_t free_count;
    pthread_mutex_t mutex;
} memory_pool_t;

typedef struct memory_stats_s {
    size_t total_allocated;
    size_t total_freed;
    size_t current_usage;
    size_t peak_usage;
    size_t pool_hits;
    size_t pool_misses;
} memory_stats_t;

// Internal structures
struct http_server_s {
    uv_tcp_t tcp;
    uv_loop_t* loop;
    SSL_CTX* ssl_ctx;
    http_request_handler_t handler;
    int port;
    int tls_enabled;  // 1 for HTTPS, 0 for HTTP
    
    // Memory management
    memory_pool_t small_pool;    // 32-256 bytes
    memory_pool_t medium_pool;   // 1KB-8KB  
    memory_pool_t large_pool;    // 16KB-64KB
    memory_pool_t connection_pool; // Connection structures
    memory_stats_t memory_stats;
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
    char* headers[MAX_HEADERS][2];  // name-value pairs
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
    char* headers[MAX_HEADERS][2];  // name-value pairs
    int header_count;
    char* body;
    size_t body_length;
};

// Memory pool function declarations
http_server_error_t memory_pool_init(memory_pool_t* pool, size_t block_size, size_t block_count);
void memory_pool_destroy(memory_pool_t* pool);
void* memory_pool_alloc(memory_pool_t* pool);
void memory_pool_free(memory_pool_t* pool, void* ptr);

// Smart memory management functions
void* http_malloc(http_server_t* server, size_t size);
void* http_realloc(http_server_t* server, void* ptr, size_t old_size, size_t new_size);
void http_free(http_server_t* server, void* ptr, size_t size);
char* http_strdup(http_server_t* server, const char* str);

// Memory statistics functions
void memory_stats_update_alloc(memory_stats_t* stats, size_t size);
void memory_stats_update_free(memory_stats_t* stats, size_t size);
void memory_stats_log(const memory_stats_t* stats);

// Internal function declarations (only in implementation file)

#endif // HTTPSERVER_IMPL

#ifdef __cplusplus
}
#endif

#endif // HTTPSERVER_H