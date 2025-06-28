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
#include <time.h>
#include <math.h>

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

// Memory monitoring configuration
#define MEMORY_STATS_LOG_INTERVAL 60000  // 60 seconds in milliseconds
#define MEMORY_WARNING_THRESHOLD_MB 100  // Warning at 100MB usage
#define MEMORY_CRITICAL_THRESHOLD_MB 500 // Critical at 500MB usage
#define MEMORY_POOL_LOW_THRESHOLD 0.8    // Warning when pool 80% full

// Dynamic buffer configuration
#define ADAPTIVE_BUFFER_MIN_SIZE 512     // Minimum buffer size
#define ADAPTIVE_BUFFER_MAX_SIZE 65536   // Maximum buffer size
#define ADAPTIVE_BUFFER_SAMPLES 10       // Number of samples for average calculation
#define ADAPTIVE_BUFFER_GROWTH_FACTOR 1.5 // Growth factor for adaptive sizing
#define TLS_BUFFER_INITIAL_SIZE 16384    // Initial TLS buffer size
#define TLS_BUFFER_MAX_SIZE 131072       // Maximum TLS buffer size

// Async I/O optimization configuration
#define WRITE_REQUEST_POOL_SIZE 256      // Pre-allocated write request pool size
#define VECTORED_IO_MAX_BUFFERS 8        // Maximum buffers for vectored I/O
#define ASYNC_WRITE_BATCH_SIZE 4         // Maximum batched write operations
#define IO_STATS_UPDATE_INTERVAL 1000    // I/O statistics update interval (ms)
#define KEEP_ALIVE_TIMEOUT 30000         // Keep-alive timeout in milliseconds
#define MAX_KEEP_ALIVE_REQUESTS 100      // Maximum requests per connection

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

// Adaptive buffer statistics
typedef struct buffer_stats_s {
    size_t recent_sizes[ADAPTIVE_BUFFER_SAMPLES];
    size_t sample_count;
    size_t current_index;
    size_t average_size;
    size_t optimal_size;
    size_t total_allocations;
    size_t resize_count;
    time_t last_update;
} buffer_stats_t;

// TLS buffer management
typedef struct tls_buffer_s {
    char* data;
    size_t size;
    size_t capacity;
    size_t optimal_capacity;
    buffer_stats_t stats;
} tls_buffer_t;

// Async I/O optimization structures
typedef struct write_request_s {
    uv_write_t uv_req;
    struct http_connection_s* connection;
    char* buffer;
    size_t buffer_size;
    int buffer_count;
    uv_buf_t bufs[VECTORED_IO_MAX_BUFFERS];
    int is_pooled;  // 1 if from pool, 0 if malloc'd
    struct write_request_s* next;  // For pool linked list
} write_request_t;

// I/O performance statistics
typedef struct io_stats_s {
    size_t total_reads;
    size_t total_writes;
    size_t bytes_read;
    size_t bytes_written;
    size_t vectored_writes;
    size_t pooled_requests;
    size_t malloc_requests;
    size_t syscall_count;
    double avg_write_size;
    double avg_batch_size;
    time_t last_update;
} io_stats_t;

// Write request pool
typedef struct write_pool_s {
    write_request_t* free_list;
    write_request_t* allocated_requests;
    size_t allocated_count;
    size_t free_count;
    pthread_mutex_t mutex;
} write_pool_t;

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
    
    // Memory monitoring
    uv_timer_t memory_stats_timer;
    int memory_monitoring_enabled;
    
    // Adaptive buffer management
    buffer_stats_t request_buffer_stats;  // For request body buffers
    buffer_stats_t response_buffer_stats; // For response buffers
    buffer_stats_t read_buffer_stats;     // For network read buffers
    size_t default_read_buffer_size;      // Current optimal read buffer size
    
    // Async I/O optimization
    write_pool_t write_pool;              // Pre-allocated write request pool
    io_stats_t io_stats;                  // I/O performance statistics
    uv_timer_t io_stats_timer;            // Timer for I/O statistics
    int io_monitoring_enabled;            // I/O monitoring flag
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
    size_t optimal_body_capacity;  // Adaptive capacity for body buffer
    
    // Response data
    http_response_t* pending_response;
    
    // Adaptive TLS buffer
    tls_buffer_t tls_buffer;
    
    // Keep-alive support
    int keep_alive_enabled;
    int requests_handled;
    uv_timer_t keep_alive_timer;
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

// Memory monitoring functions
void memory_stats_log_detailed(const http_server_t* server);
void memory_stats_check_thresholds(const http_server_t* server);
void memory_pool_stats_log(const memory_pool_t* pool, const char* pool_name);
http_server_error_t memory_monitoring_start(http_server_t* server);
void memory_monitoring_stop(http_server_t* server);
void memory_leak_check(const http_server_t* server);

// Adaptive buffer management functions
void buffer_stats_init(buffer_stats_t* stats);
void buffer_stats_update(buffer_stats_t* stats, size_t size);
size_t buffer_stats_get_optimal_size(const buffer_stats_t* stats);
void buffer_stats_log(const buffer_stats_t* stats, const char* buffer_type);

// TLS buffer management functions
http_server_error_t tls_buffer_init(tls_buffer_t* buffer, size_t initial_size);
void tls_buffer_destroy(tls_buffer_t* buffer);
http_server_error_t tls_buffer_ensure_capacity(tls_buffer_t* buffer, size_t required_size);
http_server_error_t tls_buffer_adaptive_resize(tls_buffer_t* buffer);

// Adaptive sizing functions
size_t adaptive_buffer_size(size_t current_size, size_t required_size, const buffer_stats_t* stats);
void adaptive_buffer_update_server_defaults(http_server_t* server);
size_t adaptive_read_buffer_size(const http_server_t* server, size_t suggested_size);

// Async I/O optimization functions
http_server_error_t write_pool_init(write_pool_t* pool);
void write_pool_destroy(write_pool_t* pool);
write_request_t* write_pool_acquire(write_pool_t* pool);
void write_pool_release(write_pool_t* pool, write_request_t* req);

// I/O statistics functions
void io_stats_init(io_stats_t* stats);
void io_stats_update_read(io_stats_t* stats, size_t bytes);
void io_stats_update_write(io_stats_t* stats, size_t bytes, int vectored, int pooled);
void io_stats_log(const io_stats_t* stats);
http_server_error_t io_monitoring_start(http_server_t* server);
void io_monitoring_stop(http_server_t* server);

// Optimized I/O functions
http_server_error_t async_write_vectored(struct http_connection_s* conn, 
                                        uv_buf_t* bufs, int buf_count,
                                        uv_write_cb callback);
http_server_error_t async_write_response(struct http_connection_s* conn,
                                        const char* headers, size_t header_len,
                                        const char* body, size_t body_len,
                                        uv_write_cb callback);
void async_write_complete(uv_write_t* req, int status);

// Internal function declarations (only in implementation file)

#endif // HTTPSERVER_IMPL

#ifdef __cplusplus
}
#endif

#endif // HTTPSERVER_H