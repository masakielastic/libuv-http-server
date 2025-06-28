#define _GNU_SOURCE
#define HTTPSERVER_IMPL
#include "httpserver.h"
#include <assert.h>
#include <strings.h>
#include <pthread.h>

// Forward declaration for internal connection structure
typedef struct http_connection_s http_connection_t;

// Cleanup function declarations
void cleanup_ssl_ctx(SSL_CTX** ptr);
void cleanup_ssl(SSL** ptr);
void cleanup_bio(BIO** ptr);
void cleanup_evp_pkey_ctx(EVP_PKEY_CTX** ptr);
void cleanup_evp_pkey(EVP_PKEY** ptr);
void cleanup_x509(X509** ptr);
void cleanup_memory(void** ptr);
void cleanup_http_connection(http_connection_t** ptr);

// Cleanup function definitions
void cleanup_ssl_ctx(SSL_CTX** ptr) { if (ptr && *ptr) { SSL_CTX_free(*ptr); *ptr = NULL; } }
void cleanup_ssl(SSL** ptr) { if (ptr && *ptr) { SSL_free(*ptr); *ptr = NULL; } }
void cleanup_bio(BIO** ptr) { if (ptr && *ptr) { BIO_free(*ptr); *ptr = NULL; } }
void cleanup_evp_pkey_ctx(EVP_PKEY_CTX** ptr) { if (ptr && *ptr) { EVP_PKEY_CTX_free(*ptr); *ptr = NULL; } }
void cleanup_evp_pkey(EVP_PKEY** ptr) { if (ptr && *ptr) { EVP_PKEY_free(*ptr); *ptr = NULL; } }
void cleanup_x509(X509** ptr) { if (ptr && *ptr) { X509_free(*ptr); *ptr = NULL; } }
void cleanup_memory(void** ptr) { if (ptr && *ptr) { free(*ptr); *ptr = NULL; } }
void cleanup_http_connection(http_connection_t** ptr) { if (ptr && *ptr) { free(*ptr); *ptr = NULL; } }

// Memory pool implementation
http_server_error_t memory_pool_init(memory_pool_t* pool, size_t block_size, size_t block_count) {
    HTTP_CHECK_PARAM(pool && block_size > 0 && block_count > 0, HTTP_SERVER_ERROR_INVALID_PARAM);
    
    memset(pool, 0, sizeof(memory_pool_t));
    pool->block_size = block_size;
    pool->block_count = block_count;
    pool->free_count = block_count;
    
    if (pthread_mutex_init(&pool->mutex, NULL) != 0) {
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_MEMORY, "Failed to initialize pool mutex");
    }
    
    // Allocate block array
    pool->blocks = calloc(block_count, sizeof(memory_block_t));
    if (!pool->blocks) {
        pthread_mutex_destroy(&pool->mutex);
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_MEMORY, "Failed to allocate block array");
    }
    
    // Allocate memory blocks and initialize linked list
    for (size_t i = 0; i < block_count; i++) {
        pool->blocks[i].ptr = malloc(block_size);
        if (!pool->blocks[i].ptr) {
            // Cleanup already allocated blocks
            for (size_t j = 0; j < i; j++) {
                free(pool->blocks[j].ptr);
            }
            free(pool->blocks);
            pthread_mutex_destroy(&pool->mutex);
            HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_MEMORY, "Failed to allocate memory block %zu", i);
        }
        
        pool->blocks[i].size = block_size;
        pool->blocks[i].in_use = 0;
        pool->blocks[i].next = (i < block_count - 1) ? &pool->blocks[i + 1] : NULL;
    }
    
    HTTP_LOG_INFO("Memory pool initialized: %zu blocks of %zu bytes each", block_count, block_size);
    return HTTP_SERVER_SUCCESS;
}

void memory_pool_destroy(memory_pool_t* pool) {
    if (!pool || !pool->blocks) return;
    
    pthread_mutex_lock(&pool->mutex);
    
    for (size_t i = 0; i < pool->block_count; i++) {
        if (pool->blocks[i].ptr) {
            free(pool->blocks[i].ptr);
        }
    }
    
    free(pool->blocks);
    pool->blocks = NULL;
    
    pthread_mutex_unlock(&pool->mutex);
    pthread_mutex_destroy(&pool->mutex);
    
    HTTP_LOG_INFO("Memory pool destroyed: %zu/%zu blocks were in use", 
                  pool->allocated_count, pool->block_count);
}

void* memory_pool_alloc(memory_pool_t* pool) {
    if (!pool || !pool->blocks) return NULL;
    
    pthread_mutex_lock(&pool->mutex);
    
    // Find first free block
    for (size_t i = 0; i < pool->block_count; i++) {
        if (!pool->blocks[i].in_use) {
            pool->blocks[i].in_use = 1;
            pool->allocated_count++;
            pool->free_count--;
            
            void* ptr = pool->blocks[i].ptr;
            pthread_mutex_unlock(&pool->mutex);
            return ptr;
        }
    }
    
    pthread_mutex_unlock(&pool->mutex);
    return NULL; // Pool exhausted
}

void memory_pool_free(memory_pool_t* pool, void* ptr) {
    if (!pool || !pool->blocks || !ptr) return;
    
    pthread_mutex_lock(&pool->mutex);
    
    // Find the block containing this pointer
    for (size_t i = 0; i < pool->block_count; i++) {
        if (pool->blocks[i].ptr == ptr && pool->blocks[i].in_use) {
            pool->blocks[i].in_use = 0;
            pool->allocated_count--;
            pool->free_count++;
            
            // Clear the memory for security
            memset(ptr, 0, pool->blocks[i].size);
            
            pthread_mutex_unlock(&pool->mutex);
            return;
        }
    }
    
    pthread_mutex_unlock(&pool->mutex);
    HTTP_LOG_WARN("Attempted to free pointer not in pool: %p", ptr);
}

// Memory statistics functions
void memory_stats_update_alloc(memory_stats_t* stats, size_t size) {
    if (!stats) return;
    
    stats->total_allocated += size;
    stats->current_usage += size;
    
    if (stats->current_usage > stats->peak_usage) {
        stats->peak_usage = stats->current_usage;
    }
}

void memory_stats_update_free(memory_stats_t* stats, size_t size) {
    if (!stats) return;
    
    stats->total_freed += size;
    if (stats->current_usage >= size) {
        stats->current_usage -= size;
    }
}

void memory_stats_log(const memory_stats_t* stats) {
    if (!stats) return;
    
    HTTP_LOG_INFO("Memory Statistics:");
    HTTP_LOG_INFO("  Total allocated: %zu bytes", stats->total_allocated);
    HTTP_LOG_INFO("  Total freed: %zu bytes", stats->total_freed);
    HTTP_LOG_INFO("  Current usage: %zu bytes", stats->current_usage);
    HTTP_LOG_INFO("  Peak usage: %zu bytes", stats->peak_usage);
    HTTP_LOG_INFO("  Pool hits: %zu", stats->pool_hits);
    HTTP_LOG_INFO("  Pool misses: %zu", stats->pool_misses);
    if (stats->pool_hits + stats->pool_misses > 0) {
        double hit_rate = (double)stats->pool_hits / (stats->pool_hits + stats->pool_misses) * 100.0;
        HTTP_LOG_INFO("  Pool hit rate: %.2f%%", hit_rate);
    }
}

// Smart memory management functions
void* http_malloc(http_server_t* server, size_t size) {
    if (!server || size == 0) return NULL;
    
    void* ptr = NULL;
    
    // Try to use appropriate pool based on size
    if (size <= MEMORY_POOL_SMALL_SIZE) {
        ptr = memory_pool_alloc(&server->small_pool);
        if (ptr) {
            server->memory_stats.pool_hits++;
            memory_stats_update_alloc(&server->memory_stats, MEMORY_POOL_SMALL_SIZE);
            return ptr;
        }
    } else if (size <= MEMORY_POOL_MEDIUM_SIZE) {
        ptr = memory_pool_alloc(&server->medium_pool);
        if (ptr) {
            server->memory_stats.pool_hits++;
            memory_stats_update_alloc(&server->memory_stats, MEMORY_POOL_MEDIUM_SIZE);
            return ptr;
        }
    } else if (size <= MEMORY_POOL_LARGE_SIZE) {
        ptr = memory_pool_alloc(&server->large_pool);
        if (ptr) {
            server->memory_stats.pool_hits++;
            memory_stats_update_alloc(&server->memory_stats, MEMORY_POOL_LARGE_SIZE);
            return ptr;
        }
    }
    
    // Pool allocation failed or size too large, fall back to malloc
    ptr = malloc(size);
    if (ptr) {
        server->memory_stats.pool_misses++;
        memory_stats_update_alloc(&server->memory_stats, size);
    }
    
    return ptr;
}

void* http_realloc(http_server_t* server, void* ptr, size_t old_size, size_t new_size) {
    if (!server) return realloc(ptr, new_size);
    
    // If growing within same pool category, try to get new block and copy
    if (ptr && old_size <= MEMORY_POOL_LARGE_SIZE && new_size <= MEMORY_POOL_LARGE_SIZE) {
        void* new_ptr = http_malloc(server, new_size);
        if (new_ptr) {
            memcpy(new_ptr, ptr, old_size < new_size ? old_size : new_size);
            http_free(server, ptr, old_size);
            return new_ptr;
        }
    }
    
    // Fall back to system realloc
    void* new_ptr = realloc(ptr, new_size);
    if (new_ptr && ptr) {
        // Update statistics for realloc
        memory_stats_update_free(&server->memory_stats, old_size);
        memory_stats_update_alloc(&server->memory_stats, new_size);
        server->memory_stats.pool_misses++;
    }
    
    return new_ptr;
}

void http_free(http_server_t* server, void* ptr, size_t size) {
    if (!server || !ptr) return;
    
    // Try pool-based free first
    if (size <= MEMORY_POOL_SMALL_SIZE) {
        memory_pool_free(&server->small_pool, ptr);
        memory_stats_update_free(&server->memory_stats, MEMORY_POOL_SMALL_SIZE);
        return;
    } else if (size <= MEMORY_POOL_MEDIUM_SIZE) {
        memory_pool_free(&server->medium_pool, ptr);
        memory_stats_update_free(&server->memory_stats, MEMORY_POOL_MEDIUM_SIZE);
        return;
    } else if (size <= MEMORY_POOL_LARGE_SIZE) {
        memory_pool_free(&server->large_pool, ptr);
        memory_stats_update_free(&server->memory_stats, MEMORY_POOL_LARGE_SIZE);
        return;
    }
    
    // Fall back to system free
    free(ptr);
    memory_stats_update_free(&server->memory_stats, size);
}

char* http_strdup(http_server_t* server, const char* str) {
    if (!server || !str) return NULL;
    
    size_t len = strlen(str);
    char* dup = http_malloc(server, len + 1);
    if (dup) {
        memcpy(dup, str, len + 1);
    }
    
    return dup;
}

// SSL initialization functions with improved error handling
static http_server_error_t generate_self_signed_cert(SSL_CTX* ctx) {
    HTTP_CHECK_PARAM(ctx, HTTP_SERVER_ERROR_INVALID_PARAM);
    
    EVP_PKEY_CTX* pkey_ctx __attribute__((cleanup(cleanup_evp_pkey_ctx))) = NULL;
    EVP_PKEY* pkey __attribute__((cleanup(cleanup_evp_pkey))) = NULL;
    X509* x509 __attribute__((cleanup(cleanup_x509))) = NULL;

    // Generate RSA key pair
    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pkey_ctx) {
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_SSL_INIT, "Failed to create EVP_PKEY_CTX");
    }
    
    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0) {
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_SSL_INIT, "Failed to initialize key generation");
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 2048) <= 0) {
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_SSL_INIT, "Failed to set RSA key size to 2048 bits");
    }
    
    pkey = EVP_PKEY_new();
    if (!pkey) {
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_SSL_INIT, "Failed to create EVP_PKEY");
    }
    
    if (EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0) {
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_SSL_INIT, "Failed to generate RSA key pair");
    }

    // Create X.509 certificate
    x509 = X509_new();
    if (!x509) {
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_SSL_INIT, "Failed to create X509 certificate");
    }

    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 3600);

    X509_set_pubkey(x509, pkey);

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"JP", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"Test", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0);

    X509_set_issuer_name(x509, name);

    if (!X509_sign(x509, pkey, EVP_sha256())) {
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_SSL_INIT, "Failed to sign X509 certificate");
    }

    // Set in SSL_CTX
    if (SSL_CTX_use_certificate(ctx, x509) != 1) {
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_SSL_INIT, "Failed to set certificate in SSL context");
    }
    
    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_SSL_INIT, "Failed to set private key in SSL context");
    }

    HTTP_LOG_INFO("Self-signed certificate generated successfully");
    return HTTP_SERVER_SUCCESS;
}

// Load certificates from files with improved error handling
static http_server_error_t load_cert_files(SSL_CTX* ctx, const char* cert_file, const char* key_file) {
    HTTP_CHECK_PARAM(ctx && cert_file && key_file, HTTP_SERVER_ERROR_INVALID_PARAM);
    
    // Load certificate file
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_CERT_LOAD, 
                         "Failed to load certificate file: %s", cert_file);
    }
    
    // Load private key file
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_CERT_LOAD,
                         "Failed to load private key file: %s", key_file);
    }
    
    // Verify that private key matches certificate
    if (SSL_CTX_check_private_key(ctx) != 1) {
        ERR_print_errors_fp(stderr);
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_CERT_LOAD,
                         "Private key does not match certificate");
    }
    
    HTTP_LOG_INFO("Certificate files loaded successfully: cert=%s, key=%s", cert_file, key_file);
    return HTTP_SERVER_SUCCESS;
}

static http_server_error_t init_ssl(http_server_t* server) {
    HTTP_CHECK_PARAM(server, HTTP_SERVER_ERROR_INVALID_PARAM);
    
    // Modern OpenSSL initialization (OpenSSL 1.1.0+)
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

    server->ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!server->ssl_ctx) {
        ERR_print_errors_fp(stderr);
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_SSL_INIT, "Failed to create SSL context");
    }

    // Modern security options - disable weak protocols and ciphers
    SSL_CTX_set_options(server->ssl_ctx, 
        SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |
        SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE |
        SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE);

    // Set minimum protocol version to TLS 1.2
    SSL_CTX_set_min_proto_version(server->ssl_ctx, TLS1_2_VERSION);

    // Set strong cipher suites
    if (!SSL_CTX_set_cipher_list(server->ssl_ctx, 
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256")) {
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_SSL_INIT, "Failed to set cipher list");
    }

    // Generate self-signed certificate
    http_server_error_t cert_result = generate_self_signed_cert(server->ssl_ctx);
    if (cert_result != HTTP_SERVER_SUCCESS) {
        return cert_result;
    }

    HTTP_LOG_INFO("SSL context initialized successfully with self-signed certificate");
    return HTTP_SERVER_SUCCESS;
}

static http_server_error_t init_ssl_with_certs(http_server_t* server, const char* cert_file, const char* key_file) {
    HTTP_CHECK_PARAM(server && cert_file && key_file, HTTP_SERVER_ERROR_INVALID_PARAM);
    
    // Modern OpenSSL initialization (OpenSSL 1.1.0+)
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

    server->ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!server->ssl_ctx) {
        ERR_print_errors_fp(stderr);
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_SSL_INIT, "Failed to create SSL context");
    }

    // Modern security options - disable weak protocols and ciphers
    SSL_CTX_set_options(server->ssl_ctx, 
        SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |
        SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE |
        SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE);

    // Set minimum protocol version to TLS 1.2
    SSL_CTX_set_min_proto_version(server->ssl_ctx, TLS1_2_VERSION);

    // Set strong cipher suites
    if (!SSL_CTX_set_cipher_list(server->ssl_ctx, 
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256")) {
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_SSL_INIT, "Failed to set cipher list");
    }

    // Load certificates from files
    http_server_error_t cert_result = load_cert_files(server->ssl_ctx, cert_file, key_file);
    if (cert_result != HTTP_SERVER_SUCCESS) {
        return cert_result;
    }

    HTTP_LOG_INFO("SSL context initialized successfully with custom certificates");
    return HTTP_SERVER_SUCCESS;
}

// Memory allocation callback
static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    http_connection_t* conn = (http_connection_t*)handle;
    
    buf->base = (char*)http_malloc(conn->server, suggested_size);
    if (!buf->base) {
        buf->len = 0;
        return;
    }
    buf->len = suggested_size;
}

// Connection cleanup
static void free_connection(uv_handle_t* handle) {
    http_connection_t* conn = (http_connection_t*)handle;
    if (!conn) return;
    
    http_server_t* server = conn->server;
    
    if (conn->ssl) {
        SSL_free(conn->ssl);
    }
    
    // Free parsed request data using pool-aware functions
    if (conn->method) {
        size_t method_size = strlen(conn->method) + 1;
        http_free(server, conn->method, method_size);
        conn->method = NULL;
    }
    
    if (conn->url) {
        size_t url_size = strlen(conn->url) + 1;
        http_free(server, conn->url, url_size);
        conn->url = NULL;
    }
    
    if (conn->body) {
        http_free(server, conn->body, conn->body_capacity);
        conn->body = NULL;
        conn->body_capacity = 0;
        conn->body_length = 0;
    }
    
    // Free headers using pool-aware functions
    for (int i = 0; i < conn->header_count; i++) {
        if (conn->headers[i][0]) {
            size_t name_size = strlen(conn->headers[i][0]) + 1;
            http_free(server, conn->headers[i][0], name_size);
            conn->headers[i][0] = NULL;
        }
        if (conn->headers[i][1]) {
            size_t value_size = strlen(conn->headers[i][1]) + 1;
            http_free(server, conn->headers[i][1], value_size);
            conn->headers[i][1] = NULL;
        }
    }
    conn->header_count = 0;
    
    if (conn->pending_response) {
        http_response_destroy(conn->pending_response);
        conn->pending_response = NULL;
    }
    
    // Try to free connection back to pool first
    memory_pool_free(&server->connection_pool, conn);
}

// TLS handshake handling with improved error reporting
static http_server_error_t handle_tls_handshake(http_connection_t* conn) {
    HTTP_CHECK_PARAM(conn && conn->ssl, HTTP_SERVER_ERROR_INVALID_PARAM);
    
    int result = SSL_do_handshake(conn->ssl);
    
    if (result == 1) {
        if (!conn->handshake_complete) {
            conn->handshake_complete = 1;
            HTTP_LOG_INFO("TLS handshake completed successfully");
        }
        return HTTP_SERVER_SUCCESS;
    } else {
        int ssl_error = SSL_get_error(conn->ssl, result);
        switch (ssl_error) {
            case SSL_ERROR_WANT_READ:
                HTTP_LOG_INFO("TLS handshake wants read - continuing");
                return HTTP_SERVER_ERROR_SSL_HANDSHAKE; // Non-fatal, continue
                
            case SSL_ERROR_WANT_WRITE:
                HTTP_LOG_INFO("TLS handshake wants write - continuing");
                return HTTP_SERVER_ERROR_SSL_HANDSHAKE; // Non-fatal, continue
                
            case SSL_ERROR_ZERO_RETURN:
                HTTP_LOG_WARN("TLS connection closed cleanly during handshake");
                return HTTP_SERVER_ERROR_SSL_HANDSHAKE;
                
            case SSL_ERROR_SYSCALL: {
                unsigned long err = ERR_get_error();
                if (err == 0) {
                    if (result == 0) {
                        HTTP_LOG_ERROR("TLS handshake failed: unexpected EOF");
                    } else {
                        HTTP_LOG_ERROR("TLS handshake failed: system call error");
                    }
                } else {
                    char err_buf[256];
                    ERR_error_string_n(err, err_buf, sizeof(err_buf));
                    HTTP_LOG_ERROR("TLS handshake failed: %s", err_buf);
                }
                return HTTP_SERVER_ERROR_SSL_HANDSHAKE;
            }
            
            default: {
                char err_buf[256];
                ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
                HTTP_LOG_ERROR("TLS handshake failed: %s (SSL error: %d)", err_buf, ssl_error);
                return HTTP_SERVER_ERROR_SSL_HANDSHAKE;
            }
        }
    }
}

// Write completion callback
static void on_write(uv_write_t* req, int status) {
    http_connection_t* conn = (http_connection_t*)req->handle;
    
    // Free the write request using memory pool
    http_free(conn->server, req, sizeof(uv_write_t));
    
    if (status) {
        HTTP_LOG_ERROR("Write error %s", uv_strerror(status));
        uv_close((uv_handle_t*)conn, free_connection);
        return;
    }
    
    // Close connection after response is sent
    if (conn->shutdown_sent) {
        uv_close((uv_handle_t*)conn, free_connection);
    }
}

// Flush TLS data to socket
static void flush_tls_data(http_connection_t* conn) {
    char buffer[16384];
    int pending = BIO_pending(conn->write_bio);
    
    if (pending > 0) {
        // Ensure we don't read more than buffer size
        int bytes_to_read = pending > (int)sizeof(buffer) ? (int)sizeof(buffer) : pending;
        int bytes = BIO_read(conn->write_bio, buffer, bytes_to_read);
        
        if (bytes > 0) {
            uv_write_t* req = (uv_write_t*)http_malloc(conn->server, sizeof(uv_write_t));
            if (!req) {
                HTTP_LOG_ERROR("Failed to allocate write request");
                return;
            }
            
            char* write_buf = http_malloc(conn->server, bytes);
            if (!write_buf) {
                HTTP_LOG_ERROR("Failed to allocate write buffer");
                http_free(conn->server, req, sizeof(uv_write_t));
                return;
            }
            
            memcpy(write_buf, buffer, bytes);
            uv_buf_t buf = uv_buf_init(write_buf, bytes);
            
            int result = uv_write(req, (uv_stream_t*)conn, &buf, 1, on_write);
            if (result != 0) {
                HTTP_LOG_ERROR("uv_write failed in flush_tls_data: %s", uv_strerror(result));
                http_free(conn->server, req, sizeof(uv_write_t));
                http_free(conn->server, write_buf, bytes);
            }
        }
    }
}

// HTTP parser callbacks
static int on_message_begin(llhttp_t* parser) {
    http_connection_t* conn = (http_connection_t*)parser->data;
    
    // Reset connection state for new request
    free(conn->method);
    free(conn->url);
    free(conn->body);
    
    for (int i = 0; i < conn->header_count; i++) {
        free(conn->headers[i][0]);
        free(conn->headers[i][1]);
    }
    
    conn->method = NULL;
    conn->url = NULL;
    conn->body = NULL;
    conn->body_length = 0;
    conn->body_capacity = 0;
    conn->header_count = 0;
    
    return 0;
}

static int on_url(llhttp_t* parser, const char* at, size_t length) {
    http_connection_t* conn = (http_connection_t*)parser->data;
    
    if (!conn->url) {
        conn->url = http_malloc(conn->server, length + 1);
        if (!conn->url) {
            HTTP_LOG_ERROR("Failed to allocate memory for URL");
            return -1;
        }
        memcpy(conn->url, at, length);
        conn->url[length] = '\0';
    }
    
    return 0;
}

static int on_header_field(llhttp_t* parser, const char* at, size_t length) {
    http_connection_t* conn = (http_connection_t*)parser->data;
    
    if (conn->header_count >= MAX_HEADERS) {
        fprintf(stderr, "Maximum number of headers exceeded (%d)\n", MAX_HEADERS);
        return -1;
    }
    
    conn->headers[conn->header_count][0] = http_malloc(conn->server, length + 1);
    if (!conn->headers[conn->header_count][0]) {
        HTTP_LOG_ERROR("Failed to allocate memory for header field");
        return -1;
    }
    
    memcpy(conn->headers[conn->header_count][0], at, length);
    conn->headers[conn->header_count][0][length] = '\0';
    
    return 0;
}

static int on_header_value(llhttp_t* parser, const char* at, size_t length) {
    http_connection_t* conn = (http_connection_t*)parser->data;
    
    if (conn->header_count >= MAX_HEADERS) {
        fprintf(stderr, "Maximum number of headers exceeded (%d)\n", MAX_HEADERS);
        return -1;
    }
    
    conn->headers[conn->header_count][1] = http_malloc(conn->server, length + 1);
    if (!conn->headers[conn->header_count][1]) {
        HTTP_LOG_ERROR("Failed to allocate memory for header value");
        return -1;
    }
    
    memcpy(conn->headers[conn->header_count][1], at, length);
    conn->headers[conn->header_count][1][length] = '\0';
    conn->header_count++;
    
    return 0;
}

static int on_headers_complete(llhttp_t* parser) {
    http_connection_t* conn = (http_connection_t*)parser->data;
    
    // Store method
    const char* method_str = llhttp_method_name(llhttp_get_method(parser));
    if (method_str) {
        conn->method = http_strdup(conn->server, method_str);
    }
    
    return 0;
}

static int on_body(llhttp_t* parser, const char* at, size_t length) {
    http_connection_t* conn = (http_connection_t*)parser->data;
    
    if (conn->body_length + length > conn->body_capacity) {
        size_t old_capacity = conn->body_capacity;
        size_t new_capacity = (conn->body_length + length) * 2;
        char* new_body = http_realloc(conn->server, conn->body, old_capacity, new_capacity);
        if (!new_body) {
            HTTP_LOG_ERROR("Failed to reallocate memory for request body");
            return -1;
        }
        conn->body = new_body;
        conn->body_capacity = new_capacity;
    }
    
    memcpy(conn->body + conn->body_length, at, length);
    conn->body_length += length;
    
    return 0;
}

static int on_message_complete(llhttp_t* parser) {
    http_connection_t* conn = (http_connection_t*)parser->data;
    
    // Null-terminate body if it exists
    if (conn->body) {
        if (conn->body_length >= conn->body_capacity) {
            size_t old_capacity = conn->body_capacity;
            size_t new_capacity = conn->body_capacity + 1;
            char* new_body = http_realloc(conn->server, conn->body, old_capacity, new_capacity);
            if (!new_body) {
                HTTP_LOG_ERROR("Failed to reallocate memory for null terminator");
                return -1;
            }
            conn->body = new_body;
            conn->body_capacity = new_capacity;
        }
        conn->body[conn->body_length] = '\0';
    }
    
    // Create request object and call handler
    http_request_t request = {
        .connection = conn,
        .method = conn->method,
        .url = conn->url,
        .body = conn->body,
        .body_length = conn->body_length
    };
    
    // Call user handler
    if (conn->server->handler) {
        conn->server->handler(&request);
    }
    
    return 0;
}

// Read callback
static void on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    http_connection_t* conn = (http_connection_t*)stream;
    
    if (nread < 0) {
        if (nread != UV_EOF) {
            fprintf(stderr, "Read error %s\n", uv_err_name(nread));
        }
        uv_close((uv_handle_t*)conn, free_connection);
        goto cleanup;
    }
    
    if (nread == 0) {
        goto cleanup;
    }
    
    if (conn->tls_enabled) {
        // TLS mode: Write data to read BIO
        BIO_write(conn->read_bio, buf->base, nread);
        
        // Handle TLS handshake
        if (!conn->handshake_complete) {
            http_server_error_t hs_result = handle_tls_handshake(conn);
            if (hs_result == HTTP_SERVER_ERROR_SSL_HANDSHAKE) {
                // Non-fatal handshake error, continue processing
                flush_tls_data(conn);
                if (!conn->handshake_complete) {
                    goto cleanup; // Still in progress, wait for more data
                }
            } else if (hs_result != HTTP_SERVER_SUCCESS) {
                // Fatal error
                HTTP_LOG_ERROR("Fatal TLS handshake error, closing connection");
                uv_close((uv_handle_t*)conn, free_connection);
                goto cleanup;
            } else {
                // Success
                flush_tls_data(conn);
            }
        }
        
        // Read HTTP data through SSL
        if (conn->handshake_complete && !conn->shutdown_sent) {
            char http_buf[4096];
            int bytes = SSL_read(conn->ssl, http_buf, sizeof(http_buf));
            if (bytes > 0) {
                // Parse HTTP with llhttp
                llhttp_errno_t err = llhttp_execute(&conn->parser, http_buf, bytes);
                if (err != HPE_OK) {
                    HTTP_LOG_ERROR("HTTP parse error in TLS mode: %s (error code: %d)", 
                                 llhttp_errno_name(err), err);
                    HTTP_LOG_ERROR("Parser state: method=%s, url=%s", 
                                 conn->method ? conn->method : "<none>",
                                 conn->url ? conn->url : "<none>");
                    uv_close((uv_handle_t*)conn, free_connection);
                    goto cleanup;
                }
            } else {
                int err = SSL_get_error(conn->ssl, bytes);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                    if (err != SSL_ERROR_ZERO_RETURN) {
                        fprintf(stderr, "SSL_read error: %d\n", err);
                    }
                    uv_close((uv_handle_t*)conn, free_connection);
                    goto cleanup;
                }
            }
            flush_tls_data(conn);
        }
    } else {
        // Plain HTTP mode: directly parse the raw data
        llhttp_errno_t err = llhttp_execute(&conn->parser, buf->base, nread);
        if (err != HPE_OK) {
            HTTP_LOG_ERROR("HTTP parse error in plain mode: %s (error code: %d)", 
                         llhttp_errno_name(err), err);
            HTTP_LOG_ERROR("Parser state: method=%s, url=%s, received %ld bytes", 
                         conn->method ? conn->method : "<none>",
                         conn->url ? conn->url : "<none>", nread);
            
            // Log problematic data for debugging (first 100 chars max)
            size_t log_len = nread > 100 ? 100 : nread;
            char debug_buf[101];
            memcpy(debug_buf, buf->base, log_len);
            debug_buf[log_len] = '\0';
            // Replace non-printable characters with dots for safe logging
            for (size_t i = 0; i < log_len; i++) {
                if (debug_buf[i] < 32 || debug_buf[i] > 126) {
                    debug_buf[i] = '.';
                }
            }
            HTTP_LOG_ERROR("Received data (first %zu bytes): %s", log_len, debug_buf);
            
            uv_close((uv_handle_t*)conn, free_connection);
            goto cleanup;
        }
    }

cleanup:
    if (buf->base) {
        http_free(conn->server, buf->base, buf->len);
    }
}

// New connection callback
static void on_new_connection(uv_stream_t* server, int status) {
    if (status < 0) {
        HTTP_LOG_ERROR("New connection error: %s", uv_strerror(status));
        return;
    }

    if (!server || !server->data) {
        HTTP_LOG_ERROR("Invalid parameter: server or server->data is NULL");
        return;
    }
    
    http_server_t* http_server = (http_server_t*)server->data;
    
    http_connection_t* conn __attribute__((cleanup(cleanup_http_connection))) = NULL;
    conn = (http_connection_t*)memory_pool_alloc(&http_server->connection_pool);
    if (!conn) {
        HTTP_LOG_ERROR("Failed to allocate connection from pool, falling back to malloc");
        conn = (http_connection_t*)malloc(sizeof(http_connection_t));
        HTTP_CHECK_MALLOC(conn, return);
    }
    
    memset(conn, 0, sizeof(http_connection_t));
    
    conn->server = http_server;
    conn->tls_enabled = http_server->tls_enabled;
    
    int init_result = uv_tcp_init(http_server->loop, &conn->tcp);
    if (init_result != 0) {
        HTTP_LOG_ERROR("Failed to initialize TCP handle: %s", uv_strerror(init_result));
        return;
    }
    
    conn->tcp.data = conn;
    
    int accept_result = uv_accept(server, (uv_stream_t*)conn);
    if (accept_result == 0) {
        // Setup SSL only if TLS is enabled
        if (conn->tls_enabled) {
            conn->ssl = SSL_new(http_server->ssl_ctx);
            if (!conn->ssl) {
                HTTP_LOG_ERROR("Failed to create SSL object");
                free(conn);
                return;
            }
            
            conn->read_bio = BIO_new(BIO_s_mem());
            conn->write_bio = BIO_new(BIO_s_mem());
            
            if (!conn->read_bio || !conn->write_bio) {
                HTTP_LOG_ERROR("Failed to create BIO objects");
                if (conn->read_bio) BIO_free(conn->read_bio);
                if (conn->write_bio) BIO_free(conn->write_bio);
                SSL_free(conn->ssl);
                free(conn);
                return;
            }
            
            SSL_set_bio(conn->ssl, conn->read_bio, conn->write_bio);
            SSL_set_accept_state(conn->ssl);
        }
        
        // Setup HTTP parser
        llhttp_settings_init(&conn->parser_settings);
        conn->parser_settings.on_message_begin = on_message_begin;
        conn->parser_settings.on_url = on_url;
        conn->parser_settings.on_header_field = on_header_field;
        conn->parser_settings.on_header_value = on_header_value;
        conn->parser_settings.on_headers_complete = on_headers_complete;
        conn->parser_settings.on_body = on_body;
        conn->parser_settings.on_message_complete = on_message_complete;
        
        llhttp_init(&conn->parser, HTTP_REQUEST, &conn->parser_settings);
        conn->parser.data = conn;
        
        int read_result = uv_read_start((uv_stream_t*)conn, alloc_buffer, on_read);
        if (read_result != 0) {
            HTTP_LOG_ERROR("Failed to start reading from connection: %s", uv_strerror(read_result));
            if (conn->tls_enabled && conn->ssl) {
                SSL_free(conn->ssl);
            }
            uv_close((uv_handle_t*)conn, free_connection);
            return;
        }
        if (conn->tls_enabled) {
            printf("New connection accepted, starting TLS handshake\n");
        } else {
            printf("New HTTP connection accepted\n");
        }
        // Successfully accepted and configured connection
        conn = NULL; // Transfer ownership to prevent cleanup
        
    } else {
        HTTP_LOG_ERROR("Failed to accept connection: %s", uv_strerror(accept_result));
        // conn will be cleaned up automatically by HTTP_AUTO_CLEANUP
    }
}


// Helper functions for configuration
http_server_config_t http_server_config_default(int port, http_request_handler_t handler) {
    http_server_config_t config = {0};
    config.port = port;
    config.handler = handler;
    config.tls_enabled = 1;  // HTTPS with self-signed cert by default
    config.cert_file = NULL;
    config.key_file = NULL;
    return config;
}

http_server_config_t http_server_config_http(int port, http_request_handler_t handler) {
    http_server_config_t config = {0};
    config.port = port;
    config.handler = handler;
    config.tls_enabled = 0;  // Plain HTTP
    config.cert_file = NULL;
    config.key_file = NULL;
    return config;
}

http_server_config_t http_server_config_https(int port, http_request_handler_t handler, 
                                              const char* cert_file, const char* key_file) {
    http_server_config_t config = {0};
    config.port = port;
    config.handler = handler;
    config.tls_enabled = 1;  // HTTPS with custom certs
    config.cert_file = cert_file;
    config.key_file = key_file;
    return config;
}

// Unified server creation function
http_server_t* http_server_create(const http_server_config_t* config) {
    if (!config || !config->handler) {
        fprintf(stderr, "Invalid server configuration\n");
        return NULL;
    }
    
    http_server_t* server = malloc(sizeof(http_server_t));
    if (!server) {
        fprintf(stderr, "Failed to allocate memory for server\n");
        return NULL;
    }
    
    memset(server, 0, sizeof(http_server_t));
    server->port = config->port;
    server->handler = config->handler;
    server->loop = uv_default_loop();
    server->tls_enabled = config->tls_enabled;
    
    if (config->tls_enabled) {
        http_server_error_t ssl_result;
        if (config->cert_file && config->key_file) {
            // Custom certificates
            ssl_result = init_ssl_with_certs(server, config->cert_file, config->key_file);
        } else {
            // Self-signed certificate
            ssl_result = init_ssl(server);
        }
        
        if (ssl_result != HTTP_SERVER_SUCCESS) {
            if (server->ssl_ctx) {
                SSL_CTX_free(server->ssl_ctx);
            }
            free(server);
            return NULL;
        }
    } else {
        // Plain HTTP, no SSL needed
        server->ssl_ctx = NULL;
    }
    
    // Initialize memory pools
    http_server_error_t pool_result;
    
    pool_result = memory_pool_init(&server->small_pool, MEMORY_POOL_SMALL_SIZE, MEMORY_POOL_SMALL_COUNT);
    if (pool_result != HTTP_SERVER_SUCCESS) {
        HTTP_LOG_ERROR("Failed to initialize small memory pool");
        if (server->ssl_ctx) SSL_CTX_free(server->ssl_ctx);
        free(server);
        return NULL;
    }
    
    pool_result = memory_pool_init(&server->medium_pool, MEMORY_POOL_MEDIUM_SIZE, MEMORY_POOL_MEDIUM_COUNT);
    if (pool_result != HTTP_SERVER_SUCCESS) {
        HTTP_LOG_ERROR("Failed to initialize medium memory pool");
        memory_pool_destroy(&server->small_pool);
        if (server->ssl_ctx) SSL_CTX_free(server->ssl_ctx);
        free(server);
        return NULL;
    }
    
    pool_result = memory_pool_init(&server->large_pool, MEMORY_POOL_LARGE_SIZE, MEMORY_POOL_LARGE_COUNT);
    if (pool_result != HTTP_SERVER_SUCCESS) {
        HTTP_LOG_ERROR("Failed to initialize large memory pool");
        memory_pool_destroy(&server->medium_pool);
        memory_pool_destroy(&server->small_pool);
        if (server->ssl_ctx) SSL_CTX_free(server->ssl_ctx);
        free(server);
        return NULL;
    }
    
    pool_result = memory_pool_init(&server->connection_pool, sizeof(http_connection_t), MEMORY_POOL_CONNECTION_COUNT);
    if (pool_result != HTTP_SERVER_SUCCESS) {
        HTTP_LOG_ERROR("Failed to initialize connection memory pool");
        memory_pool_destroy(&server->large_pool);
        memory_pool_destroy(&server->medium_pool);
        memory_pool_destroy(&server->small_pool);
        if (server->ssl_ctx) SSL_CTX_free(server->ssl_ctx);
        free(server);
        return NULL;
    }
    
    // Initialize memory statistics
    memset(&server->memory_stats, 0, sizeof(memory_stats_t));
    
    uv_tcp_init(server->loop, &server->tcp);
    server->tcp.data = server;
    
    HTTP_LOG_INFO("HTTP server created with memory pools");
    memory_stats_log(&server->memory_stats);
    
    return server;
}

int http_server_listen(http_server_t* server) {
    if (!server) return -1;
    
    struct sockaddr_in addr;
    uv_ip4_addr("0.0.0.0", server->port, &addr);
    
    uv_tcp_bind(&server->tcp, (const struct sockaddr*)&addr, 0);
    
    int r = uv_listen((uv_stream_t*)&server->tcp, 128, on_new_connection);
    if (r) {
        fprintf(stderr, "Listen error %s\n", uv_strerror(r));
        return r;
    }
    
    if (server->tls_enabled) {
        printf("HTTPS server listening on https://0.0.0.0:%d\n", server->port);
    } else {
        printf("HTTP server listening on http://0.0.0.0:%d\n", server->port);
    }
    fflush(stdout);
    
    return uv_run(server->loop, UV_RUN_DEFAULT);
}

void http_server_destroy(http_server_t* server) {
    if (!server) return;
    
    // Log final memory statistics
    HTTP_LOG_INFO("Server shutdown - Final memory statistics:");
    memory_stats_log(&server->memory_stats);
    
    // Destroy memory pools
    memory_pool_destroy(&server->connection_pool);
    memory_pool_destroy(&server->large_pool);
    memory_pool_destroy(&server->medium_pool);
    memory_pool_destroy(&server->small_pool);
    
    if (server->ssl_ctx) {
        SSL_CTX_free(server->ssl_ctx);
    }
    
    free(server);
}

// Request API
const char* http_request_method(http_request_t* request) {
    return request ? request->method : NULL;
}

const char* http_request_target(http_request_t* request) {
    return request ? request->url : NULL;
}

const char* http_request_header(http_request_t* request, const char* name) {
    if (!request || !name) return NULL;
    
    for (int i = 0; i < request->connection->header_count; i++) {
        if (strcasecmp(request->connection->headers[i][0], name) == 0) {
            return request->connection->headers[i][1];
        }
    }
    
    return NULL;
}

const char* http_request_body(http_request_t* request) {
    return request ? request->body : NULL;
}

size_t http_request_body_length(http_request_t* request) {
    return request ? request->body_length : 0;
}

// Response API
http_response_t* http_response_init(void) {
    http_response_t* response = malloc(sizeof(http_response_t));
    if (!response) {
        fprintf(stderr, "Failed to allocate memory for response\n");
        return NULL;
    }
    
    memset(response, 0, sizeof(http_response_t));
    response->status_code = 200;
    
    return response;
}

void http_response_status(http_response_t* response, int status) {
    if (response) {
        response->status_code = status;
    }
}

void http_response_header(http_response_t* response, const char* name, const char* value) {
    if (!response || !name || !value) return;
    
    if (response->header_count >= MAX_HEADERS) {
        fprintf(stderr, "Maximum number of response headers exceeded (%d)\n", MAX_HEADERS);
        return;
    }
    
    response->headers[response->header_count][0] = strdup(name);
    if (!response->headers[response->header_count][0]) {
        fprintf(stderr, "Failed to allocate memory for response header name\n");
        return;
    }
    
    response->headers[response->header_count][1] = strdup(value);
    if (!response->headers[response->header_count][1]) {
        fprintf(stderr, "Failed to allocate memory for response header value\n");
        free(response->headers[response->header_count][0]);
        response->headers[response->header_count][0] = NULL;
        return;
    }
    
    response->header_count++;
}

void http_response_body(http_response_t* response, const char* body, size_t length) {
    if (!response) return;
    
    free(response->body);
    response->body = malloc(length + 1);
    if (!response->body) {
        fprintf(stderr, "Failed to allocate memory for response body\n");
        response->body_length = 0;
        return;
    }
    memcpy(response->body, body, length);
    response->body[length] = '\0';
    response->body_length = length;
}

int http_respond(http_request_t* request, http_response_t* response) {
    if (!request || !response) return -1;
    
    http_connection_t* conn = request->connection;
    
    // Calculate required buffer size dynamically
    size_t required_size = 0;
    
    // Status line (HTTP/1.1 XXX OK\r\n)
    required_size += 64; // Conservative estimate for status line
    
    // Headers
    for (int i = 0; i < response->header_count; i++) {
        if (response->headers[i][0] && response->headers[i][1]) {
            required_size += strlen(response->headers[i][0]) + strlen(response->headers[i][1]) + 4; // ": \r\n"
        }
    }
    
    // Content-Length header
    if (response->body) {
        required_size += 64; // "Content-Length: XXXXXX\r\n"
    }
    
    // Connection close and end headers
    required_size += 32; // "Connection: close\r\n\r\n"
    
    // Body
    if (response->body) {
        required_size += response->body_length;
    }
    
    // Add safety margin
    required_size += 256;
    
    // Allocate dynamic buffer
    char* response_buf = malloc(required_size);
    if (!response_buf) {
        fprintf(stderr, "Failed to allocate response buffer of size %zu\n", required_size);
        return -1;
    }
    
    int offset = 0;
    size_t remaining = required_size;
    
    // Status line
    int written = snprintf(response_buf + offset, remaining, 
                          "HTTP/1.1 %d OK\r\n", response->status_code);
    if (written >= (int)remaining) {
        free(response_buf);
        return -1;
    }
    offset += written;
    remaining -= written;
    
    // Headers
    for (int i = 0; i < response->header_count; i++) {
        if (response->headers[i][0] && response->headers[i][1]) {
            written = snprintf(response_buf + offset, remaining,
                              "%s: %s\r\n", response->headers[i][0], response->headers[i][1]);
            if (written >= (int)remaining) {
                free(response_buf);
                return -1;
            }
            offset += written;
            remaining -= written;
        }
    }
    
    // Content-Length header
    if (response->body) {
        written = snprintf(response_buf + offset, remaining,
                          "Content-Length: %zu\r\n", response->body_length);
        if (written >= (int)remaining) {
            free(response_buf);
            return -1;
        }
        offset += written;
        remaining -= written;
    }
    
    // Connection close
    written = snprintf(response_buf + offset, remaining, "Connection: close\r\n");
    if (written >= (int)remaining) {
        free(response_buf);
        return -1;
    }
    offset += written;
    remaining -= written;
    
    // End headers
    written = snprintf(response_buf + offset, remaining, "\r\n");
    if (written >= (int)remaining) {
        free(response_buf);
        return -1;
    }
    offset += written;
    remaining -= written;
    
    // Body
    if (response->body) {
        if (response->body_length >= remaining) {
            free(response_buf);
            return -1;
        }
        memcpy(response_buf + offset, response->body, response->body_length);
        offset += response->body_length;
    }
    
    if (conn->tls_enabled) {
        // Send response via SSL
        int bytes = SSL_write(conn->ssl, response_buf, offset);
        free(response_buf);
        
        if (bytes > 0) {
            printf("Sent HTTPS response (%d bytes)\n", bytes);
            SSL_shutdown(conn->ssl);
            conn->shutdown_sent = 1;
            flush_tls_data(conn);
            return 0;
        } else {
            int err = SSL_get_error(conn->ssl, bytes);
            fprintf(stderr, "SSL_write failed: %d\n", err);
            return -1;
        }
    } else {
        // Send response directly via TCP
        uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
        if (!req) {
            fprintf(stderr, "Failed to allocate write request\n");
            free(response_buf);
            return -1;
        }
        
        uv_buf_t buf = uv_buf_init(response_buf, offset);
        
        int result = uv_write(req, (uv_stream_t*)conn, &buf, 1, on_write);
        if (result == 0) {
            printf("Sent HTTP response (%d bytes)\n", offset);
            conn->shutdown_sent = 1;
            return 0;
        } else {
            fprintf(stderr, "uv_write failed: %s\n", uv_strerror(result));
            free(req);
            free(response_buf);
            return -1;
        }
    }
}

void http_response_destroy(http_response_t* response) {
    if (!response) return;
    
    for (int i = 0; i < response->header_count; i++) {
        free(response->headers[i][0]);
        free(response->headers[i][1]);
    }
    
    free(response->body);
    free(response);
}