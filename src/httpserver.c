#define _GNU_SOURCE
#define HTTPSERVER_IMPL
#include "httpserver.h"
#include <assert.h>
#include <strings.h>
#include <pthread.h>

// Forward declaration for internal connection structure
typedef struct http_connection_s http_connection_t;

// SSL initialization functions (from libuv-tls-server-sample.c)
static int generate_self_signed_cert(SSL_CTX* ctx) {
    EVP_PKEY* pkey = NULL;
    X509* x509 = NULL;
    EVP_PKEY_CTX* pkey_ctx = NULL;
    X509_NAME* name = NULL;
    int ret = 0;

    // Generate RSA key pair
    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pkey_ctx) goto cleanup;
    
    if (EVP_PKEY_keygen_init(pkey_ctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 2048) <= 0) goto cleanup;
    
    pkey = EVP_PKEY_new();
    if (!pkey) goto cleanup;
    
    if (EVP_PKEY_keygen(pkey_ctx, &pkey) <= 0) goto cleanup;

    // Create X.509 certificate
    x509 = X509_new();
    if (!x509) goto cleanup;

    X509_set_version(x509, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 3600);

    X509_set_pubkey(x509, pkey);

    name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"JP", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"Test", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"localhost", -1, -1, 0);

    X509_set_issuer_name(x509, name);

    if (!X509_sign(x509, pkey, EVP_sha256())) goto cleanup;

    // Set in SSL_CTX
    if (SSL_CTX_use_certificate(ctx, x509) != 1) goto cleanup;
    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) goto cleanup;

    ret = 1;

cleanup:
    if (pkey_ctx) EVP_PKEY_CTX_free(pkey_ctx);
    if (pkey) EVP_PKEY_free(pkey);
    if (x509) X509_free(x509);
    return ret;
}

// Load certificates from files
static int load_cert_files(SSL_CTX* ctx, const char* cert_file, const char* key_file) {
    // Load certificate file
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Failed to load certificate file: %s\n", cert_file);
        ERR_print_errors_fp(stderr);
        return 0;
    }
    
    // Load private key file
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "Failed to load private key file: %s\n", key_file);
        ERR_print_errors_fp(stderr);
        return 0;
    }
    
    // Verify that private key matches certificate
    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "Private key does not match certificate\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }
    
    return 1;
}

static int init_ssl(http_server_t* server) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    server->ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!server->ssl_ctx) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    // Security options
    SSL_CTX_set_options(server->ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    // Generate self-signed certificate
    if (!generate_self_signed_cert(server->ssl_ctx)) {
        fprintf(stderr, "Failed to generate self-signed certificate\n");
        return 0;
    }

    return 1;
}

static int init_ssl_with_certs(http_server_t* server, const char* cert_file, const char* key_file) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    server->ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (!server->ssl_ctx) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    // Security options
    SSL_CTX_set_options(server->ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);

    // Load certificates from files
    if (!load_cert_files(server->ssl_ctx, cert_file, key_file)) {
        fprintf(stderr, "Failed to load certificate files\n");
        return 0;
    }

    return 1;
}

// Memory allocation callback
static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    buf->base = (char*)malloc(suggested_size);
    buf->len = suggested_size;
}

// Connection cleanup
static void free_connection(uv_handle_t* handle) {
    http_connection_t* conn = (http_connection_t*)handle;
    
    if (conn->ssl) {
        SSL_free(conn->ssl);
    }
    
    // Free parsed request data
    free(conn->method);
    free(conn->url);
    free(conn->body);
    
    for (int i = 0; i < conn->header_count; i++) {
        free(conn->headers[i][0]);
        free(conn->headers[i][1]);
    }
    
    if (conn->pending_response) {
        http_response_destroy(conn->pending_response);
    }
    
    free(conn);
}

// TLS handshake handling
static int handle_tls_handshake(http_connection_t* conn) {
    int result = SSL_do_handshake(conn->ssl);
    
    if (result == 1) {
        if (!conn->handshake_complete) {
            conn->handshake_complete = 1;
            printf("TLS handshake completed successfully\n");
        }
        return 1;
    } else {
        int ssl_error = SSL_get_error(conn->ssl, result);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            return 0; // Continue handshake
        } else {
            char err_buf[256];
            ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
            fprintf(stderr, "TLS handshake failed: %s\n", err_buf);
            return -1;
        }
    }
}

// Write completion callback
static void on_write(uv_write_t* req, int status) {
    http_connection_t* conn = (http_connection_t*)req->handle;
    free(req);
    
    if (status) {
        fprintf(stderr, "Write error %s\n", uv_strerror(status));
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
        int bytes = BIO_read(conn->write_bio, buffer, sizeof(buffer));
        if (bytes > 0) {
            uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
            uv_buf_t buf = uv_buf_init(malloc(bytes), bytes);
            memcpy(buf.base, buffer, bytes);
            uv_write(req, (uv_stream_t*)conn, &buf, 1, on_write);
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
        conn->url = malloc(length + 1);
        memcpy(conn->url, at, length);
        conn->url[length] = '\0';
    }
    
    return 0;
}

static int on_header_field(llhttp_t* parser, const char* at, size_t length) {
    http_connection_t* conn = (http_connection_t*)parser->data;
    
    if (conn->header_count < 64) {
        conn->headers[conn->header_count][0] = malloc(length + 1);
        memcpy(conn->headers[conn->header_count][0], at, length);
        conn->headers[conn->header_count][0][length] = '\0';
    }
    
    return 0;
}

static int on_header_value(llhttp_t* parser, const char* at, size_t length) {
    http_connection_t* conn = (http_connection_t*)parser->data;
    
    if (conn->header_count < 64) {
        conn->headers[conn->header_count][1] = malloc(length + 1);
        memcpy(conn->headers[conn->header_count][1], at, length);
        conn->headers[conn->header_count][1][length] = '\0';
        conn->header_count++;
    }
    
    return 0;
}

static int on_headers_complete(llhttp_t* parser) {
    http_connection_t* conn = (http_connection_t*)parser->data;
    
    // Store method
    const char* method_str = llhttp_method_name(llhttp_get_method(parser));
    if (method_str) {
        conn->method = strdup(method_str);
    }
    
    return 0;
}

static int on_body(llhttp_t* parser, const char* at, size_t length) {
    http_connection_t* conn = (http_connection_t*)parser->data;
    
    if (conn->body_length + length > conn->body_capacity) {
        conn->body_capacity = (conn->body_length + length) * 2;
        conn->body = realloc(conn->body, conn->body_capacity);
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
            conn->body_capacity++;
            conn->body = realloc(conn->body, conn->body_capacity);
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
            int hs_result = handle_tls_handshake(conn);
            if (hs_result < 0) {
                uv_close((uv_handle_t*)conn, free_connection);
                goto cleanup;
            }
            flush_tls_data(conn);
            if (!conn->handshake_complete) {
                goto cleanup;
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
                    fprintf(stderr, "HTTP parse error: %s\n", llhttp_errno_name(err));
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
            fprintf(stderr, "HTTP parse error: %s\n", llhttp_errno_name(err));
            uv_close((uv_handle_t*)conn, free_connection);
            goto cleanup;
        }
    }

cleanup:
    if (buf->base) {
        free(buf->base);
    }
}

// New connection callback
static void on_new_connection(uv_stream_t* server, int status) {
    if (status < 0) {
        fprintf(stderr, "New connection error %s\n", uv_strerror(status));
        return;
    }

    http_server_t* http_server = (http_server_t*)server->data;
    http_connection_t* conn = (http_connection_t*)malloc(sizeof(http_connection_t));
    memset(conn, 0, sizeof(http_connection_t));
    
    conn->server = http_server;
    conn->tls_enabled = http_server->tls_enabled;
    uv_tcp_init(http_server->loop, &conn->tcp);
    conn->tcp.data = conn;
    
    if (uv_accept(server, (uv_stream_t*)conn) == 0) {
        // Setup SSL only if TLS is enabled
        if (conn->tls_enabled) {
            conn->ssl = SSL_new(http_server->ssl_ctx);
            if (!conn->ssl) {
                fprintf(stderr, "Failed to create SSL object\n");
                free(conn);
                return;
            }
            
            conn->read_bio = BIO_new(BIO_s_mem());
            conn->write_bio = BIO_new(BIO_s_mem());
            
            if (!conn->read_bio || !conn->write_bio) {
                fprintf(stderr, "Failed to create BIO objects\n");
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
        
        uv_read_start((uv_stream_t*)conn, alloc_buffer, on_read);
        if (conn->tls_enabled) {
            printf("New connection accepted, starting TLS handshake\n");
        } else {
            printf("New HTTP connection accepted\n");
        }
    } else {
        fprintf(stderr, "Failed to accept connection\n");
        free(conn);
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
    if (!server) return NULL;
    
    memset(server, 0, sizeof(http_server_t));
    server->port = config->port;
    server->handler = config->handler;
    server->loop = uv_default_loop();
    server->tls_enabled = config->tls_enabled;
    
    if (config->tls_enabled) {
        if (config->cert_file && config->key_file) {
            // Custom certificates
            if (!init_ssl_with_certs(server, config->cert_file, config->key_file)) {
                free(server);
                return NULL;
            }
        } else {
            // Self-signed certificate
            if (!init_ssl(server)) {
                free(server);
                return NULL;
            }
        }
    } else {
        // Plain HTTP, no SSL needed
        server->ssl_ctx = NULL;
    }
    
    uv_tcp_init(server->loop, &server->tcp);
    server->tcp.data = server;
    
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
    if (!response) return NULL;
    
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
    if (!response || !name || !value || response->header_count >= 64) return;
    
    response->headers[response->header_count][0] = strdup(name);
    response->headers[response->header_count][1] = strdup(value);
    response->header_count++;
}

void http_response_body(http_response_t* response, const char* body, size_t length) {
    if (!response) return;
    
    free(response->body);
    response->body = malloc(length + 1);
    memcpy(response->body, body, length);
    response->body[length] = '\0';
    response->body_length = length;
}

int http_respond(http_request_t* request, http_response_t* response) {
    if (!request || !response) return -1;
    
    http_connection_t* conn = request->connection;
    
    // Build HTTP response
    char* response_buf = malloc(8192);
    int offset = 0;
    
    // Status line
    offset += snprintf(response_buf + offset, 8192 - offset, 
                      "HTTP/1.1 %d OK\r\n", response->status_code);
    
    // Headers
    for (int i = 0; i < response->header_count; i++) {
        offset += snprintf(response_buf + offset, 8192 - offset,
                          "%s: %s\r\n", response->headers[i][0], response->headers[i][1]);
    }
    
    // Content-Length header
    if (response->body) {
        offset += snprintf(response_buf + offset, 8192 - offset,
                          "Content-Length: %zu\r\n", response->body_length);
    }
    
    // Connection close
    offset += snprintf(response_buf + offset, 8192 - offset, "Connection: close\r\n");
    
    // End headers
    offset += snprintf(response_buf + offset, 8192 - offset, "\r\n");
    
    // Body
    if (response->body) {
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