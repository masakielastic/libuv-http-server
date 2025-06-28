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

// Memory monitoring implementation
void memory_pool_stats_log(const memory_pool_t* pool, const char* pool_name) {
    if (!pool || !pool_name) return;
    
    double usage_percent = 0.0;
    if (pool->block_count > 0) {
        usage_percent = (double)pool->allocated_count / pool->block_count * 100.0;
    }
    
    HTTP_LOG_INFO("Pool [%s]: %zu/%zu blocks used (%.1f%%), %zu bytes each", 
                  pool_name, pool->allocated_count, pool->block_count, 
                  usage_percent, pool->block_size);
    
    // Check for pool exhaustion warning
    if (usage_percent >= MEMORY_POOL_LOW_THRESHOLD * 100.0) {
        HTTP_LOG_WARN("Pool [%s] is %.1f%% full - consider increasing pool size", 
                      pool_name, usage_percent);
    }
}

void memory_stats_log_detailed(const http_server_t* server) {
    if (!server) return;
    
    HTTP_LOG_INFO("=== Detailed Memory Statistics ===");
    
    // Overall statistics
    memory_stats_log(&server->memory_stats);
    
    // Individual pool statistics
    memory_pool_stats_log(&server->small_pool, "Small");
    memory_pool_stats_log(&server->medium_pool, "Medium");
    memory_pool_stats_log(&server->large_pool, "Large");
    memory_pool_stats_log(&server->connection_pool, "Connection");
    
    // Calculate memory efficiency
    size_t total_pool_memory = 
        (server->small_pool.block_count * server->small_pool.block_size) +
        (server->medium_pool.block_count * server->medium_pool.block_size) +
        (server->large_pool.block_count * server->large_pool.block_size) +
        (server->connection_pool.block_count * server->connection_pool.block_size);
    
    HTTP_LOG_INFO("Total pool memory reserved: %zu bytes (%.2f MB)", 
                  total_pool_memory, (double)total_pool_memory / (1024 * 1024));
    
    if (server->memory_stats.total_allocated > 0) {
        double efficiency = (double)server->memory_stats.pool_hits / 
                           (server->memory_stats.pool_hits + server->memory_stats.pool_misses) * 100.0;
        HTTP_LOG_INFO("Memory pool efficiency: %.2f%%", efficiency);
    }
    
    HTTP_LOG_INFO("================================");
}

void memory_stats_check_thresholds(const http_server_t* server) {
    if (!server) return;
    
    // Convert bytes to MB for threshold comparison
    double current_usage_mb = (double)server->memory_stats.current_usage / (1024 * 1024);
    
    // Check critical threshold
    if (current_usage_mb >= MEMORY_CRITICAL_THRESHOLD_MB) {
        HTTP_LOG_ERROR("CRITICAL: Memory usage %.2f MB exceeds critical threshold %d MB", 
                       current_usage_mb, MEMORY_CRITICAL_THRESHOLD_MB);
        HTTP_LOG_ERROR("Consider restarting the server or investigating memory leaks");
    }
    // Check warning threshold
    else if (current_usage_mb >= MEMORY_WARNING_THRESHOLD_MB) {
        HTTP_LOG_WARN("WARNING: Memory usage %.2f MB exceeds warning threshold %d MB", 
                      current_usage_mb, MEMORY_WARNING_THRESHOLD_MB);
    }
    
    // Check individual pool utilization
    double small_usage = (double)server->small_pool.allocated_count / server->small_pool.block_count;
    double medium_usage = (double)server->medium_pool.allocated_count / server->medium_pool.block_count;
    double large_usage = (double)server->large_pool.allocated_count / server->large_pool.block_count;
    double conn_usage = (double)server->connection_pool.allocated_count / server->connection_pool.block_count;
    
    if (small_usage >= MEMORY_POOL_LOW_THRESHOLD) {
        HTTP_LOG_WARN("Small pool utilization high: %.1f%%", small_usage * 100.0);
    }
    if (medium_usage >= MEMORY_POOL_LOW_THRESHOLD) {
        HTTP_LOG_WARN("Medium pool utilization high: %.1f%%", medium_usage * 100.0);
    }
    if (large_usage >= MEMORY_POOL_LOW_THRESHOLD) {
        HTTP_LOG_WARN("Large pool utilization high: %.1f%%", large_usage * 100.0);
    }
    if (conn_usage >= MEMORY_POOL_LOW_THRESHOLD) {
        HTTP_LOG_WARN("Connection pool utilization high: %.1f%%", conn_usage * 100.0);
    }
}

// Timer callback for periodic memory statistics logging
static void memory_stats_timer_cb(uv_timer_t* timer) {
    http_server_t* server = (http_server_t*)timer->data;
    if (!server) return;
    
    HTTP_LOG_INFO("=== Periodic Memory Report ===");
    memory_stats_log_detailed(server);
    memory_stats_check_thresholds(server);
    
    // Adaptive buffer maintenance
    HTTP_LOG_INFO("=== Adaptive Buffer Report ===");
    buffer_stats_log(&server->request_buffer_stats, "Request Body");
    buffer_stats_log(&server->response_buffer_stats, "Response");
    buffer_stats_log(&server->read_buffer_stats, "Network Read");
    
    // Update server defaults based on collected statistics
    adaptive_buffer_update_server_defaults(server);
}

// Enable memory monitoring with periodic logging
http_server_error_t memory_monitoring_start(http_server_t* server) {
    if (!server) return HTTP_SERVER_ERROR_INVALID_PARAM;
    
    int result = uv_timer_init(server->loop, &server->memory_stats_timer);
    if (result != 0) {
        HTTP_LOG_ERROR("Failed to initialize memory stats timer: %s", uv_strerror(result));
        return HTTP_SERVER_ERROR_MEMORY;
    }
    
    server->memory_stats_timer.data = server;
    
    result = uv_timer_start(&server->memory_stats_timer, memory_stats_timer_cb, 
                           MEMORY_STATS_LOG_INTERVAL, MEMORY_STATS_LOG_INTERVAL);
    if (result != 0) {
        HTTP_LOG_ERROR("Failed to start memory stats timer: %s", uv_strerror(result));
        return HTTP_SERVER_ERROR_MEMORY;
    }
    
    server->memory_monitoring_enabled = 1;
    HTTP_LOG_INFO("Memory monitoring started (interval: %d seconds)", 
                  MEMORY_STATS_LOG_INTERVAL / 1000);
    
    return HTTP_SERVER_SUCCESS;
}

// Disable memory monitoring
void memory_monitoring_stop(http_server_t* server) {
    if (!server || !server->memory_monitoring_enabled) return;
    
    uv_timer_stop(&server->memory_stats_timer);
    server->memory_monitoring_enabled = 0;
    HTTP_LOG_INFO("Memory monitoring stopped");
}

// Memory leak detection
void memory_leak_check(const http_server_t* server) {
    if (!server) return;
    
    HTTP_LOG_INFO("=== Memory Leak Check ===");
    
    // Check for unfreed allocations
    if (server->memory_stats.current_usage > 0) {
        HTTP_LOG_WARN("Potential memory leak detected: %zu bytes still allocated", 
                      server->memory_stats.current_usage);
        
        double leak_mb = (double)server->memory_stats.current_usage / (1024 * 1024);
        if (leak_mb > 1.0) {
            HTTP_LOG_ERROR("Significant memory leak: %.2f MB not freed", leak_mb);
        }
    } else {
        HTTP_LOG_INFO("No memory leaks detected - all memory properly freed");
    }
    
    // Check pool consistency
    size_t total_allocated = server->small_pool.allocated_count + 
                            server->medium_pool.allocated_count +
                            server->large_pool.allocated_count +
                            server->connection_pool.allocated_count;
    
    if (total_allocated > 0) {
        HTTP_LOG_WARN("Pool leak detected: %zu blocks still allocated across all pools", 
                      total_allocated);
        
        if (server->small_pool.allocated_count > 0) {
            HTTP_LOG_WARN("Small pool: %zu blocks not returned", 
                          server->small_pool.allocated_count);
        }
        if (server->medium_pool.allocated_count > 0) {
            HTTP_LOG_WARN("Medium pool: %zu blocks not returned", 
                          server->medium_pool.allocated_count);
        }
        if (server->large_pool.allocated_count > 0) {
            HTTP_LOG_WARN("Large pool: %zu blocks not returned", 
                          server->large_pool.allocated_count);
        }
        if (server->connection_pool.allocated_count > 0) {
            HTTP_LOG_WARN("Connection pool: %zu blocks not returned", 
                          server->connection_pool.allocated_count);
        }
    } else {
        HTTP_LOG_INFO("All pool blocks properly returned");
    }
    
    // Calculate allocation/deallocation balance
    if (server->memory_stats.total_allocated != server->memory_stats.total_freed) {
        size_t imbalance = server->memory_stats.total_allocated > server->memory_stats.total_freed ?
                          server->memory_stats.total_allocated - server->memory_stats.total_freed :
                          server->memory_stats.total_freed - server->memory_stats.total_allocated;
        
        HTTP_LOG_WARN("Allocation/deallocation imbalance: %zu bytes", imbalance);
        HTTP_LOG_INFO("Total allocated: %zu bytes, Total freed: %zu bytes", 
                      server->memory_stats.total_allocated, server->memory_stats.total_freed);
    }
    
    HTTP_LOG_INFO("========================");
}

// ===== Adaptive Buffer Management Implementation =====

// Initialize buffer statistics
void buffer_stats_init(buffer_stats_t* stats) {
    if (!stats) return;
    
    memset(stats, 0, sizeof(buffer_stats_t));
    stats->last_update = time(NULL);
    stats->optimal_size = ADAPTIVE_BUFFER_MIN_SIZE;
}

// Update buffer statistics with new size sample
void buffer_stats_update(buffer_stats_t* stats, size_t size) {
    if (!stats || size == 0) return;
    
    // Add new sample to circular buffer
    stats->recent_sizes[stats->current_index] = size;
    stats->current_index = (stats->current_index + 1) % ADAPTIVE_BUFFER_SAMPLES;
    
    if (stats->sample_count < ADAPTIVE_BUFFER_SAMPLES) {
        stats->sample_count++;
    }
    
    stats->total_allocations++;
    stats->last_update = time(NULL);
    
    // Recalculate average and optimal size
    size_t sum = 0;
    for (size_t i = 0; i < stats->sample_count; i++) {
        sum += stats->recent_sizes[i];
    }
    
    stats->average_size = sum / stats->sample_count;
    
    // Calculate optimal size with some overhead
    size_t new_optimal = (size_t)(stats->average_size * ADAPTIVE_BUFFER_GROWTH_FACTOR);
    
    // Clamp to min/max bounds
    if (new_optimal < ADAPTIVE_BUFFER_MIN_SIZE) {
        new_optimal = ADAPTIVE_BUFFER_MIN_SIZE;
    } else if (new_optimal > ADAPTIVE_BUFFER_MAX_SIZE) {
        new_optimal = ADAPTIVE_BUFFER_MAX_SIZE;
    }
    
    // Only update optimal size if it's significantly different
    if (labs((long)new_optimal - (long)stats->optimal_size) > (long)(stats->optimal_size * 0.1)) {
        stats->optimal_size = new_optimal;
        stats->resize_count++;
    }
}

// Get optimal buffer size based on statistics
size_t buffer_stats_get_optimal_size(const buffer_stats_t* stats) {
    if (!stats || stats->sample_count == 0) {
        return ADAPTIVE_BUFFER_MIN_SIZE;
    }
    
    return stats->optimal_size;
}

// Log buffer statistics
void buffer_stats_log(const buffer_stats_t* stats, const char* buffer_type) {
    if (!stats || !buffer_type) return;
    
    if (stats->sample_count == 0) {
        HTTP_LOG_INFO("Buffer [%s]: No samples yet", buffer_type);
        return;
    }
    
    double efficiency = stats->total_allocations > 0 ? 
                       (double)stats->resize_count / stats->total_allocations * 100.0 : 0.0;
    
    HTTP_LOG_INFO("Buffer [%s]: avg=%zu, optimal=%zu, samples=%zu, resizes=%zu (%.1f%% efficiency)",
                  buffer_type, stats->average_size, stats->optimal_size, 
                  stats->sample_count, stats->resize_count, 100.0 - efficiency);
}

// Initialize TLS buffer
http_server_error_t tls_buffer_init(tls_buffer_t* buffer, size_t initial_size) {
    HTTP_CHECK_PARAM(buffer, HTTP_SERVER_ERROR_INVALID_PARAM);
    
    memset(buffer, 0, sizeof(tls_buffer_t));
    
    if (initial_size < TLS_BUFFER_INITIAL_SIZE) {
        initial_size = TLS_BUFFER_INITIAL_SIZE;
    }
    
    buffer->data = malloc(initial_size);
    if (!buffer->data) {
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_MEMORY, "Failed to allocate TLS buffer");
    }
    
    buffer->capacity = initial_size;
    buffer->optimal_capacity = initial_size;
    buffer_stats_init(&buffer->stats);
    
    return HTTP_SERVER_SUCCESS;
}

// Destroy TLS buffer
void tls_buffer_destroy(tls_buffer_t* buffer) {
    if (!buffer) return;
    
    free(buffer->data);
    memset(buffer, 0, sizeof(tls_buffer_t));
}

// Ensure TLS buffer has required capacity
http_server_error_t tls_buffer_ensure_capacity(tls_buffer_t* buffer, size_t required_size) {
    HTTP_CHECK_PARAM(buffer, HTTP_SERVER_ERROR_INVALID_PARAM);
    
    if (buffer->capacity >= required_size) {
        return HTTP_SERVER_SUCCESS;
    }
    
    // Calculate new capacity with some growth
    size_t new_capacity = required_size * 2;
    if (new_capacity > TLS_BUFFER_MAX_SIZE) {
        new_capacity = TLS_BUFFER_MAX_SIZE;
        if (new_capacity < required_size) {
            HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_BUFFER_OVERFLOW, 
                            "Required TLS buffer size %zu exceeds maximum %zu", 
                            required_size, (size_t)TLS_BUFFER_MAX_SIZE);
        }
    }
    
    char* new_data = realloc(buffer->data, new_capacity);
    if (!new_data) {
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_MEMORY, 
                        "Failed to resize TLS buffer from %zu to %zu bytes", 
                        buffer->capacity, new_capacity);
    }
    
    buffer->data = new_data;
    buffer->capacity = new_capacity;
    
    // Update statistics
    buffer_stats_update(&buffer->stats, required_size);
    
    return HTTP_SERVER_SUCCESS;
}

// Adaptive resize of TLS buffer based on usage patterns
http_server_error_t tls_buffer_adaptive_resize(tls_buffer_t* buffer) {
    HTTP_CHECK_PARAM(buffer, HTTP_SERVER_ERROR_INVALID_PARAM);
    
    size_t optimal = buffer_stats_get_optimal_size(&buffer->stats);
    
    // Only resize if optimal size is significantly different and beneficial
    if (optimal != buffer->optimal_capacity && 
        labs((long)optimal - (long)buffer->capacity) > (long)(buffer->capacity * 0.2)) {
        
        // For shrinking, only do it if we haven't used the extra space recently
        if (optimal < buffer->capacity) {
            time_t now = time(NULL);
            if (now - buffer->stats.last_update < 60) {  // Don't shrink if recently active
                return HTTP_SERVER_SUCCESS;
            }
        }
        
        char* new_data = realloc(buffer->data, optimal);
        if (!new_data) {
            // Realloc failure for shrinking is not critical
            if (optimal > buffer->capacity) {
                HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_MEMORY, 
                                "Failed to grow TLS buffer to optimal size %zu", optimal);
            }
            return HTTP_SERVER_SUCCESS;  // Shrinking failure is acceptable
        }
        
        buffer->data = new_data;
        buffer->capacity = optimal;
        buffer->optimal_capacity = optimal;
        
        HTTP_LOG_INFO("TLS buffer adaptively resized to %zu bytes", optimal);
    }
    
    return HTTP_SERVER_SUCCESS;
}

// Calculate adaptive buffer size
size_t adaptive_buffer_size(size_t current_size __attribute__((unused)), size_t required_size, const buffer_stats_t* stats) {
    if (!stats || stats->sample_count == 0) {
        // No statistics yet, use default growth
        size_t new_size = required_size * 2;
        return new_size < ADAPTIVE_BUFFER_MIN_SIZE ? ADAPTIVE_BUFFER_MIN_SIZE : 
               new_size > ADAPTIVE_BUFFER_MAX_SIZE ? ADAPTIVE_BUFFER_MAX_SIZE : new_size;
    }
    
    size_t optimal = buffer_stats_get_optimal_size(stats);
    
    // If required size fits in optimal, use optimal
    if (required_size <= optimal) {
        return optimal;
    }
    
    // Otherwise, grow from required size
    size_t new_size = (size_t)(required_size * ADAPTIVE_BUFFER_GROWTH_FACTOR);
    return new_size > ADAPTIVE_BUFFER_MAX_SIZE ? ADAPTIVE_BUFFER_MAX_SIZE : new_size;
}

// Update server's default buffer sizes based on collected statistics
void adaptive_buffer_update_server_defaults(http_server_t* server) {
    if (!server) return;
    
    // Update default read buffer size
    size_t optimal_read = buffer_stats_get_optimal_size(&server->read_buffer_stats);
    if (optimal_read != server->default_read_buffer_size) {
        server->default_read_buffer_size = optimal_read;
        HTTP_LOG_INFO("Updated default read buffer size to %zu bytes", optimal_read);
    }
}

// Get adaptive read buffer size
size_t adaptive_read_buffer_size(const http_server_t* server, size_t suggested_size) {
    if (!server) return suggested_size;
    
    size_t optimal = server->default_read_buffer_size;
    
    // Use the larger of suggested or optimal size
    return suggested_size > optimal ? suggested_size : optimal;
}

// ===== Async I/O Optimization Implementation =====

// Forward declaration
static void free_connection(uv_handle_t* handle);

// Initialize write request pool
http_server_error_t write_pool_init(write_pool_t* pool) {
    HTTP_CHECK_PARAM(pool, HTTP_SERVER_ERROR_INVALID_PARAM);
    
    memset(pool, 0, sizeof(write_pool_t));
    
    int result = pthread_mutex_init(&pool->mutex, NULL);
    if (result != 0) {
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_MEMORY, "Failed to initialize write pool mutex");
    }
    
    // Pre-allocate write request structures
    pool->allocated_requests = calloc(WRITE_REQUEST_POOL_SIZE, sizeof(write_request_t));
    if (!pool->allocated_requests) {
        pthread_mutex_destroy(&pool->mutex);
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_MEMORY, "Failed to allocate write request pool");
    }
    
    // Initialize free list
    pool->free_list = NULL;
    for (int i = 0; i < WRITE_REQUEST_POOL_SIZE; i++) {
        write_request_t* req = &pool->allocated_requests[i];
        req->is_pooled = 1;
        req->next = pool->free_list;
        pool->free_list = req;
        pool->free_count++;
    }
    
    pool->allocated_count = WRITE_REQUEST_POOL_SIZE;
    
    HTTP_LOG_INFO("Write request pool initialized with %d requests", WRITE_REQUEST_POOL_SIZE);
    return HTTP_SERVER_SUCCESS;
}

// Destroy write request pool
void write_pool_destroy(write_pool_t* pool) {
    if (!pool) return;
    
    pthread_mutex_destroy(&pool->mutex);
    free(pool->allocated_requests);
    memset(pool, 0, sizeof(write_pool_t));
}

// Acquire write request from pool
write_request_t* write_pool_acquire(write_pool_t* pool) {
    if (!pool) return NULL;
    
    pthread_mutex_lock(&pool->mutex);
    
    write_request_t* req = NULL;
    if (pool->free_list) {
        req = pool->free_list;
        pool->free_list = req->next;
        pool->free_count--;
        
        // Reset request structure
        memset(&req->uv_req, 0, sizeof(uv_write_t));
        req->connection = NULL;
        req->buffer = NULL;
        req->buffer_size = 0;
        req->buffer_count = 0;
        req->next = NULL;
        memset(req->bufs, 0, sizeof(req->bufs));
    }
    
    pthread_mutex_unlock(&pool->mutex);
    
    // If pool exhausted, allocate new request
    if (!req) {
        req = malloc(sizeof(write_request_t));
        if (req) {
            memset(req, 0, sizeof(write_request_t));
            req->is_pooled = 0;
        }
    }
    
    return req;
}

// Release write request back to pool
void write_pool_release(write_pool_t* pool, write_request_t* req) {
    if (!pool || !req) return;
    
    // Clean up request data
    if (req->buffer) {
        if (req->connection && req->connection->server) {
            http_free(req->connection->server, req->buffer, req->buffer_size);
        } else {
            free(req->buffer);
        }
        req->buffer = NULL;
    }
    
    if (req->is_pooled) {
        pthread_mutex_lock(&pool->mutex);
        req->next = pool->free_list;
        pool->free_list = req;
        pool->free_count++;
        pthread_mutex_unlock(&pool->mutex);
    } else {
        free(req);
    }
}

// Initialize I/O statistics
void io_stats_init(io_stats_t* stats) {
    if (!stats) return;
    
    memset(stats, 0, sizeof(io_stats_t));
    stats->last_update = time(NULL);
}

// Update read statistics
void io_stats_update_read(io_stats_t* stats, size_t bytes) {
    if (!stats) return;
    
    stats->total_reads++;
    stats->bytes_read += bytes;
    stats->syscall_count++;
    stats->last_update = time(NULL);
}

// Update write statistics
void io_stats_update_write(io_stats_t* stats, size_t bytes, int vectored, int pooled) {
    if (!stats) return;
    
    stats->total_writes++;
    stats->bytes_written += bytes;
    stats->syscall_count++;
    
    if (vectored) {
        stats->vectored_writes++;
    }
    
    if (pooled) {
        stats->pooled_requests++;
    } else {
        stats->malloc_requests++;
    }
    
    // Update averages
    if (stats->total_writes > 0) {
        stats->avg_write_size = (double)stats->bytes_written / stats->total_writes;
    }
    
    if (stats->vectored_writes > 0) {
        stats->avg_batch_size = (double)stats->total_writes / stats->vectored_writes;
    }
    
    stats->last_update = time(NULL);
}

// Log I/O statistics
void io_stats_log(const io_stats_t* stats) {
    if (!stats) return;
    
    HTTP_LOG_INFO("=== I/O Performance Statistics ===");
    HTTP_LOG_INFO("Reads: %zu total, %zu bytes (avg: %.1f bytes/read)", 
                  stats->total_reads, stats->bytes_read,
                  stats->total_reads > 0 ? (double)stats->bytes_read / stats->total_reads : 0.0);
    HTTP_LOG_INFO("Writes: %zu total, %zu bytes (avg: %.1f bytes/write)", 
                  stats->total_writes, stats->bytes_written, stats->avg_write_size);
    HTTP_LOG_INFO("Vectored writes: %zu (%.1f%% of total, avg batch: %.1f)", 
                  stats->vectored_writes, 
                  stats->total_writes > 0 ? (double)stats->vectored_writes / stats->total_writes * 100.0 : 0.0,
                  stats->avg_batch_size);
    HTTP_LOG_INFO("Request pool usage: %zu pooled, %zu malloc'd (%.1f%% pool hit rate)", 
                  stats->pooled_requests, stats->malloc_requests,
                  (stats->pooled_requests + stats->malloc_requests) > 0 ? 
                  (double)stats->pooled_requests / (stats->pooled_requests + stats->malloc_requests) * 100.0 : 0.0);
    HTTP_LOG_INFO("Total syscalls: %zu", stats->syscall_count);
    HTTP_LOG_INFO("=====================================");
}

// Optimized vectored write function
http_server_error_t async_write_vectored(struct http_connection_s* conn, 
                                        uv_buf_t* bufs, int buf_count,
                                        uv_write_cb callback) {
    HTTP_CHECK_PARAM(conn && bufs && buf_count > 0, HTTP_SERVER_ERROR_INVALID_PARAM);
    
    if (buf_count > VECTORED_IO_MAX_BUFFERS) {
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_INVALID_PARAM, 
                        "Buffer count %d exceeds maximum %d", buf_count, VECTORED_IO_MAX_BUFFERS);
    }
    
    // Acquire write request from pool
    write_request_t* req = write_pool_acquire(&conn->server->write_pool);
    if (!req) {
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_MEMORY, "Failed to acquire write request");
    }
    
    req->connection = conn;
    req->buffer_count = buf_count;
    
    // Copy buffer descriptors
    memcpy(req->bufs, bufs, buf_count * sizeof(uv_buf_t));
    
    // For single buffer writes from http_respond, take ownership of the buffer
    if (buf_count == 1 && bufs[0].len > 1024) {  // Likely a response buffer
        req->buffer = bufs[0].base;
        req->buffer_size = bufs[0].len;
    }
    
    // Calculate total bytes
    size_t total_bytes = 0;
    for (int i = 0; i < buf_count; i++) {
        total_bytes += bufs[i].len;
    }
    
    // Set callback data
    req->uv_req.data = req;
    
    // Update statistics
    io_stats_update_write(&conn->server->io_stats, total_bytes, 1, req->is_pooled);
    
    // Perform vectored write
    int result = uv_write(&req->uv_req, (uv_stream_t*)conn, req->bufs, buf_count, callback);
    if (result != 0) {
        write_pool_release(&conn->server->write_pool, req);
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_NETWORK, "uv_write failed: %s", uv_strerror(result));
    }
    
    return HTTP_SERVER_SUCCESS;
}

// Optimized response write function
http_server_error_t async_write_response(struct http_connection_s* conn,
                                        const char* headers, size_t header_len,
                                        const char* body, size_t body_len,
                                        uv_write_cb callback) {
    HTTP_CHECK_PARAM(conn && headers && header_len > 0, HTTP_SERVER_ERROR_INVALID_PARAM);
    
    uv_buf_t bufs[2];
    int buf_count = 1;
    
    // Setup header buffer
    bufs[0] = uv_buf_init((char*)headers, header_len);
    
    // Setup body buffer if present
    if (body && body_len > 0) {
        bufs[1] = uv_buf_init((char*)body, body_len);
        buf_count = 2;
    }
    
    return async_write_vectored(conn, bufs, buf_count, callback);
}

// Common write completion handler
void async_write_complete(uv_write_t* req, int status) {
    write_request_t* write_req = (write_request_t*)req->data;
    if (!write_req) return;
    
    http_connection_t* conn = write_req->connection;
    
    if (status < 0) {
        HTTP_LOG_ERROR("Write error: %s", uv_strerror(status));
        // Close connection on write error will be handled by protocol layer
        // Don't close here to avoid double-free issues
    } else {
        // Calculate total bytes written for statistics
        size_t total_bytes = 0;
        for (int i = 0; i < write_req->buffer_count; i++) {
            total_bytes += write_req->bufs[i].len;
        }
        
        // Handle post-write connection management
        if (conn && conn->server) {
            // Check if we should close the connection
            if (conn->shutdown_sent) {
                // Response sent and connection should be closed
                uv_close((uv_handle_t*)conn, free_connection);
            }
            // For Keep-Alive connections, leave the connection open
        }
    }
    
    // Release write request back to pool
    if (conn && conn->server) {
        write_pool_release(&conn->server->write_pool, write_req);
    } else {
        // Fallback cleanup
        if (write_req->buffer) {
            free(write_req->buffer);
        }
        if (!write_req->is_pooled) {
            free(write_req);
        }
    }
}

// I/O monitoring timer callback
static void io_stats_timer_cb(uv_timer_t* timer) {
    http_server_t* server = (http_server_t*)timer->data;
    if (!server) return;
    
    HTTP_LOG_INFO("=== Periodic I/O Performance Report ===");
    io_stats_log(&server->io_stats);
}

// Start I/O monitoring
http_server_error_t io_monitoring_start(http_server_t* server) {
    HTTP_CHECK_PARAM(server, HTTP_SERVER_ERROR_INVALID_PARAM);
    
    if (server->io_monitoring_enabled) {
        HTTP_LOG_WARN("I/O monitoring already started");
        return HTTP_SERVER_SUCCESS;
    }
    
    int result = uv_timer_init(server->loop, &server->io_stats_timer);
    if (result != 0) {
        HTTP_RETURN_ERROR(HTTP_SERVER_ERROR_MEMORY, "Failed to initialize I/O stats timer: %s", uv_strerror(result));
    }
    
    server->io_stats_timer.data = server;
    
    result = uv_timer_start(&server->io_stats_timer, io_stats_timer_cb, 
                           IO_STATS_UPDATE_INTERVAL, IO_STATS_UPDATE_INTERVAL);
    if (result != 0) {
        HTTP_LOG_ERROR("Failed to start I/O stats timer: %s", uv_strerror(result));
        return HTTP_SERVER_ERROR_MEMORY;
    }
    
    server->io_monitoring_enabled = 1;
    HTTP_LOG_INFO("I/O monitoring started (interval: %d ms)", IO_STATS_UPDATE_INTERVAL);
    
    return HTTP_SERVER_SUCCESS;
}

// Stop I/O monitoring
void io_monitoring_stop(http_server_t* server) {
    if (!server || !server->io_monitoring_enabled) return;
    
    uv_timer_stop(&server->io_stats_timer);
    server->io_monitoring_enabled = 0;
    HTTP_LOG_INFO("I/O monitoring stopped");
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

// Memory allocation callback with adaptive sizing
static void alloc_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    http_connection_t* conn = (http_connection_t*)handle;
    
    // Use adaptive buffer sizing
    size_t adaptive_size = adaptive_read_buffer_size(conn->server, suggested_size);
    
    buf->base = (char*)http_malloc(conn->server, adaptive_size);
    if (!buf->base) {
        buf->len = 0;
        return;
    }
    buf->len = adaptive_size;
    
    // Update statistics for future optimization
    buffer_stats_update(&conn->server->read_buffer_stats, adaptive_size);
    
    // Update I/O read statistics
    io_stats_update_read(&conn->server->io_stats, adaptive_size);
}

// Connection cleanup
static void free_connection(uv_handle_t* handle) {
    http_connection_t* conn = (http_connection_t*)handle;
    if (!conn) return;
    
    http_server_t* server = conn->server;
    
    if (conn->ssl) {
        SSL_free(conn->ssl);
    }
    
    // Cleanup adaptive TLS buffer
    if (conn->tls_enabled) {
        tls_buffer_destroy(&conn->tls_buffer);
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
// Flush TLS data to socket
static void flush_tls_data(http_connection_t* conn) {
    int pending = BIO_pending(conn->write_bio);
    
    if (pending > 0) {
        // Ensure TLS buffer has adequate capacity
        http_server_error_t buffer_result = tls_buffer_ensure_capacity(&conn->tls_buffer, pending);
        if (buffer_result != HTTP_SERVER_SUCCESS) {
            HTTP_LOG_ERROR("Failed to ensure TLS buffer capacity for %d bytes", pending);
            return;
        }
        
        int bytes = BIO_read(conn->write_bio, conn->tls_buffer.data, pending);
        
        if (bytes > 0) {
            // Use optimized async write with TLS buffer data
            uv_buf_t buf = uv_buf_init(conn->tls_buffer.data, bytes);
            
            http_server_error_t result = async_write_vectored(conn, &buf, 1, async_write_complete);
            if (result != HTTP_SERVER_SUCCESS) {
                HTTP_LOG_ERROR("Failed to write TLS data: error %d", result);
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
        size_t required_size = conn->body_length + length;
        
        // Use adaptive buffer sizing
        size_t new_capacity = adaptive_buffer_size(old_capacity, required_size, 
                                                   &conn->server->request_buffer_stats);
        
        char* new_body = http_realloc(conn->server, conn->body, old_capacity, new_capacity);
        if (!new_body) {
            HTTP_LOG_ERROR("Failed to reallocate memory for request body");
            return -1;
        }
        conn->body = new_body;
        conn->body_capacity = new_capacity;
        conn->optimal_body_capacity = new_capacity;
        
        // Update statistics
        buffer_stats_update(&conn->server->request_buffer_stats, new_capacity);
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
    conn->keep_alive_enabled = 1;  // Enable Keep-Alive by default for HTTP
    conn->requests_handled = 0;
    
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
            
            // Initialize adaptive TLS buffer
            http_server_error_t tls_init_result = tls_buffer_init(&conn->tls_buffer, TLS_BUFFER_INITIAL_SIZE);
            if (tls_init_result != HTTP_SERVER_SUCCESS) {
                HTTP_LOG_ERROR("Failed to initialize TLS buffer");
                BIO_free(conn->read_bio);
                BIO_free(conn->write_bio);
                SSL_free(conn->ssl);
                free(conn);
                return;
            }
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
    
    // Initialize adaptive buffer statistics
    buffer_stats_init(&server->request_buffer_stats);
    buffer_stats_init(&server->response_buffer_stats);
    buffer_stats_init(&server->read_buffer_stats);
    server->default_read_buffer_size = ADAPTIVE_BUFFER_MIN_SIZE;
    
    // Initialize async I/O optimization
    http_server_error_t write_pool_result = write_pool_init(&server->write_pool);
    if (write_pool_result != HTTP_SERVER_SUCCESS) {
        HTTP_LOG_ERROR("Failed to initialize write request pool");
        memory_pool_destroy(&server->connection_pool);
        memory_pool_destroy(&server->large_pool);
        memory_pool_destroy(&server->medium_pool);
        memory_pool_destroy(&server->small_pool);
        if (server->ssl_ctx) SSL_CTX_free(server->ssl_ctx);
        free(server);
        return NULL;
    }
    
    io_stats_init(&server->io_stats);
    
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
    
    // Start memory monitoring
    http_server_error_t monitor_result = memory_monitoring_start(server);
    if (monitor_result != HTTP_SERVER_SUCCESS) {
        HTTP_LOG_WARN("Failed to start memory monitoring, continuing without it");
    }
    
    // Start I/O performance monitoring
    http_server_error_t io_monitor_result = io_monitoring_start(server);
    if (io_monitor_result != HTTP_SERVER_SUCCESS) {
        HTTP_LOG_WARN("Failed to start I/O monitoring, continuing without it");
    }
    
    // Log initial memory state
    memory_stats_log_detailed(server);
    
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
    
    // Stop monitoring
    memory_monitoring_stop(server);
    io_monitoring_stop(server);
    
    // Log final statistics
    HTTP_LOG_INFO("Server shutdown - Final statistics:");
    memory_stats_log_detailed(server);
    io_stats_log(&server->io_stats);
    
    // Perform memory leak detection before destroying pools
    memory_leak_check(server);
    
    // Destroy async I/O resources
    write_pool_destroy(&server->write_pool);
    
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
    
    // Use adaptive buffer sizing for response
    size_t optimal_size = adaptive_buffer_size(0, required_size, &conn->server->response_buffer_stats);
    size_t actual_size = optimal_size > required_size ? optimal_size : required_size;
    
    // Allocate dynamic buffer using server's memory management
    char* response_buf = (char*)http_malloc(conn->server, actual_size);
    if (!response_buf) {
        HTTP_LOG_ERROR("Failed to allocate response buffer of size %zu", actual_size);
        return -1;
    }
    
    // Update statistics
    buffer_stats_update(&conn->server->response_buffer_stats, actual_size);
    
    int offset = 0;
    size_t remaining = actual_size;
    
    // Status line
    int written = snprintf(response_buf + offset, remaining, 
                          "HTTP/1.1 %d OK\r\n", response->status_code);
    if (written >= (int)remaining) {
        http_free(conn->server, response_buf, actual_size);
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
                http_free(conn->server, response_buf, actual_size);
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
            http_free(conn->server, response_buf, actual_size);
            return -1;
        }
        offset += written;
        remaining -= written;
    }
    
    // Connection header (Keep-Alive or Close)
    const char* connection_header = "Connection: close\r\n";
    if (conn->keep_alive_enabled && conn->requests_handled < MAX_KEEP_ALIVE_REQUESTS && !conn->tls_enabled) {
        connection_header = "Connection: keep-alive\r\n";
    }
    written = snprintf(response_buf + offset, remaining, "%s", connection_header);
    if (written >= (int)remaining) {
        http_free(conn->server, response_buf, actual_size);
        return -1;
    }
    offset += written;
    remaining -= written;
    
    // End headers
    written = snprintf(response_buf + offset, remaining, "\r\n");
    if (written >= (int)remaining) {
        http_free(conn->server, response_buf, actual_size);
        return -1;
    }
    offset += written;
    remaining -= written;
    
    // Body
    if (response->body) {
        if (response->body_length >= remaining) {
            http_free(conn->server, response_buf, actual_size);
            return -1;
        }
        memcpy(response_buf + offset, response->body, response->body_length);
        offset += response->body_length;
    }
    
    if (conn->tls_enabled) {
        // Send response via SSL (still uses single buffer for SSL compatibility)
        int bytes = SSL_write(conn->ssl, response_buf, offset);
        
        if (bytes > 0) {
            printf("Sent HTTPS response (%d bytes)\n", bytes);
            SSL_shutdown(conn->ssl);
            conn->shutdown_sent = 1;
            flush_tls_data(conn);
            
            // Update I/O statistics
            io_stats_update_write(&conn->server->io_stats, bytes, 0, 0);
            
            http_free(conn->server, response_buf, actual_size);
            return 0;
        } else {
            int err = SSL_get_error(conn->ssl, bytes);
            fprintf(stderr, "SSL_write failed: %d\n", err);
            http_free(conn->server, response_buf, actual_size);
            return -1;
        }
    } else {
        // Use optimized vectored write for plain HTTP
        // Separate headers from body for potential optimization
        size_t header_len = offset;
        if (response->body && response->body_length > 0) {
            header_len = offset - response->body_length;
        }
        
        http_server_error_t result;
        if (response->body && response->body_length > 0) {
            // Send headers and body separately using vectored I/O
            result = async_write_response(conn, response_buf, header_len, 
                                        response->body, response->body_length,
                                        async_write_complete);
        } else {
            // Headers only
            uv_buf_t buf = uv_buf_init(response_buf, header_len);
            result = async_write_vectored(conn, &buf, 1, async_write_complete);
        }
        
        if (result == HTTP_SERVER_SUCCESS) {
            printf("Sent HTTP response (%d bytes)\n", offset);
            
            // Handle connection based on Keep-Alive setting
            conn->requests_handled++;
            if (conn->keep_alive_enabled && conn->requests_handled < MAX_KEEP_ALIVE_REQUESTS) {
                // Keep connection alive for next request
                conn->shutdown_sent = 0;
                // Reset parser for next request
                llhttp_init(&conn->parser, HTTP_REQUEST, &conn->parser_settings);
                conn->parser.data = conn;
            } else {
                // Close connection
                conn->shutdown_sent = 1;
            }
            
            // Note: response_buf will be freed by async_write_complete
            return 0;
        } else {
            HTTP_LOG_ERROR("Failed to send HTTP response: error %d", result);
            http_free(conn->server, response_buf, actual_size);
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