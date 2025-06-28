CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
INCLUDES = -I.
LIBS = -luv -lssl -lcrypto

# Source files
SOURCES = httpserver.c llhttp.c api.c http.c
OBJECTS = $(SOURCES:.c=.o)
HEADERS = httpserver.h llhttp.h

# Test programs
TEST_SOURCES = test_server.c test_mkcert.c test_http.c test_unified.c
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)
TEST_TARGETS = test_server test_mkcert test_http test_unified

# Library
LIBRARY = libhttpserver.a

# Default target
all: $(LIBRARY) $(TEST_TARGETS)

# Static library
$(LIBRARY): $(OBJECTS)
	ar rcs $@ $^

# Test executables
test_server: test_server.o $(LIBRARY)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

test_mkcert: test_mkcert.o $(LIBRARY)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

test_http: test_http.o $(LIBRARY)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

test_unified: test_unified.o $(LIBRARY)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Object files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Clean target
clean:
	rm -f $(OBJECTS) $(TEST_OBJECTS) $(LIBRARY) $(TEST_TARGETS)

# Install target (optional)
install: $(LIBRARY)
	install -d /usr/local/lib
	install -d /usr/local/include
	install $(LIBRARY) /usr/local/lib/
	install httpserver.h /usr/local/include/

# Uninstall target (optional)
uninstall:
	rm -f /usr/local/lib/$(LIBRARY)
	rm -f /usr/local/include/httpserver.h

# Test target
test: test_server
	./test_server

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: all

# Check dependencies
check-deps:
	@echo "Checking dependencies..."
	@pkg-config --exists libuv || echo "ERROR: libuv not found"
	@pkg-config --exists openssl || echo "ERROR: openssl not found"
	@echo "Dependencies check completed"

.PHONY: all clean install uninstall test debug check-deps