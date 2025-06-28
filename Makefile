CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
LLHTTP_CFLAGS = -Wall -Wextra -std=c99 -O2 -Wno-unused-parameter
INCLUDES = -Isrc
LIBS = -luv -lssl -lcrypto

# Source files
SOURCES = src/httpserver.c src/llhttp.c src/api.c src/http.c
OBJECTS = $(SOURCES:.c=.o)
HEADERS = src/httpserver.h src/llhttp.h

# Test programs
TEST_SOURCES = tests/test_unified.c
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)
TEST_TARGETS = test_unified

# Library
LIBRARY = libhttpserver.a

# Default target
all: $(LIBRARY) $(TEST_TARGETS)

# Static library
$(LIBRARY): $(OBJECTS)
	ar rcs $@ $^

# Test executables
test_unified: tests/test_unified.o $(LIBRARY)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Object files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Special rules for llhttp generated files (suppress unused parameter warnings)
src/llhttp.o: src/llhttp.c $(HEADERS)
	$(CC) $(LLHTTP_CFLAGS) $(INCLUDES) -c $< -o $@

src/api.o: src/api.c $(HEADERS)
	$(CC) $(LLHTTP_CFLAGS) $(INCLUDES) -c $< -o $@

src/http.o: src/http.c $(HEADERS)
	$(CC) $(LLHTTP_CFLAGS) $(INCLUDES) -c $< -o $@

# Clean target
clean:
	rm -f $(OBJECTS) $(TEST_OBJECTS) $(LIBRARY) $(TEST_TARGETS)

# Install target (optional)
install: $(LIBRARY)
	install -d /usr/local/lib
	install -d /usr/local/include
	install $(LIBRARY) /usr/local/lib/
	install src/httpserver.h /usr/local/include/

# Uninstall target (optional)
uninstall:
	rm -f /usr/local/lib/$(LIBRARY)
	rm -f /usr/local/include/httpserver.h

# Test target
test: test_unified
	./test_unified

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