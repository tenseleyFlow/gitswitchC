# Makefile for gitswitch-c
# Safe git identity switching with SSH/GPG isolation

# Project configuration
PROJECT_NAME = gitswitch-c
VERSION = 1.0.2
TARGET = gitswitch

# Directories
SRCDIR = src
BUILDDIR = build
OBJDIR = $(BUILDDIR)/obj
BINDIR = $(BUILDDIR)/bin
TESTDIR = tests
DOCDIR = docs

# Platform detection
UNAME_S := $(shell uname -s)

# Compiler and flags
CC = gcc
CFLAGS = -std=gnu11 -Wall -Wextra -Wstrict-prototypes \
         -Wmissing-prototypes -Wold-style-definition -Wredundant-decls \
         -Wbad-function-cast -Wnested-externs -Winit-self \
         -Wshadow -Wwrite-strings -Wcast-align -Wstrict-aliasing=2 \
         -Wmissing-include-dirs -Wformat=2 -Winit-self \
         -Wswitch-default -Wunused -Werror-implicit-function-declaration

# Platform-specific flags
ifeq ($(UNAME_S),Linux)
    # GCC-specific warnings
    CFLAGS += -Wlogical-op -Wdate-time
    # Linux-specific security flags
    SECURITY_FLAGS_DEBUG = -fstack-protector-strong -fstack-clash-protection -fcf-protection \
                          -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
    SECURITY_FLAGS_RELEASE = -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
                            -fstack-clash-protection -fcf-protection \
                            -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
endif

ifeq ($(UNAME_S),Darwin)
    # macOS-specific security flags (no cf-protection, stack-clash-protection, or Linux linker flags)
    SECURITY_FLAGS_DEBUG = -fstack-protector-strong
    SECURITY_FLAGS_RELEASE = -D_FORTIFY_SOURCE=2 -fstack-protector-strong
    # macOS OpenSSL paths (Homebrew)
    OPENSSL_PREFIX := $(shell brew --prefix openssl@3 2>/dev/null || brew --prefix openssl 2>/dev/null)
    ifneq ($(OPENSSL_PREFIX),)
        INCLUDES += -I$(OPENSSL_PREFIX)/include
        LDFLAGS += -L$(OPENSSL_PREFIX)/lib
    endif
endif

# Debug/Release configurations
DEBUG_FLAGS = -g -O0 -DDEBUG -Wp,-U_FORTIFY_SOURCE -fsanitize=address -fsanitize=undefined \
              -fno-omit-frame-pointer -Wpedantic $(SECURITY_FLAGS_DEBUG)
RELEASE_FLAGS = -O2 -DNDEBUG -s $(SECURITY_FLAGS_RELEASE)

# Default to debug build
BUILD_TYPE ?= debug
ifeq ($(BUILD_TYPE),release)
    CFLAGS += $(RELEASE_FLAGS)
else
    CFLAGS += $(DEBUG_FLAGS)
endif

# Include directories
INCLUDES = -I$(SRCDIR)

# Libraries
LIBS = -lssl -lcrypto
# Note: TOML parsing library will be added (e.g., -ltoml or embedded parser)

# Source files (Phase 2 - Configuration Management)
PHASE2_SOURCES = $(SRCDIR)/main.c $(SRCDIR)/error.c $(SRCDIR)/utils.c \
                 $(SRCDIR)/display.c $(SRCDIR)/toml_parser.c $(SRCDIR)/config.c \
                 $(SRCDIR)/accounts.c

# Source files (Phase 3 - Git Operations)
PHASE3_SOURCES = $(PHASE2_SOURCES) $(SRCDIR)/git_ops.c

# Source files (Phase 4 - SSH Security Framework)
PHASE4_SOURCES = $(PHASE3_SOURCES) $(SRCDIR)/ssh_manager.c

# Source files (Phase 5 - GPG Environment Isolation)
PHASE5_SOURCES = $(PHASE4_SOURCES) $(SRCDIR)/gpg_manager.c

SOURCES = $(PHASE5_SOURCES)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
HEADERS = $(wildcard $(SRCDIR)/*.h)

# Test files
TEST_SOURCES = $(wildcard $(TESTDIR)/*.c)
TEST_OBJECTS = $(TEST_SOURCES:$(TESTDIR)/%.c=$(OBJDIR)/test_%.o)
TEST_TARGETS = $(TEST_SOURCES:$(TESTDIR)/%.c=$(BINDIR)/test_%)

# Default target
.PHONY: all
all: $(BINDIR)/$(TARGET)

# Create directories
$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(BINDIR):
	@mkdir -p $(BINDIR)

# Compile source files
$(OBJDIR)/%.o: $(SRCDIR)/%.c $(HEADERS) | $(OBJDIR)
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Link main executable
$(BINDIR)/$(TARGET): $(OBJECTS) | $(BINDIR)
	@echo "Linking $@..."
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) -o $@ $(LIBS)
	@echo "Build complete: $@"

# Install target
.PHONY: install
install: $(BINDIR)/$(TARGET)
	@echo "Installing $(TARGET)..."
	install -d $(DESTDIR)/usr/local/bin
	install -m 755 $(BINDIR)/$(TARGET) $(DESTDIR)/usr/local/bin/$(TARGET)
	@echo "Installation complete"

# Uninstall target
.PHONY: uninstall
uninstall:
	@echo "Uninstalling $(TARGET)..."
	rm -f $(DESTDIR)/usr/local/bin/$(TARGET)
	@echo "Uninstall complete"

# Test compilation
$(OBJDIR)/test_%.o: $(TESTDIR)/%.c $(HEADERS) | $(OBJDIR)
	@echo "Compiling test $<..."
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Test executables (exclude main.o to avoid multiple main functions)
$(BINDIR)/test_%: $(OBJDIR)/test_%.o $(filter-out $(OBJDIR)/main.o,$(OBJECTS)) | $(BINDIR)
	@echo "Linking test $@..."
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS)

# Build and run tests
.PHONY: test
test: $(TEST_TARGETS)
	@echo "Running tests..."
	@for test in $(TEST_TARGETS); do \
		echo "Running $$test..."; \
		$$test || exit 1; \
	done
	@echo "All tests passed!"

# Static analysis
.PHONY: analyze
analyze:
	@echo "Running static analysis..."
	@command -v cppcheck >/dev/null 2>&1 && \
		cppcheck --enable=all --std=c11 --suppress=missingIncludeSystem $(SRCDIR) || \
		echo "cppcheck not found - skipping static analysis"

# Code formatting
.PHONY: format
format:
	@echo "Formatting code..."
	@command -v clang-format >/dev/null 2>&1 && \
		clang-format -i $(SOURCES) $(HEADERS) || \
		echo "clang-format not found - skipping formatting"

# Security scan
.PHONY: security-scan
security-scan:
	@echo "Running security scan..."
	@command -v flawfinder >/dev/null 2>&1 && \
		flawfinder $(SRCDIR) || \
		echo "flawfinder not found - skipping security scan"

# Memory check (requires valgrind)
.PHONY: memcheck
memcheck: $(BINDIR)/$(TARGET)
	@echo "Running memory check..."
	@command -v valgrind >/dev/null 2>&1 && \
		valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all \
		--track-origins=yes --verbose --log-file=valgrind.log \
		$(BINDIR)/$(TARGET) --help || \
		echo "valgrind not found - skipping memory check"

# Documentation generation
.PHONY: docs
docs:
	@echo "Generating documentation..."
	@mkdir -p $(DOCDIR)
	@command -v doxygen >/dev/null 2>&1 && \
		doxygen Doxyfile || \
		echo "doxygen not found - skipping documentation generation"

# Clean targets
.PHONY: clean
clean:
	@echo "Cleaning build files..."
	rm -rf $(BUILDDIR)
	rm -f valgrind.log
	rm -f *.core core.*

.PHONY: distclean
distclean: clean
	@echo "Cleaning all generated files..."
	rm -rf $(DOCDIR)

# Development helpers
.PHONY: debug
debug: BUILD_TYPE=debug
debug: all

.PHONY: release
release: BUILD_TYPE=release
release: all

# Quick development cycle
.PHONY: dev
dev: clean debug test

# Show build information
.PHONY: info
info:
	@echo "Project: $(PROJECT_NAME) v$(VERSION)"
	@echo "Target: $(TARGET)"
	@echo "Build type: $(BUILD_TYPE)"
	@echo "Compiler: $(CC)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo "Sources: $(SOURCES)"
	@echo "Objects: $(OBJECTS)"

# Dependencies check
.PHONY: deps
deps:
	@echo "Checking dependencies..."
	@echo "Required tools:"
	@command -v $(CC) >/dev/null 2>&1 && echo "   $(CC)" || echo "   $(CC) - REQUIRED"
	@command -v make >/dev/null 2>&1 && echo "   make" || echo "   make - REQUIRED"
	@echo "Optional tools:"
	@command -v cppcheck >/dev/null 2>&1 && echo "   cppcheck" || echo "   cppcheck - for static analysis"
	@command -v clang-format >/dev/null 2>&1 && echo "   clang-format" || echo "   clang-format - for formatting"
	@command -v valgrind >/dev/null 2>&1 && echo "   valgrind" || echo "   valgrind - for memory checking"
	@command -v flawfinder >/dev/null 2>&1 && echo "   flawfinder" || echo "   flawfinder - for security scanning"
	@command -v doxygen >/dev/null 2>&1 && echo "   doxygen" || echo "   doxygen - for documentation"

# Help target
.PHONY: help
help:
	@echo "$(PROJECT_NAME) Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  all          Build the project (default)"
	@echo "  debug        Build debug version"
	@echo "  release      Build release version"
	@echo "  test         Build and run tests"
	@echo "  install      Install to system"
	@echo "  uninstall    Remove from system"
	@echo "  clean        Remove build files"
	@echo "  distclean    Remove all generated files"
	@echo "  format       Format source code"
	@echo "  analyze      Run static analysis"
	@echo "  security-scan Run security scan"
	@echo "  memcheck     Run memory checker"
	@echo "  docs         Generate documentation"
	@echo "  deps         Check dependencies"
	@echo "  info         Show build information"
	@echo "  dev          Quick development cycle (clean + debug + test)"
	@echo "  dist         Create distribution tarball"
	@echo "  rpm          Build RPM package"
	@echo "  help         Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  BUILD_TYPE   debug (default) or release"
	@echo "  CC           Compiler (default: gcc)"
	@echo "  DESTDIR      Installation prefix"

# RPM package building
PACKAGE = gitswitcher
RPM_VERSION = $(VERSION)

.PHONY: dist rpm
dist: clean
	@echo "Creating distribution tarball..."
	tar czf $(PACKAGE)-$(RPM_VERSION).tar.gz \
		--exclude='.git*' \
		--exclude='*.o' \
		--exclude='build' \
		--exclude='*.core' \
		--exclude='valgrind.log' \
		--transform 's,^,$(PACKAGE)-$(RPM_VERSION)/,' \
		src/ *.md Makefile $(PACKAGE).spec

rpm: dist
	@echo "Building RPM package..."
	@command -v rpmbuild >/dev/null 2>&1 || (echo "rpmbuild not available - install rpm-build package" && exit 1)
	mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	cp $(PACKAGE)-$(RPM_VERSION).tar.gz ~/rpmbuild/SOURCES/
	cp $(PACKAGE).spec ~/rpmbuild/SPECS/
	rpmbuild -ba ~/rpmbuild/SPECS/$(PACKAGE).spec
	@echo "RPM packages created in ~/rpmbuild/RPMS/"

# Prevent make from removing intermediate files
.SECONDARY: $(OBJECTS) $(TEST_OBJECTS)