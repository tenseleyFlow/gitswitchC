# Makefile for gitswitch-c
# Safe git identity switching with SSH/GPG isolation

# Project configuration
PROJECT_NAME = gitswitch-c
TARGET = gitswitch

# Install prefix (override for packaging, e.g. PREFIX=/usr). DESTDIR is honored
# on top of it for staged installs.
PREFIX ?= /usr/local

# Version: the VERSION file is the single source of truth for the release
# number, so the binary stamp is deterministic and identical in git checkouts
# and source tarballs. A VERSION= env override is honored for one-off builds.
# COMMIT is the short git hash (or "unknown" outside a checkout) for traceability.
VERSION ?= $(shell cat VERSION 2>/dev/null)
ifeq ($(strip $(VERSION)),)
    VERSION := unknown
endif
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION_FLAGS = -DGITSWITCH_VERSION=\"$(VERSION)\" -DGITSWITCH_COMMIT=\"$(COMMIT)\"

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
         -Wswitch-default -Wunused -Werror-implicit-function-declaration \
         $(VERSION_FLAGS)

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

ifeq ($(UNAME_S),FreeBSD)
    # GCC-specific warnings (GCC from ports)
    CFLAGS += -Wlogical-op -Wdate-time
    # FreeBSD security flags (ELF linker supports relro/now/noexecstack)
    SECURITY_FLAGS_DEBUG = -fstack-protector-strong -fstack-clash-protection -fcf-protection \
                          -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
    SECURITY_FLAGS_RELEASE = -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
                            -fstack-clash-protection -fcf-protection \
                            -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
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

# Optional GNU readline: gives the interactive add/edit prompts line editing
# and TAB path completion. Auto-detected; build still works without it (the
# prompt module falls back to fgets). Override with READLINE=0 to force off.
#
# GNU readline isn't on the default search path everywhere: on macOS it's a
# keg-only Homebrew formula, and on the BSDs it lives under /usr/local. Probe
# with those hints so the feature engages there too instead of silently
# degrading. The same hints are added to the real build flags when detected.
READLINE ?= auto
READLINE_HINT_CFLAGS :=
READLINE_HINT_LIBS :=
READLINE_BREW_PREFIX := $(shell brew --prefix readline 2>/dev/null)
ifneq ($(READLINE_BREW_PREFIX),)
  READLINE_HINT_CFLAGS += -I$(READLINE_BREW_PREFIX)/include
  READLINE_HINT_LIBS += -L$(READLINE_BREW_PREFIX)/lib
endif
ifneq ($(wildcard /usr/local/include/readline/readline.h),)
  READLINE_HINT_CFLAGS += -I/usr/local/include
  READLINE_HINT_LIBS += -L/usr/local/lib
endif
ifeq ($(READLINE),auto)
  READLINE_OK := $(shell echo 'int main(void){return 0;}' \
                  | $(CC) $(READLINE_HINT_CFLAGS) -include stdio.h -include readline/readline.h \
                    -xc - $(READLINE_HINT_LIBS) -lreadline -o /dev/null >/dev/null 2>&1 && echo 1)
else ifeq ($(READLINE),0)
  READLINE_OK :=
else
  READLINE_OK := 1
endif
ifeq ($(READLINE_OK),1)
  CFLAGS += -DHAVE_READLINE $(READLINE_HINT_CFLAGS)
  LIBS += $(READLINE_HINT_LIBS) -lreadline
endif

# Source files (Phase 2 - Configuration Management)
PHASE2_SOURCES = $(SRCDIR)/main.c $(SRCDIR)/error.c $(SRCDIR)/utils.c \
                 $(SRCDIR)/display.c $(SRCDIR)/toml_parser.c $(SRCDIR)/config.c \
                 $(SRCDIR)/accounts.c $(SRCDIR)/prompt.c

# Source files (Phase 3 - Git Operations)
PHASE3_SOURCES = $(PHASE2_SOURCES) $(SRCDIR)/git_ops.c

# Source files (Phase 4 - SSH Security Framework)
PHASE4_SOURCES = $(PHASE3_SOURCES) $(SRCDIR)/ssh_manager.c

# Source files (Phase 5 - GPG Environment Isolation)
PHASE5_SOURCES = $(PHASE4_SOURCES) $(SRCDIR)/gpg_manager.c

# Source files (audit remediation - signal-safe switching, SIG-01/SIG-02)
PHASE6_SOURCES = $(PHASE5_SOURCES) $(SRCDIR)/signals.c

SOURCES = $(PHASE6_SOURCES)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
HEADERS = $(wildcard $(SRCDIR)/*.h)

# Test files. Sources are named tests/test_*.c so the binary name reads
# naturally (tests/test_foo.c -> build/bin/test_foo); test.h is the harness.
TEST_SOURCES = $(wildcard $(TESTDIR)/test_*.c)
TEST_OBJECTS = $(TEST_SOURCES:$(TESTDIR)/test_%.c=$(OBJDIR)/test_%.o)
TEST_TARGETS = $(TEST_SOURCES:$(TESTDIR)/test_%.c=$(BINDIR)/test_%)

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
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(BINDIR)/$(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	@echo "Installing shell completions..."
	install -d $(DESTDIR)$(PREFIX)/share/bash-completion/completions
	install -m 644 completions/gitswitch.bash $(DESTDIR)$(PREFIX)/share/bash-completion/completions/$(TARGET)
	install -d $(DESTDIR)$(PREFIX)/share/zsh/site-functions
	install -m 644 completions/gitswitch.zsh $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_$(TARGET)
	install -d $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d
	install -m 644 completions/gitswitch.fish $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/$(TARGET).fish
	@echo "Installation complete"

# Uninstall target
.PHONY: uninstall
uninstall:
	@echo "Uninstalling $(TARGET)..."
	rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	rm -f $(DESTDIR)$(PREFIX)/share/bash-completion/completions/$(TARGET)
	rm -f $(DESTDIR)$(PREFIX)/share/zsh/site-functions/_$(TARGET)
	rm -f $(DESTDIR)$(PREFIX)/share/fish/vendor_completions.d/$(TARGET).fish
	@echo "Uninstall complete"

# Test compilation
$(OBJDIR)/test_%.o: $(TESTDIR)/test_%.c $(TESTDIR)/test.h $(HEADERS) | $(OBJDIR)
	@echo "Compiling test $<..."
	$(CC) $(CFLAGS) $(INCLUDES) -I$(TESTDIR) -c $< -o $@

# Test executables (exclude main.o to avoid multiple main functions)
$(BINDIR)/test_%: $(OBJDIR)/test_%.o $(filter-out $(OBJDIR)/main.o,$(OBJECTS)) | $(BINDIR)
	@echo "Linking test $@..."
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LIBS)

# Build and run tests. The main binary is a dependency because the CLI-level
# tests (tests/test_cli.c) exec build/bin/gitswitch: main.c is excluded from
# the test link (it defines main), so its command handlers are only reachable
# end-to-end through the binary itself.
.PHONY: test
ifeq ($(strip $(TEST_SOURCES)),)
test:
	@echo "ERROR: no C tests discovered under $(TESTDIR)/ (expected test_*.c)" >&2
	@exit 1
else
test: $(BINDIR)/$(TARGET) $(TEST_TARGETS)
	@echo "Running tests..."
	@for test in $(TEST_TARGETS); do \
		echo "Running $$test..."; \
		$$test || exit 1; \
	done
	@echo "All tests passed!"
endif

# Static analysis
.PHONY: analyze
analyze:
	@echo "Running static analysis..."
	@if command -v cppcheck >/dev/null 2>&1; then \
		cppcheck --enable=all --error-exitcode=1 --std=c11 \
			--suppress=missingIncludeSystem $(SRCDIR); \
	else \
		echo "cppcheck not installed - skipping static analysis"; \
	fi

# Code formatting
.PHONY: format
format:
	@echo "Formatting code..."
	@if command -v clang-format >/dev/null 2>&1; then \
		clang-format -i $(SOURCES) $(HEADERS); \
	else \
		echo "clang-format not installed - skipping formatting"; \
	fi

# Security scan
.PHONY: security-scan
security-scan:
	@echo "Running security scan..."
	@if command -v flawfinder >/dev/null 2>&1; then \
		flawfinder --error-level=5 $(SRCDIR); \
	else \
		echo "flawfinder not installed - skipping security scan"; \
	fi

# Memory check (requires Valgrind and a clean BUILD_TYPE=release build). ASan
# instrumentation and Valgrind must not be combined in the same binary.
MEMCHECK_TARGETS = $(BINDIR)/test_runner $(BINDIR)/test_security

.PHONY: memcheck
ifeq ($(BUILD_TYPE),release)
memcheck: $(BINDIR)/$(TARGET) $(MEMCHECK_TARGETS)
	@echo "Running memory check..."
	@set -e; \
	if command -v valgrind >/dev/null 2>&1; then \
		for target in $(MEMCHECK_TARGETS); do \
			echo "Valgrind: $$target"; \
			valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all \
				--track-origins=yes --error-exitcode=99 \
				--log-file=valgrind-%p.log "$$target"; \
		done; \
		echo "Valgrind: $(BINDIR)/$(TARGET) --help"; \
		valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all \
			--track-origins=yes --error-exitcode=99 \
			--log-file=valgrind-%p.log $(BINDIR)/$(TARGET) --help; \
	else \
		echo "valgrind not installed - skipping memory check"; \
	fi
else
memcheck:
	@if command -v valgrind >/dev/null 2>&1; then \
		echo "ERROR: memcheck requires a clean BUILD_TYPE=release build (ASan and Valgrind are incompatible)" >&2; \
		exit 2; \
	else \
		echo "valgrind not installed - skipping memory check"; \
	fi
endif

# Documentation generation
.PHONY: docs
docs:
	@echo "Generating documentation..."
	@mkdir -p $(DOCDIR)
	@if command -v doxygen >/dev/null 2>&1; then \
		doxygen Doxyfile; \
	else \
		echo "doxygen not installed - skipping documentation generation"; \
	fi

# Clean targets
.PHONY: clean
clean:
	@echo "Cleaning build files..."
	rm -rf $(BUILDDIR)
	rm -f valgrind*.log
	rm -f *.core core.*

.PHONY: distclean
distclean: clean
	@echo "Cleaning all generated files..."
	rm -rf $(DOCDIR)

# Development helpers. Re-invoke make with BUILD_TYPE on the command line so it
# is set before the parse-time `ifeq ($(BUILD_TYPE),release)` that selects the
# flag set. A target-specific `release: BUILD_TYPE=release` is applied too late
# (after parsing) and would silently build with the default debug flags.
.PHONY: debug
debug:
	$(MAKE) BUILD_TYPE=debug all

.PHONY: release
release:
	$(MAKE) BUILD_TYPE=release all

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
	@echo "  memcheck     Run memory checker (requires a clean release build)"
	@echo "  docs         Generate documentation"
	@echo "  deps         Check dependencies"
	@echo "  info         Show build information"
	@echo "  dev          Quick development cycle (clean + debug + test)"
	@echo "  dist         Create distribution tarball"
	@echo "  distcheck    Build, test, and stage-install the source tarball"
	@echo "  qa-contract-test Verify QA failure and cleanup contracts"
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
DIST_ROOT = $(PACKAGE)-$(RPM_VERSION)
DIST_ARCHIVE = $(DIST_ROOT).tar.gz
# Reviewed allowlist. Copying only these entries inherently excludes VCS/OMX
# state, build products, cores, logs, and previously generated archives.
DIST_MANIFEST = src tests completions VERSION LICENSE README.md Makefile $(PACKAGE).spec

.PHONY: dist distcheck qa-contract-test rpm
dist:
	@echo "Creating distribution tarball..."
	@set -eu; \
	tmp=$$(mktemp -d "$${TMPDIR:-/tmp}/gitswitch-dist.XXXXXX"); \
	trap 'rm -rf "$$tmp"' 0; \
	trap 'exit 1' 1 2 3 15; \
	mkdir "$$tmp/$(DIST_ROOT)"; \
	cp -R $(DIST_MANIFEST) "$$tmp/$(DIST_ROOT)/"; \
	tar -C "$$tmp" -czf "$$tmp/$(DIST_ARCHIVE)" \
		--exclude='.git' --exclude='.git/*' \
		--exclude='.omx' --exclude='.omx/*' \
		--exclude='build' --exclude='build/*' \
		--exclude='*.o' --exclude='*.core' --exclude='core' --exclude='core.*' \
		--exclude='valgrind*.log' --exclude='*.tar.gz' \
		"$(DIST_ROOT)"; \
	mv "$$tmp/$(DIST_ARCHIVE)" "$(CURDIR)/$(DIST_ARCHIVE)"

distcheck: dist
	@sh tests/test_dist.sh "$(CURDIR)/$(DIST_ARCHIVE)" "$(DIST_ROOT)" \
		"$(PREFIX)" "$(MAKE_COMMAND)"

qa-contract-test:
	@sh tests/test_qa.sh "$(CURDIR)" "$(MAKE_COMMAND)"

rpm: dist
	@echo "Building RPM package..."
	@command -v rpmbuild >/dev/null 2>&1 || (echo "rpmbuild not available - install rpm-build package" && exit 1)
	mkdir -p ~/rpmbuild/BUILD ~/rpmbuild/RPMS ~/rpmbuild/SOURCES \
		~/rpmbuild/SPECS ~/rpmbuild/SRPMS
	cp $(DIST_ARCHIVE) ~/rpmbuild/SOURCES/
	cp $(PACKAGE).spec ~/rpmbuild/SPECS/
	rpmbuild -ba ~/rpmbuild/SPECS/$(PACKAGE).spec
	@echo "RPM packages created in ~/rpmbuild/RPMS/"

# Prevent make from removing intermediate files
.SECONDARY: $(OBJECTS) $(TEST_OBJECTS)
