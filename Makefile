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
# -Wstrict-aliasing=3 (the -Wall default), not =2: level 2 is documented as
# "aggressive, quick, not too precise" and flags the canonical POSIX
# sockaddr_un -> sockaddr cast at -O2 even through an intermediate void*
# (gcc 13 on the CI runners) — a false positive WERROR turns into a build
# break. Level 3 keeps the real dereference-based aliasing analysis.
CFLAGS = -std=gnu11 -Wall -Wextra -Wstrict-prototypes \
         -Wmissing-prototypes -Wold-style-definition -Wredundant-decls \
         -Wbad-function-cast -Wnested-externs -Winit-self \
         -Wshadow -Wwrite-strings -Wcast-align -Wstrict-aliasing=3 \
         -Wmissing-include-dirs -Wformat=2 -Winit-self \
         -Wswitch-default -Wunused -Werror-implicit-function-declaration \
         $(VERSION_FLAGS)

# Platform-specific flags
ifeq ($(UNAME_S),Linux)
    # GCC-specific warnings
    CFLAGS += -Wlogical-op -Wdate-time
    # Linux-specific security flags. -fPIE/-pie are REQUESTED, not inherited:
    # relying on the host compiler's default-PIE meant non-mainstream
    # toolchains (vanilla upstream gcc, older cross compilers) shipped
    # ASLR-defeating non-PIE release binaries with all QA green (AR-05 L9).
    # distcheck now asserts the staged binary is ET_DYN with RELRO+NOW.
    SECURITY_FLAGS_DEBUG = -fstack-protector-strong -fstack-clash-protection -fcf-protection \
                          -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
    SECURITY_FLAGS_RELEASE = -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
                            -fstack-clash-protection -fcf-protection -fPIE -pie \
                            -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
endif

ifeq ($(UNAME_S),Darwin)
    # macOS-specific security flags (no cf-protection, stack-clash-protection, or Linux linker flags)
    SECURITY_FLAGS_DEBUG = -fstack-protector-strong
    SECURITY_FLAGS_RELEASE = -D_FORTIFY_SOURCE=2 -fstack-protector-strong
endif

ifeq ($(UNAME_S),FreeBSD)
    # GCC-specific warnings (GCC from ports)
    CFLAGS += -Wlogical-op -Wdate-time
    # FreeBSD security flags (ELF linker supports relro/now/noexecstack).
    # -fPIE/-pie requested explicitly — the ports gcc used in CI does not
    # default to PIE (AR-05 L9).
    SECURITY_FLAGS_DEBUG = -fstack-protector-strong -fstack-clash-protection -fcf-protection \
                          -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
    SECURITY_FLAGS_RELEASE = -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
                            -fstack-clash-protection -fcf-protection -fPIE -pie \
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

# Warnings-as-errors knob. CI passes WERROR=1 so the ~20 -W flags above gate
# merges instead of scrolling past in build logs (AR-05 L7: only
# -Werror-implicit-function-declaration was fatal, so new -Wshadow/-Wformat=2
# class diagnostics merged silently). Local builds stay non-Werror so a new
# compiler's novel warnings never block development.
ifeq ($(WERROR),1)
    CFLAGS += -Werror
endif

# clang-specific silencing (macOS 'gcc' is clang; WERROR promoted both of
# these long-standing diagnostics to hard errors):
# - -Wgnu-zero-variadic-macro-arguments: the ##__VA_ARGS__ comma-pasting GNU
#   extension in error.h's logging macros is deliberate (-std=gnu11).
# - -Wformat-nonliteral (clang's -Wformat=2 variant): fires on the bounded
#   vsnprintf wrappers in error.c/display.c whose fmt comes from internal
#   callers (same sites triaged for the AR-05 L1 flawfinder baseline); gcc's
#   -Wformat=2 does not flag va_list forwarding.
CC_IS_CLANG := $(shell $(CC) --version 2>/dev/null | grep -c clang)
ifneq ($(CC_IS_CLANG),0)
    CFLAGS += -Wno-gnu-zero-variadic-macro-arguments -Wno-format-nonliteral
endif

# Include directories
INCLUDES = -I$(SRCDIR)

# Libraries. No crypto library: randomness comes from /dev/urandom and the
# SHA256/MD5 strings in ssh_manager.c only parse `ssh-keygen -l` output, so
# the old -lssl -lcrypto linkage was a phantom dependency that put
# libssl/libcrypto DT_NEEDED entries in every shipped binary (AR-05 M2).
LIBS =

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

# BUILD_TYPE stamp: debug and release share build/obj and build/bin, but
# their flag sets differ radically (ASan/UBSan -O0 vs stripped NDEBUG -O2)
# and BUILD_TYPE is invisible to the dependency graph. Without the stamp,
# `make BUILD_TYPE=release` followed by `make BUILD_TYPE=debug test` printed
# "Nothing to be done" and ran the "sanitizer" suite against uninstrumented
# release objects — silently fake QA results (AR-05 M3). The recipe rewrites
# the stamp only when the recorded type differs, so crossing BUILD_TYPE (and
# only that) forces a full rebuild.
BUILDTYPE_STAMP = $(OBJDIR)/.buildtype
$(BUILDTYPE_STAMP): buildtype-force | $(OBJDIR)
	@if [ "`cat $(BUILDTYPE_STAMP) 2>/dev/null`" != "$(BUILD_TYPE)" ]; then \
		echo "$(BUILD_TYPE)" > $(BUILDTYPE_STAMP); \
	fi

.PHONY: buildtype-force
buildtype-force:

# Compile source files
$(OBJDIR)/%.o: $(SRCDIR)/%.c $(HEADERS) $(BUILDTYPE_STAMP) | $(OBJDIR)
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
$(OBJDIR)/test_%.o: $(TESTDIR)/test_%.c $(TESTDIR)/test.h $(HEADERS) $(BUILDTYPE_STAMP) | $(OBJDIR)
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
		cppcheck --enable=warning,performance,portability \
			--error-exitcode=1 --std=c11 \
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

# Security scan. --error-level=4: the codebase has zero level-5 constructs
# expressible in its style, so the old level-5 gate was green by construction
# (AR-05 L1). Every pre-existing level-4 hit was triaged and carries an
# inline "Flawfinder: ignore" with its rationale, so a NEW level-4 use of a
# strcpy/format/exec-class function now fails this target until it is either
# fixed or explicitly annotated.
.PHONY: security-scan
security-scan:
	@echo "Running security scan..."
	@if command -v flawfinder >/dev/null 2>&1; then \
		flawfinder --error-level=4 $(SRCDIR); \
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

# No docs target: it invoked `doxygen Doxyfile` against a Doxyfile that never
# existed in the repo or the dist manifest — failing for anyone with doxygen
# installed and false-succeeding (empty docs/) for everyone else (AR-05 L4).

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
# Archive COMMITTED VCS content, not the live working tree: the old cp -R of
# the manifest directories shipped any stray file nested inside src/, tests/,
# or completions/ (editor backups, experiment files, test-run droppings), so
# release tarballs were not reproducible from a tag and could leak unreviewed
# content (AR-05 L5). git archive draws from HEAD, which also inherently
# excludes VCS state, build products, cores, logs, and prior archives.
dist:
	@echo "Creating distribution tarball..."
	@git rev-parse --git-dir >/dev/null 2>&1 || \
		{ echo "ERROR: dist builds from committed VCS content and requires a git checkout" >&2; exit 1; }
	@if ! git diff-index --quiet HEAD -- $(DIST_MANIFEST) 2>/dev/null; then \
		echo "WARNING: working tree differs from HEAD for manifest paths; the archive contains committed content only" >&2; \
	fi
	git archive --prefix=$(DIST_ROOT)/ -o $(DIST_ARCHIVE) HEAD -- $(DIST_MANIFEST)

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
