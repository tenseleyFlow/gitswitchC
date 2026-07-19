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
# and source tarballs. Freeze defaults at parse time: recursive ?= shell
# expressions used to re-run cat/git every time VERSION_FLAGS or the build
# fingerprint expanded. Explicit environment/command-line values are frozen
# too, but never probe the checkout (AR-07 L25).
ifeq ($(origin VERSION),undefined)
    VERSION := $(shell cat VERSION 2>/dev/null)
else
    override VERSION := $(VERSION)
endif
ifeq ($(strip $(VERSION)),)
    override VERSION := unknown
endif
ifeq ($(origin COMMIT),undefined)
    COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
else
    override COMMIT := $(COMMIT)
endif
VERSION_FLAGS := -DGITSWITCH_VERSION=\"$(VERSION)\" -DGITSWITCH_COMMIT=\"$(COMMIT)\"

# Directories
SRCDIR = src
BUILDDIR = build
OBJDIR = $(BUILDDIR)/obj
BINDIR = $(BUILDDIR)/bin
override BUILD_ROOT_MARKER_NAME := .gitswitch-build-root
override GITSWITCH_BUILD_ROOT := $(BUILDDIR)
export GITSWITCH_BUILD_ROOT
# Release publication is a security boundary, not a caller-selected build
# output. Keep its host helper in one untracked namespace even when ordinary
# build directories are redirected by a packager.
override TOOLBUILDDIR := build/tools
TESTDIR = tests
DOCDIR = docs
HOSTCC ?= cc

# Release-publisher helpers execute on the build host, so their compiler
# identity is deliberately separate from the target compiler below. As with
# CC, a multi-launcher HOSTCC command may provide the complete whitespace-free
# identity-file list explicitly; the default binds the resolved first launcher
# by content as well as by command spelling and version output.
HOSTCC_LAUNCHER := $(firstword $(HOSTCC))
HOSTCC_RESOLVED_DEFAULT := $(shell p=`command -v "$(HOSTCC_LAUNCHER)" 2>/dev/null` || exit 0; \
	d=$${p%/*}; b=`printf '%s\n' "$$p" | sed 's,.*/,,'`; \
	if test "$$d" = "$$p"; then d=.; b=$$p; fi; \
	cd "$$d" 2>/dev/null && printf '%s/%s' "$$PWD" "$$b")
HOSTCC_IDENTITY_FILE ?= $(HOSTCC_RESOLVED_DEFAULT)
HOSTCC_IDENTITY_FILES ?= $(HOSTCC_IDENTITY_FILE)
HOSTCC_VERSION_ID := $(shell $(HOSTCC) --version 2>/dev/null | sed -n '1p')
override GITSWITCH_HOSTCC_COMMAND := $(HOSTCC)
override GITSWITCH_HOSTCC_LAUNCHER := $(HOSTCC_LAUNCHER)
override GITSWITCH_HOSTCC_RESOLVED := $(HOSTCC_RESOLVED_DEFAULT)
override GITSWITCH_HOSTCC_IDENTITY_FILES := $(HOSTCC_IDENTITY_FILES)
override GITSWITCH_HOSTCC_VERSION := $(HOSTCC_VERSION_ID)
export GITSWITCH_HOSTCC_COMMAND
export GITSWITCH_HOSTCC_LAUNCHER
export GITSWITCH_HOSTCC_RESOLVED
export GITSWITCH_HOSTCC_IDENTITY_FILES
export GITSWITCH_HOSTCC_VERSION

# Compiler identity and target policy. Hardening follows the compiler's target,
# never the machine running Make. The launcher itself is content-fingerprinted
# so an in-place wrapper/toolchain policy change invalidates every shared
# object. Multi-launcher commands (for example, ccache plus a compiler) may set
# TOOLCHAIN_IDENTITY_FILES to the complete whitespace-free path list.
CC = gcc
CC_LAUNCHER := $(firstword $(CC))
# macOS still ships GNU make 3.81, whose parser treats an unescaped `#` inside
# $(shell ...) as a comment. Use the already-required POSIX sed instead of
# ${p##*/} here, without adding another parse-time tool dependency.
CC_RESOLVED_DEFAULT := $(shell p=`command -v "$(CC_LAUNCHER)" 2>/dev/null` || exit 0; \
	d=$${p%/*}; b=`printf '%s\n' "$$p" | sed 's,.*/,,'`; \
	if test "$$d" = "$$p"; then d=.; b=$$p; fi; \
	cd "$$d" 2>/dev/null && printf '%s/%s' "$$PWD" "$$b")
CC_IDENTITY_FILE ?= $(CC_RESOLVED_DEFAULT)
TOOLCHAIN_IDENTITY_FILES ?= $(CC_IDENTITY_FILE)
override TOOLCHAIN_FINGERPRINT_FAILURE := __GITSWITCH_INCOMPLETE_TOOLCHAIN_IDENTITY__
TOOLCHAIN_FILE_FINGERPRINT := $(shell ( \
	fingerprint=; \
	test -n "$(strip $(TOOLCHAIN_IDENTITY_FILES))" || exit 1; \
	for f in $(TOOLCHAIN_IDENTITY_FILES); do \
		test -f "$$f" && test -r "$$f" || exit 1; \
		if command -v sha256sum >/dev/null 2>&1; then \
			digest_output=`sha256sum "$$f"` || exit 1; \
			digest=$${digest_output%% *}; \
		elif command -v shasum >/dev/null 2>&1; then \
			digest_output=`shasum -a 256 "$$f"` || exit 1; \
			digest=$${digest_output%% *}; \
		elif command -v sha256 >/dev/null 2>&1; then \
			digest=`sha256 -q "$$f"` || exit 1; \
		else \
			digest_output=`cksum "$$f"` || exit 1; \
			set -- $$digest_output; \
			test -n "$$1" && test -n "$$2" || exit 1; \
			digest=$$1:$$2; \
		fi; \
		test -n "$$digest" || exit 1; \
		fingerprint=$$fingerprint$$f=$$digest\;; \
	done; \
	test -n "$$fingerprint" || exit 1; \
	printf '%s' "$$fingerprint"; \
) || printf '%s' '$(TOOLCHAIN_FINGERPRINT_FAILURE)')
CC_VERSION_ID := $(shell $(CC) --version 2>/dev/null | sed -n '1p')
override TARGET_TRIPLE_DETECTED := $(shell $(CC) -dumpmachine 2>/dev/null | sed -n '1p')
# A claimed target is security policy, not caller metadata: accepting a
# command-line TARGET_TRIPLE let a native x86 compiler claim AArch64 and omit
# CET while still producing an x86 release. Always bind the policy to the
# selected compiler's own target report.
override TARGET_TRIPLE := $(strip $(TARGET_TRIPLE_DETECTED))
override TARGET_ARCH := $(firstword $(subst -, ,$(TARGET_TRIPLE)))

# Platform detection (OS selects linker/ABI policy; architecture comes from
# TARGET_TRIPLE above). UNAME_M remains diagnostic fingerprint material only.
override UNAME_S := $(shell uname -s)
override UNAME_M := $(shell uname -m)

# Destination control-flow protection is selected by target architecture and
# compile-probed against the actual compiler. Unsupported optional protection
# is omitted; host uname can neither add the wrong ISA flag nor remove the
# destination-appropriate one.
ifneq ($(filter x86_64 i386 i486 i586 i686,$(TARGET_ARCH)),)
    override CF_PROTECTION_CANDIDATE := -fcf-protection
else ifneq ($(filter aarch64 arm64,$(TARGET_ARCH)),)
    override CF_PROTECTION_CANDIDATE := -mbranch-protection=standard
else
    override CF_PROTECTION_CANDIDATE :=
endif
ifneq ($(CF_PROTECTION_CANDIDATE),)
    override CF_PROTECTION := $(shell printf 'int gitswitch_cf_probe(void){return 0;}\n' | \
	$(CC) $(CF_PROTECTION_CANDIDATE) -x c -c -o /dev/null - \
	>/dev/null 2>&1 && printf '%s' '$(CF_PROTECTION_CANDIDATE)')
else
    override CF_PROTECTION :=
endif

# Compiler and flags
# Compiler family, needed before the flag set: macOS 'gcc' is clang, and a
# few spellings/diagnostics differ (see the clang block further down).
CC_IS_CLANG := $(shell $(CC) --version 2>/dev/null | grep -c clang)

# -Wstrict-aliasing=3 (the -Wall default), not =2: level 2 is documented as
# "aggressive, quick, not too precise" and flags the canonical POSIX
# sockaddr_un -> sockaddr cast at -O2 even through an intermediate void*
# (gcc 13 on the CI runners) — a false positive WERROR turns into a build
# break. Level 3 keeps the real dereference-based aliasing analysis. clang
# only understands the bare spelling (the =N levels are gcc-specific and an
# unknown-warning-option error under -Werror).
ifneq ($(CC_IS_CLANG),0)
    STRICT_ALIASING_FLAG = -Wstrict-aliasing
else
    STRICT_ALIASING_FLAG = -Wstrict-aliasing=3
endif

# Supported platforms have a fixed native artifact inspector. An unsupported
# release must supply both an audited format and an explicit acknowledgement;
# release-policy-check below also validates its complete minimum flag set.
UNSUPPORTED_RELEASE_ACK ?=
ifeq ($(UNAME_S),Linux)
    override RELEASE_ARTIFACT_FORMAT := elf
else ifeq ($(UNAME_S),FreeBSD)
    override RELEASE_ARTIFACT_FORMAT := elf
else ifeq ($(UNAME_S),Darwin)
    override RELEASE_ARTIFACT_FORMAT := macho
else
    RELEASE_ARTIFACT_FORMAT ?=
endif

CFLAGS = -std=gnu11 -Wall -Wextra -Wstrict-prototypes \
         -Wmissing-prototypes -Wold-style-definition -Wredundant-decls \
         -Wbad-function-cast -Wnested-externs -Winit-self \
         -Wshadow -Wwrite-strings -Wcast-align $(STRICT_ALIASING_FLAG) \
         -Wmissing-include-dirs -Wformat=2 -Winit-self \
         -Wswitch-default -Wunused -Werror-implicit-function-declaration \
         $(VERSION_FLAGS)

# Production frames above 128 KiB are a build-time regression: the supported
# CLI must run with a 256 KiB stack, leaving room for libc and nested helpers.
# Keep this on production translation units (tests intentionally construct
# several large fixtures on their own stacks).
FRAME_SIZE_WARNING = -Wframe-larger-than=131072

# Platform-specific flags
ifeq ($(UNAME_S),Linux)
    # Compiler-specific warnings. Clang does not implement -Wlogical-op.
    ifeq ($(CC_IS_CLANG),0)
        CFLAGS += -Wlogical-op
    endif
    CFLAGS += -Wdate-time
    # Linux-specific security flags. -fPIE/-pie are REQUESTED, not inherited:
    # relying on the host compiler's default-PIE meant non-mainstream
    # toolchains (vanilla upstream gcc, older cross compilers) shipped
    # ASLR-defeating non-PIE release binaries with all QA green (AR-05 L9).
    # distcheck now asserts the staged binary is ET_DYN with RELRO+NOW.
    SECURITY_CFLAGS_DEBUG = -fstack-protector-strong -fstack-clash-protection $(CF_PROTECTION)
    SECURITY_LDFLAGS_DEBUG = -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
    override SECURITY_CFLAGS_RELEASE := -D_FORTIFY_SOURCE=2 \
                             -fstack-protector-strong \
                             -fstack-clash-protection $(CF_PROTECTION) -fPIE
    override SECURITY_LDFLAGS_RELEASE := -pie -Wl,-z,relro -Wl,-z,now \
                             -Wl,-z,noexecstack
endif

ifeq ($(UNAME_S),Darwin)
    # macOS-specific security flags (no cf-protection, stack-clash-protection, or Linux linker flags)
    SECURITY_CFLAGS_DEBUG = -fstack-protector-strong
    override SECURITY_CFLAGS_RELEASE := -D_FORTIFY_SOURCE=2 \
                             -fstack-protector-strong -fPIE
    override SECURITY_LDFLAGS_RELEASE := -Wl,-pie
endif

ifeq ($(UNAME_S),FreeBSD)
    # Compiler-specific warnings (CI normally uses GCC from ports).
    ifeq ($(CC_IS_CLANG),0)
        CFLAGS += -Wlogical-op
    endif
    CFLAGS += -Wdate-time
    # FreeBSD security flags (ELF linker supports relro/now/noexecstack).
    # -fPIE/-pie requested explicitly — the ports gcc used in CI does not
    # default to PIE (AR-05 L9).
    SECURITY_CFLAGS_DEBUG = -fstack-protector-strong -fstack-clash-protection $(CF_PROTECTION)
    SECURITY_LDFLAGS_DEBUG = -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
    override SECURITY_CFLAGS_RELEASE := -D_FORTIFY_SOURCE=2 \
                             -fstack-protector-strong \
                             -fstack-clash-protection $(CF_PROTECTION) -fPIE
    override SECURITY_LDFLAGS_RELEASE := -pie -Wl,-z,relro -Wl,-z,now \
                             -Wl,-z,noexecstack
endif

# Debug/Release configurations
DEBUG_FLAGS = -g -O0 -DDEBUG -Wp,-U_FORTIFY_SOURCE -fsanitize=address -fsanitize=undefined \
              -fno-omit-frame-pointer -Wpedantic $(SECURITY_CFLAGS_DEBUG)
DEBUG_LDFLAGS = -fsanitize=address -fsanitize=undefined $(SECURITY_LDFLAGS_DEBUG)
# -s (strip) lives in RELEASE_LDFLAGS, not here: it is a link-only flag, and
# CFLAGS feeds the compile step too, where clang errors on it as an unused
# command-line argument under WERROR (gcc silently ignores it).
# This final, non-overridable release suffix applies to every production and
# test translation unit. The forced header makes a missing effective stack
# policy a compile error in that exact TU; the flag is deliberately last so a
# caller cannot neutralize it through CFLAGS or platform flag ordering.
# Unknown operating systems retain an explicit operator-supplied security
# policy, but the minimum is reasserted after that input so a later negation
# cannot satisfy a presence-only check while winning compiler/linker ordering.
override UNSUPPORTED_RELEASE_REQUIRED_CFLAGS :=
override UNSUPPORTED_RELEASE_REQUIRED_LDFLAGS :=
ifeq ($(filter $(UNAME_S),Linux Darwin FreeBSD),)
    override UNSUPPORTED_RELEASE_REQUIRED_CFLAGS := \
        -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
    ifeq ($(RELEASE_ARTIFACT_FORMAT),elf)
        override UNSUPPORTED_RELEASE_REQUIRED_LDFLAGS := \
            -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack
    else ifeq ($(RELEASE_ARTIFACT_FORMAT),macho)
        override UNSUPPORTED_RELEASE_REQUIRED_LDFLAGS := -Wl,-pie
    endif
endif
override RELEASE_REQUIRED_CFLAGS := \
                          $(UNSUPPORTED_RELEASE_REQUIRED_CFLAGS) \
                          -fstack-protector-strong \
                          -DGITSWITCH_REQUIRE_STRONG_SSP=1 \
                          -include $(SRCDIR)/release_hardening.h
override RELEASE_FLAGS := -O2 -DNDEBUG $(SECURITY_CFLAGS_RELEASE)
override RELEASE_LDFLAGS := -s $(SECURITY_LDFLAGS_RELEASE)
COVERAGE_FLAGS = -g -O0 --coverage -fprofile-abs-path
COVERAGE_LDFLAGS = --coverage

# The coverage lane is intentionally canonical and reproducible: GCC's gcov
# data is collected from a clean tree. gcovr publishes every human/machine
# report in one pass, then enforces the measured ratchet from that pass's JSON.
COVERAGE_CC ?= gcc
COVERAGE_GCOV ?= gcov
GCOVR ?= gcovr
COVERAGE_READLINE ?= 1
COVERAGE_REPORT_DIR ?= $(BUILDDIR)/coverage
# Baseline at 81afb4c with GCC/gcov 16.1.1 and gcovr 8.6: three clean
# full-capability runs were identical at 10,277/14,805 lines (69.4%) and
# 7,034/12,068 branches (58.3%). Whole-point floors leave a narrow allowance
# for supported-runner gcov reporting differences; ratchets only move upward
# after a new measured baseline, never downward to accommodate a regression.
COVERAGE_MIN_LINES ?= 69
COVERAGE_MIN_BRANCHES ?= 58

# Default to debug build
BUILD_TYPE ?= debug
ifeq ($(BUILD_TYPE),release)
    override RELEASE_ENFORCED_CFLAGS := $(RELEASE_FLAGS)
    override RELEASE_ENFORCED_LDFLAGS := $(RELEASE_LDFLAGS) \
                                         $(UNSUPPORTED_RELEASE_REQUIRED_LDFLAGS)
    override TU_HARDENING_FLAGS := $(RELEASE_REQUIRED_CFLAGS)
else ifeq ($(BUILD_TYPE),coverage)
    override RELEASE_ENFORCED_CFLAGS :=
    override RELEASE_ENFORCED_LDFLAGS :=
    override TU_HARDENING_FLAGS :=
    CFLAGS += $(COVERAGE_FLAGS)
    LDFLAGS += $(COVERAGE_LDFLAGS)
else
    override RELEASE_ENFORCED_CFLAGS :=
    override RELEASE_ENFORCED_LDFLAGS :=
    override TU_HARDENING_FLAGS :=
    CFLAGS += $(DEBUG_FLAGS)
    LDFLAGS += $(DEBUG_LDFLAGS)
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
# (CC_IS_CLANG is computed above, before the base CFLAGS.)
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

# Optional GNU readline: gives terminal-to-terminal add/edit prompts line
# editing and TAB path completion. Auto-detected; build still works without it
# (the prompt module uses its bounded byte-wise stdio reader). Override with
# READLINE=0 to force off.
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
                 $(SRCDIR)/publication.c $(SRCDIR)/accounts.c $(SRCDIR)/prompt.c

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
PUBLIC_API_PRODUCTION_OBJECT = $(OBJDIR)/test_public_api_production.o
PUBLIC_API_PRODUCTION_TARGET = $(BINDIR)/test_public_api_production
PUBLIC_API_COVERAGE_STAMP = $(OBJDIR)/.public-api-coverage
TEST_TARGETS += $(PUBLIC_API_PRODUCTION_TARGET)
CLI_E2E_TEST_TARGETS = \
	$(BINDIR)/test_ar04_cli \
	$(BINDIR)/test_ar04_lifecycle \
	$(BINDIR)/test_ar05_pty \
	$(BINDIR)/test_ar07_cli_commit \
	$(BINDIR)/test_ar07_completion \
	$(BINDIR)/test_ar07_shell_init \
	$(BINDIR)/test_cli \
	$(BINDIR)/test_pty
AR07_RESET_MAIN_OBJECT = $(OBJDIR)/main_ar07_reset.o
AR08_REMOVE_ACCOUNTS_OBJECT = $(OBJDIR)/accounts_ar08_remove.o
AR08_HINT_CONFIG_OBJECT = $(OBJDIR)/config_ar08_hint.o
AR08_COPY_UTILS_OBJECT = $(OBJDIR)/utils_ar08_copy.o
AR09_SECURITY_UTILS_OBJECT = $(OBJDIR)/utils_ar09_security.o
AR09_DISPATCH_SIGNALS_OBJECT = $(OBJDIR)/signals_ar09_dispatch.o
AR09_DISPATCH_TEST_OBJECT = $(OBJDIR)/test_signals_ar09_dispatch.o
DEPFILES = $(OBJECTS:.o=.d) $(TEST_OBJECTS:.o=.d) \
           $(AR07_RESET_MAIN_OBJECT:.o=.d) \
           $(AR08_REMOVE_ACCOUNTS_OBJECT:.o=.d) \
           $(AR08_HINT_CONFIG_OBJECT:.o=.d) \
           $(AR08_COPY_UTILS_OBJECT:.o=.d) \
           $(AR09_SECURITY_UTILS_OBJECT:.o=.d) \
           $(AR09_DISPATCH_SIGNALS_OBJECT:.o=.d) \
           $(AR09_DISPATCH_TEST_OBJECT:.o=.d) \
           $(PUBLIC_API_PRODUCTION_OBJECT:.o=.d)

# Let each translation unit describe its real header graph. -MP keeps a stale
# dependency file usable long enough to re-run the compiler after a header is
# removed/renamed, where the missing include is then reported authoritatively.
# CPPFLAGS is included explicitly so standard caller-provided preprocessor
# inputs participate in both compilation and the build fingerprint.
DEPFLAGS ?= -MMD -MP

# Default target
.PHONY: all
all: $(BINDIR)/$(TARGET)

# Create application build directories only under a root this checkout owns.
# The canonical project-local build directory is intrinsically ours for
# compatibility with older trees and with the fixed release-helper namespace.
# A redirected root is claimed only when this invocation atomically creates
# its final component; existing redirected directories require the exact
# private marker from an earlier invocation of this checkout.
.PHONY: prepare-build-root
prepare-build-root:
	@set -e; \
	umask 077; \
	build_root=$$GITSWITCH_BUILD_ROOT; \
	while test "$$build_root" != / && \
	      test "$${build_root%/}" != "$$build_root"; do \
		build_root=$${build_root%/}; \
	done; \
	case "$$build_root" in \
		''|/|.|..|../*|*/..|*'/../'*) \
			echo "ERROR: refusing unsafe application build root: $$build_root" >&2; \
			exit 1 ;; \
	esac; \
	project_root=`CDPATH='' cd . && pwd -P` || exit 1; \
	case "$$build_root" in \
		"$$project_root") \
			echo 'ERROR: application build root aliases the project root' >&2; \
			exit 1 ;; \
	esac; \
	case "$$build_root" in \
		/*) build_component_path=/; build_remaining=$${build_root#/} ;; \
		*) build_component_path=.; build_remaining=$$build_root ;; \
	esac; \
	while test -n "$$build_remaining"; do \
		case "$$build_remaining" in \
			*/*) build_component=$${build_remaining%%/*}; \
				build_remaining=$${build_remaining#*/} ;; \
			*) build_component=$$build_remaining; build_remaining= ;; \
		esac; \
		case "$$build_component" in ''|.) continue ;; esac; \
		if test "$$build_component_path" = /; then \
			build_component_path=/$$build_component; \
		else \
			build_component_path=$$build_component_path/$$build_component; \
		fi; \
		if test -n "$$build_remaining" && \
		   test -L "$$build_component_path"; then \
			echo "ERROR: application build root has a symlinked component: $$build_component_path" >&2; \
			exit 1; \
		fi; \
	done; \
	if test -L "$$build_root"; then \
		echo "ERROR: application build root is a symlink: $$build_root" >&2; \
		exit 1; \
	fi; \
	if test -e "$$build_root" && ! test -d "$$build_root"; then \
		echo "ERROR: application build root is not a directory: $$build_root" >&2; \
		exit 1; \
	fi; \
	created_root=0; \
	marker="$$build_root/$(BUILD_ROOT_MARKER_NAME)"; \
	marker_tmp=; \
	pending_build_root_signal=; \
	cleanup_build_root_claim() { \
		claim_status=$$1; \
		trap - 0 1 2 3 15; \
		if test -n "$$marker_tmp"; then \
			rm -f "$$marker_tmp" 2>/dev/null || :; \
		fi; \
		if test "$$created_root" -eq 1 && \
		   ! test -e "$$marker" && ! test -L "$$marker"; then \
			rmdir "$$build_root" 2>/dev/null || :; \
		fi; \
		exit "$$claim_status"; \
	}; \
	record_build_root_signal() { \
		pending_build_root_signal=$$1; \
	}; \
	abort_if_build_root_signalled() { \
		if test -n "$$pending_build_root_signal"; then \
			claim_signal_status=$$pending_build_root_signal; \
			pending_build_root_signal=; \
			cleanup_build_root_claim "$$claim_signal_status"; \
		fi; \
	}; \
	trap 'cleanup_build_root_claim $$?' 0; \
	trap 'record_build_root_signal 129' 1; \
	trap 'record_build_root_signal 130' 2; \
	trap 'record_build_root_signal 131' 3; \
	trap 'record_build_root_signal 143' 15; \
	if ! test -d "$$build_root"; then \
		case "$$build_root" in \
			*/*) build_parent=$${build_root%/*}; \
				test -n "$$build_parent" || build_parent=/ ;; \
			*) build_parent=. ;; \
		esac; \
		mkdir -p "$$build_parent" || exit 1; \
		abort_if_build_root_signalled; \
		if mkdir -m 0755 "$$build_root"; then \
			created_root=1; \
		else \
			abort_if_build_root_signalled; \
			echo "ERROR: cannot atomically claim application build root: $$build_root" >&2; \
			exit 1; \
		fi; \
	fi; \
	abort_if_build_root_signalled; \
	trap 'cleanup_build_root_claim 129' 1; \
	trap 'cleanup_build_root_claim 130' 2; \
	trap 'cleanup_build_root_claim 131' 3; \
	trap 'cleanup_build_root_claim 143' 15; \
	abort_if_build_root_signalled; \
	test -d "$$build_root" && test ! -L "$$build_root" || { \
		echo "ERROR: application build root changed during preparation: $$build_root" >&2; \
		exit 1; \
	}; \
	build_physical=`CDPATH='' cd "$$build_root" && pwd -P` || exit 1; \
	case "$$build_physical" in \
		/|"$$project_root") \
			echo "ERROR: unsafe physical application build root: $$build_physical" >&2; \
			exit 1 ;; \
	esac; \
	if test -e "$$marker" || test -L "$$marker"; then \
		test -f "$$marker" && test ! -L "$$marker" || { \
			echo "ERROR: application build-root marker is invalid: $$marker" >&2; \
			exit 1; \
		}; \
		marker_mode=`find "$$marker" -prune -type f -perm 0600 \
			-print 2>/dev/null`; \
		test "$$marker_mode" = "$$marker" && \
		{ \
			printf '%s\n' 'schema=gitswitch-build-root-v1'; \
			printf 'project=%s\n' "$$project_root"; \
			printf 'build=%s\n' "$$build_physical"; \
		} | cmp -s - "$$marker" || { \
			echo "ERROR: application build-root marker is invalid: $$marker" >&2; \
			exit 1; \
		}; \
	else \
		if test "$$created_root" -ne 1 && \
		   test "$$build_physical" != "$$project_root/build"; then \
			echo "ERROR: refusing unowned existing application build root: $$build_root" >&2; \
			exit 1; \
		fi; \
		marker_tmp="$$marker.tmp.$$$$"; \
		{ \
			printf '%s\n' 'schema=gitswitch-build-root-v1'; \
			printf 'project=%s\n' "$$project_root"; \
			printf 'build=%s\n' "$$build_physical"; \
		} >"$$marker_tmp"; \
		chmod 0600 "$$marker_tmp"; \
		mv -f "$$marker_tmp" "$$marker"; \
		marker_tmp=; \
	fi; \
	trap - 0 1 2 3 15

$(OBJDIR): | prepare-build-root
	@mkdir -p "$(OBJDIR)"

$(BINDIR): | prepare-build-root
	@mkdir -p "$(BINDIR)"

override DIST_PUBLISH_HELPER := build/tools/release-publish
override DIST_PUBLISH_NAMED_TEST_HELPER := build/tools/release-publish-named-test
override DIST_PUBLISH_PROVENANCE := build/tools/.release-publish.provenance
override DIST_PUBLISH_LOCK := .gitswitch-release-publish.lock
override DIST_PUBLISH_POLICY_VERSION := host-tool-v1
override DIST_PUBLISH_COMMON_FLAGS := -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror
override DIST_PUBLISH_PRODUCTION_DEFINES :=
# Exercise descriptor-bound publication from a named temp on every QA host;
# macOS CI exercises its exact fclonefileat implementation below this contract.
override DIST_PUBLISH_NAMED_DEFINES := \
	-DGITSWITCH_RELEASE_FORCE_NAMED_TEMP=1 \
	-DGITSWITCH_RELEASE_TEST_FD_PRESSURE=1 \
	-DGITSWITCH_RELEASE_TEST_ADOPTION_RACE=1 \
	-DGITSWITCH_RELEASE_TEST_PUBLICATION_RACE=1 \
	-DGITSWITCH_RELEASE_TEST_CLEANUP_RACE=1 \
	-DGITSWITCH_RELEASE_TEST_SIGNAL_DEFAULT=1 \
	-DGITSWITCH_RELEASE_TEST_DIGEST=1 \
	-DGITSWITCH_RELEASE_PRODUCER_TIMEOUT_MS=5000
override GITSWITCH_DIST_PUBLISH_POLICY_VERSION := $(DIST_PUBLISH_POLICY_VERSION)
override GITSWITCH_DIST_PUBLISH_COMMON_FLAGS := $(DIST_PUBLISH_COMMON_FLAGS)
override GITSWITCH_DIST_PUBLISH_PRODUCTION_DEFINES := $(DIST_PUBLISH_PRODUCTION_DEFINES)
override GITSWITCH_DIST_PUBLISH_NAMED_DEFINES := $(DIST_PUBLISH_NAMED_DEFINES)
export GITSWITCH_DIST_PUBLISH_POLICY_VERSION
export GITSWITCH_DIST_PUBLISH_COMMON_FLAGS
export GITSWITCH_DIST_PUBLISH_PRODUCTION_DEFINES
export GITSWITCH_DIST_PUBLISH_NAMED_DEFINES

# One controller owns both publisher profiles and one receipt. A root-local
# cooperative mutex stays outside every cleaned build tree, so independent
# Make processes cannot interleave generation, release use, or cleanup. The
# public target enters through the signal-forwarding lock supervisor; the
# private target refuses direct calls without the supervisor's unique token.
# It runs for every requested helper, independently of mtimes, and reuses the
# pair only
# when source/header bytes, HOSTCC identity, exact compile policy, and both
# current helper digests match the receipt. This closes the future-mtime and
# post-build replacement holes while preserving a true no-op incremental
# build. GNU Make's -B remains the CI real-build gate and deliberately bypasses
# reuse. All canonical files are published only after both private compiles
# succeed; a failure or interrupted rename leaves a detectable mismatch rather
# than blessing a partial generation.
.PHONY: release-publish-helpers _release-publish-helpers-locked
release-publish-helpers: tools/release_publish_lock.sh
	+@sh tools/release_publish_lock.sh "$(DIST_PUBLISH_LOCK)" \
		"$(MAKE_COMMAND)" --no-print-directory \
		_release-publish-helpers-locked

_release-publish-helpers-locked: tools/release_publish.c \
		src/freebsd_compat.h tools/release_publish_lock.sh
	@set -e; \
	umask 077; \
	lock_token=$${GITSWITCH_RELEASE_LOCK_TOKEN-}; \
	test -n "$$lock_token" && test -d "$$lock_token" && \
	test ! -L "$$lock_token" || { \
		echo 'ERROR: release-helper controller requires a live lock token' >&2; \
		exit 1; \
	}; \
	test -d "$(DIST_PUBLISH_LOCK)" && \
	test ! -L "$(DIST_PUBLISH_LOCK)" && \
	IFS= read -r lock_owner <"$(DIST_PUBLISH_LOCK)/owner" && \
	test "$$lock_owner" = "$$lock_token" || { \
		echo 'ERROR: release-helper controller does not own the shared lock' >&2; \
		exit 1; \
	}; \
	digest_file() { \
		digest_path=$$1; \
		digest_value=; \
		if command -v sha256sum >/dev/null 2>&1; then \
			digest_output=`sha256sum "$$digest_path"` || return 1; \
			digest_value=$${digest_output%% *}; \
		elif command -v shasum >/dev/null 2>&1; then \
			digest_output=`shasum -a 256 "$$digest_path"` || return 1; \
			digest_value=$${digest_output%% *}; \
		elif command -v sha256 >/dev/null 2>&1; then \
			digest_value=`sha256 -q "$$digest_path"` || return 1; \
		else \
			echo 'ERROR: SHA-256 tool required for release-helper provenance' >&2; \
			return 1; \
		fi; \
		case "$$digest_value" in \
			''|*[!0-9A-Fa-f]*) return 1 ;; \
		esac; \
		test "$${#digest_value}" -eq 64 || return 1; \
		printf '%s' "$$digest_value"; \
	}; \
	file_mode_matches() { \
		mode_path=$$1; \
		mode_value=$$2; \
		mode_match=`find "$$mode_path" -prune -type f \
			-perm "$$mode_value" -print 2>/dev/null` || return 1; \
		test "$$mode_match" = "$$mode_path"; \
	}; \
	root_physical=`CDPATH='' cd . && pwd -P` || { \
		echo 'ERROR: cannot resolve release-helper project root' >&2; \
		exit 1; \
	}; \
	host_os=`uname -s 2>/dev/null` || { \
		echo 'ERROR: cannot identify release-helper host platform' >&2; \
		exit 1; \
	}; \
	normalize_namespace_acl() { \
		namespace_acl_path=$$1; \
		case "$$host_os" in \
			Linux) : ;; \
			Darwin) \
				chmod -N "$$namespace_acl_path" || { \
					echo "ERROR: cannot clear release-helper ACL: $$namespace_acl_path" >&2; \
					return 1; \
				} ;; \
			FreeBSD) \
				namespace_acl_nfs4=`getconf ACL_NFS4 "$$namespace_acl_path" 2>/dev/null` || { \
					echo "ERROR: cannot query release-helper NFSv4 ACL support: $$namespace_acl_path" >&2; \
					return 1; \
				}; \
				namespace_acl_extended=`getconf ACL_EXTENDED "$$namespace_acl_path" 2>/dev/null` || { \
					echo "ERROR: cannot query release-helper POSIX ACL support: $$namespace_acl_path" >&2; \
					return 1; \
				}; \
				case "$$namespace_acl_nfs4:$$namespace_acl_extended" in \
					1:0|1:1) \
						setfacl -b "$$namespace_acl_path" || { \
							echo "ERROR: cannot clear release-helper NFSv4 ACL: $$namespace_acl_path" >&2; \
							return 1; \
						} ;; \
					0:1) \
						setfacl -b "$$namespace_acl_path" && \
						setfacl -k "$$namespace_acl_path" || { \
							echo "ERROR: cannot clear release-helper POSIX ACL: $$namespace_acl_path" >&2; \
							return 1; \
						} ;; \
					0:0) : ;; \
					*) \
						echo "ERROR: invalid release-helper ACL capability result: $$namespace_acl_path" >&2; \
						return 1 ;; \
				esac ;; \
			*) \
				echo "ERROR: unsupported release-helper ACL policy: $$host_os" >&2; \
				return 1 ;; \
		esac; \
	}; \
	for namespace_component in build "$(TOOLBUILDDIR)"; do \
		case "$$namespace_component" in \
			build) namespace_create_mode=0755 ;; \
			*) namespace_create_mode=0700 ;; \
		esac; \
		if test -L "$$namespace_component"; then \
			echo "ERROR: release-helper namespace is a symlink: $$namespace_component" >&2; \
			exit 1; \
		fi; \
		if test -e "$$namespace_component" && \
		   ! test -d "$$namespace_component"; then \
			echo "ERROR: release-helper namespace is not a directory: $$namespace_component" >&2; \
			exit 1; \
		fi; \
		test -d "$$namespace_component" || \
			mkdir -m "$$namespace_create_mode" "$$namespace_component" || { \
			echo "ERROR: cannot create release-helper namespace: $$namespace_component" >&2; \
			exit 1; \
		}; \
		test -d "$$namespace_component" && test ! -L "$$namespace_component" || { \
			echo "ERROR: release-helper namespace changed during creation: $$namespace_component" >&2; \
			exit 1; \
		}; \
		normalize_namespace_acl "$$namespace_component" || exit 1; \
		case "$$namespace_component" in \
			build) \
				chmod go-w "$$namespace_component" || { \
					echo 'ERROR: cannot make build namespace non-writable by peers' >&2; \
					exit 1; \
				} ;; \
			*) \
				chmod 0700 "$$namespace_component" || { \
					echo 'ERROR: cannot secure release-helper namespace' >&2; \
					exit 1; \
				} ;; \
		esac; \
	done; \
	tools_physical=`CDPATH='' cd "$(TOOLBUILDDIR)" && pwd -P` || { \
		echo 'ERROR: cannot resolve release-helper namespace' >&2; \
		exit 1; \
	}; \
	test "$$tools_physical" = "$$root_physical/$(TOOLBUILDDIR)" || { \
		echo 'ERROR: release-helper namespace resolves outside the project' >&2; \
		exit 1; \
	}; \
	tmpdir=`mktemp -d "$(TOOLBUILDDIR)/release-publish.tmp.XXXXXX"` || { \
		echo 'ERROR: cannot create private release-helper build directory' >&2; \
		exit 1; \
	}; \
	cleanup_host_tools() { \
		cleanup_status=$$1; \
		trap - 0 1 2 3 15; \
		rm -rf "$$tmpdir"; \
		exit "$$cleanup_status"; \
	}; \
	trap 'cleanup_host_tools $$?' 0; \
	trap 'cleanup_host_tools 129' 1; \
	trap 'cleanup_host_tools 130' 2; \
	trap 'cleanup_host_tools 131' 3; \
	trap 'cleanup_host_tools 143' 15; \
	test -n "$$GITSWITCH_HOSTCC_COMMAND" && \
	test -n "$$GITSWITCH_HOSTCC_LAUNCHER" && \
	test -n "$$GITSWITCH_HOSTCC_RESOLVED" && \
	test -n "$$GITSWITCH_HOSTCC_IDENTITY_FILES" && \
	test -n "$$GITSWITCH_HOSTCC_VERSION" || { \
		echo 'ERROR: complete HOSTCC command, path, version, and identity files are required' >&2; \
		exit 1; \
	}; \
	test -f "$$GITSWITCH_HOSTCC_RESOLVED" && \
	test -r "$$GITSWITCH_HOSTCC_RESOLVED" || { \
		echo 'ERROR: resolved HOSTCC launcher is not a readable regular file' >&2; \
		exit 1; \
	}; \
	hostcc_resolved_digest=`digest_file "$$GITSWITCH_HOSTCC_RESOLVED"` || { \
		echo 'ERROR: cannot fingerprint resolved HOSTCC launcher' >&2; exit 1; \
	}; \
	mkdir "$$tmpdir/tools" "$$tmpdir/src" || { \
		echo 'ERROR: cannot create private release-helper source tree' >&2; \
		exit 1; \
	}; \
	cp tools/release_publish.c "$$tmpdir/tools/release_publish.c" || { \
		echo 'ERROR: cannot snapshot release publisher source' >&2; exit 1; \
	}; \
	cp src/freebsd_compat.h "$$tmpdir/src/freebsd_compat.h" || { \
		echo 'ERROR: cannot snapshot release publisher compatibility header' >&2; \
		exit 1; \
	}; \
	chmod 0600 "$$tmpdir/tools/release_publish.c" \
		"$$tmpdir/src/freebsd_compat.h" || exit 1; \
	release_source_digest=`digest_file "$$tmpdir/tools/release_publish.c"` || { \
		echo 'ERROR: cannot fingerprint release publisher snapshot' >&2; exit 1; \
	}; \
	compat_header_digest=`digest_file "$$tmpdir/src/freebsd_compat.h"` || { \
		echo 'ERROR: cannot fingerprint release publisher header snapshot' >&2; \
		exit 1; \
	}; \
	identity_manifest="$$tmpdir/identity"; \
	: >"$$identity_manifest"; \
	identity_count=0; \
	for identity_file in $$GITSWITCH_HOSTCC_IDENTITY_FILES; do \
		test -f "$$identity_file" && test -r "$$identity_file" || { \
			echo "ERROR: HOSTCC identity file is not readable: $$identity_file" >&2; \
			exit 1; \
		}; \
		identity_digest=`digest_file "$$identity_file"` || { \
			echo "ERROR: cannot fingerprint HOSTCC identity file: $$identity_file" >&2; \
			exit 1; \
		}; \
		printf 'hostcc_identity=%s:%s\n' "$$identity_file" "$$identity_digest" \
			>>"$$identity_manifest"; \
		identity_count=$$((identity_count + 1)); \
	done; \
	test "$$identity_count" -gt 0 || { \
		echo 'ERROR: HOSTCC identity-file list is incomplete' >&2; exit 1; \
	}; \
	verify_host_inputs() { \
		current_source_digest=`digest_file tools/release_publish.c` || return 1; \
		current_header_digest=`digest_file src/freebsd_compat.h` || return 1; \
		current_resolved_digest=`digest_file "$$GITSWITCH_HOSTCC_RESOLVED"` || \
			return 1; \
		current_hostcc_version=`$(HOSTCC) --version 2>/dev/null | sed -n '1p'`; \
		test "$$current_source_digest" = "$$release_source_digest" || return 1; \
		test "$$current_header_digest" = "$$compat_header_digest" || return 1; \
		test "$$current_resolved_digest" = "$$hostcc_resolved_digest" || \
			return 1; \
		test "$$current_hostcc_version" = "$$GITSWITCH_HOSTCC_VERSION" || \
			return 1; \
		current_identity_manifest="$$tmpdir/identity.current"; \
		: >"$$current_identity_manifest"; \
		current_identity_count=0; \
		for current_identity_file in $$GITSWITCH_HOSTCC_IDENTITY_FILES; do \
			test -f "$$current_identity_file" && \
			test -r "$$current_identity_file" || return 1; \
			current_identity_digest=`digest_file "$$current_identity_file"` || \
				return 1; \
			printf 'hostcc_identity=%s:%s\n' "$$current_identity_file" \
				"$$current_identity_digest" >>"$$current_identity_manifest"; \
			current_identity_count=$$((current_identity_count + 1)); \
		done; \
		test "$$current_identity_count" = "$$identity_count" || return 1; \
		cmp -s "$$current_identity_manifest" "$$identity_manifest"; \
	}; \
	verify_host_inputs || { \
		echo 'ERROR: release-helper inputs changed while being snapshotted' >&2; \
		exit 1; \
	}; \
	printf '%s' "$$GITSWITCH_HOSTCC_COMMAND" >"$$tmpdir/hostcc-command"; \
	printf '%s' "$$GITSWITCH_HOSTCC_VERSION" >"$$tmpdir/hostcc-version"; \
	printf '%s' "$$GITSWITCH_DIST_PUBLISH_COMMON_FLAGS" >"$$tmpdir/common-flags"; \
	printf '%s' "$$GITSWITCH_DIST_PUBLISH_PRODUCTION_DEFINES" >"$$tmpdir/production-defines"; \
	printf '%s' "$$GITSWITCH_DIST_PUBLISH_NAMED_DEFINES" >"$$tmpdir/named-defines"; \
	hostcc_command_digest=`digest_file "$$tmpdir/hostcc-command"` || exit 1; \
	hostcc_version_digest=`digest_file "$$tmpdir/hostcc-version"` || exit 1; \
	common_flags_digest=`digest_file "$$tmpdir/common-flags"` || exit 1; \
	production_defines_digest=`digest_file "$$tmpdir/production-defines"` || exit 1; \
	named_defines_digest=`digest_file "$$tmpdir/named-defines"` || exit 1; \
	expected="$$tmpdir/expected"; \
	{ \
		printf 'schema=%s\n' "$$GITSWITCH_DIST_PUBLISH_POLICY_VERSION"; \
		printf 'source_release_publish_sha256=%s\n' "$$release_source_digest"; \
		printf 'source_freebsd_compat_sha256=%s\n' "$$compat_header_digest"; \
		printf 'hostcc_command_sha256=%s\n' "$$hostcc_command_digest"; \
		printf 'hostcc_launcher=%s\n' "$$GITSWITCH_HOSTCC_LAUNCHER"; \
		printf 'hostcc_resolved=%s\n' "$$GITSWITCH_HOSTCC_RESOLVED"; \
		printf 'hostcc_resolved_sha256=%s\n' "$$hostcc_resolved_digest"; \
		printf 'hostcc_version_sha256=%s\n' "$$hostcc_version_digest"; \
		cat "$$identity_manifest"; \
		printf 'common_flags_sha256=%s\n' "$$common_flags_digest"; \
		printf 'production_defines_sha256=%s\n' "$$production_defines_digest"; \
		printf 'named_defines_sha256=%s\n' "$$named_defines_digest"; \
	} >"$$expected"; \
	force_rebuild=$(if $(findstring B,$(firstword $(MAKEFLAGS))),1,0); \
	if test "$$force_rebuild" -eq 0 && \
	   file_mode_matches "$(DIST_PUBLISH_HELPER)" 0755 && \
	   test -x "$(DIST_PUBLISH_HELPER)" && \
	   file_mode_matches "$(DIST_PUBLISH_NAMED_TEST_HELPER)" 0755 && \
	   test -x "$(DIST_PUBLISH_NAMED_TEST_HELPER)" && \
	   file_mode_matches "$(DIST_PUBLISH_PROVENANCE)" 0644; then \
		production_digest=`digest_file "$(DIST_PUBLISH_HELPER)"` || production_digest=; \
		named_digest=`digest_file "$(DIST_PUBLISH_NAMED_TEST_HELPER)"` || named_digest=; \
		if test -n "$$production_digest" && test -n "$$named_digest"; then \
			{ \
				cat "$$expected"; \
				printf 'production_helper_sha256=%s\n' "$$production_digest"; \
				printf 'named_helper_sha256=%s\n' "$$named_digest"; \
			} >"$$tmpdir/current"; \
			if cmp -s "$$tmpdir/current" "$(DIST_PUBLISH_PROVENANCE)" && \
			   verify_host_inputs; then \
				exit 0; \
			fi; \
		fi; \
	fi; \
	production_tmp="$$tmpdir/release-publish"; \
	named_tmp="$$tmpdir/release-publish-named-test"; \
	echo "Building descriptor-pinned release publisher..."; \
	$(HOSTCC) $(DIST_PUBLISH_COMMON_FLAGS) $(DIST_PUBLISH_PRODUCTION_DEFINES) \
		"$$tmpdir/tools/release_publish.c" -o "$$production_tmp"; \
	echo "Building named-temp release publisher fixture..."; \
	$(HOSTCC) $(DIST_PUBLISH_COMMON_FLAGS) $(DIST_PUBLISH_NAMED_DEFINES) \
		"$$tmpdir/tools/release_publish.c" -o "$$named_tmp"; \
	chmod 0755 "$$production_tmp" "$$named_tmp"; \
	production_digest=`digest_file "$$production_tmp"` || exit 1; \
	named_digest=`digest_file "$$named_tmp"` || exit 1; \
	new_receipt="$$tmpdir/provenance"; \
	{ \
		cat "$$expected"; \
		printf 'production_helper_sha256=%s\n' "$$production_digest"; \
		printf 'named_helper_sha256=%s\n' "$$named_digest"; \
	} >"$$new_receipt"; \
	chmod 0644 "$$new_receipt"; \
	verify_host_inputs || { \
		echo 'ERROR: release-helper inputs changed during compilation' >&2; \
		exit 1; \
	}; \
	mv -f "$$production_tmp" "$(DIST_PUBLISH_HELPER)"; \
	mv -f "$$named_tmp" "$(DIST_PUBLISH_NAMED_TEST_HELPER)"; \
	mv -f "$$new_receipt" "$(DIST_PUBLISH_PROVENANCE)"; \
	file_mode_matches "$(DIST_PUBLISH_HELPER)" 0755 && \
	test -x "$(DIST_PUBLISH_HELPER)" && \
	file_mode_matches "$(DIST_PUBLISH_NAMED_TEST_HELPER)" 0755 && \
	test -x "$(DIST_PUBLISH_NAMED_TEST_HELPER)" && \
	file_mode_matches "$(DIST_PUBLISH_PROVENANCE)" 0644 || { \
		echo 'ERROR: release-helper publication produced an invalid file shape' >&2; \
		exit 1; \
	}; \
	verify_host_inputs || { \
		echo 'ERROR: release-helper inputs changed during publication' >&2; \
		exit 1; \
	}; \
	published_production_digest=`digest_file "$(DIST_PUBLISH_HELPER)"` || exit 1; \
	published_named_digest=`digest_file "$(DIST_PUBLISH_NAMED_TEST_HELPER)"` || exit 1; \
	{ \
		cat "$$expected"; \
		printf 'production_helper_sha256=%s\n' "$$published_production_digest"; \
		printf 'named_helper_sha256=%s\n' "$$published_named_digest"; \
	} >"$$tmpdir/published"; \
	cmp -s "$$tmpdir/published" "$(DIST_PUBLISH_PROVENANCE)" || { \
		echo 'ERROR: release-helper provenance changed during publication' >&2; \
		exit 1; \
	}; \
	file_mode_matches "$(DIST_PUBLISH_HELPER)" 0755 && \
	test -x "$(DIST_PUBLISH_HELPER)" && \
	file_mode_matches "$(DIST_PUBLISH_NAMED_TEST_HELPER)" 0755 && \
	test -x "$(DIST_PUBLISH_NAMED_TEST_HELPER)" && \
	file_mode_matches "$(DIST_PUBLISH_PROVENANCE)" 0644 || { \
		echo 'ERROR: release-helper metadata changed during finalization' >&2; \
		exit 1; \
	}; \
	verify_host_inputs || { \
		echo 'ERROR: release-helper inputs changed during finalization' >&2; \
		exit 1; \
	}

$(DIST_PUBLISH_HELPER) $(DIST_PUBLISH_NAMED_TEST_HELPER): | release-publish-helpers
	@mode_match=`find "$@" -prune -type f -perm 0755 -print 2>/dev/null`; \
	test "$$mode_match" = "$@" && test -x "$@" || { \
		echo "ERROR: verified release helper is unavailable: $@" >&2; \
		exit 1; \
	}

# The CI symbol consumer shares the same cross-process critical section as
# helper generation. Keeping both operations in one supervised invocation
# prevents a concurrent clean/rebuild from replacing the exact helper between
# provenance validation and inspection.
.PHONY: release-symbol-contract-test _release-symbol-contract-test-locked
release-symbol-contract-test: tools/release_publish_lock.sh
	+@sh tools/release_publish_lock.sh "$(DIST_PUBLISH_LOCK)" \
		"$(MAKE_COMMAND)" --no-print-directory \
		_release-symbol-contract-test-locked

_release-symbol-contract-test-locked: _release-publish-helpers-locked \
		tests/test_ci_symbols.sh
	@/bin/sh tests/test_ci_symbols.sh "$(BINDIR)/$(TARGET)" \
		"$(DIST_PUBLISH_HELPER)"

# Build-config stamp: objects/tests share build/obj and build/bin across every
# configuration. Record every effective compile/link input, not just the build
# type and metadata: otherwise READLINE, compiler, flag, library, or platform
# changes can reuse incompatible objects and make tests falsely green (AR-07
# M34). The first line retains BUILD_TYPE before `|` for the install guard.
#
# A make-exported value reaches the shell as data rather than recipe syntax,
# so command-line flags containing quotes/metacharacters cannot alter this
# recipe. The temporary file is compared byte-for-byte and the real stamp is
# replaced only on change, preserving true no-op incremental builds.
BUILDTYPE_STAMP = $(OBJDIR)/.buildconfig
define BUILD_STAMP_CONTENT
$(BUILD_TYPE)|buildconfig-v3
version=$(VERSION)
commit=$(COMMIT)
cc=$(CC)
cc_launcher=$(CC_LAUNCHER)
cc_resolved=$(CC_IDENTITY_FILE)
cc_identity_files=$(TOOLCHAIN_IDENTITY_FILES)
cc_file_fingerprint=$(TOOLCHAIN_FILE_FINGERPRINT)
cc_version=$(CC_VERSION_ID)
cc_is_clang=$(CC_IS_CLANG)
target_triple=$(TARGET_TRIPLE)
target_triple_detected=$(TARGET_TRIPLE_DETECTED)
target_arch=$(TARGET_ARCH)
cppflags=$(CPPFLAGS)
cflags=$(CFLAGS)
release_enforced_cflags=$(RELEASE_ENFORCED_CFLAGS)
release_required_cflags=$(RELEASE_REQUIRED_CFLAGS)
frame_size_warning=$(FRAME_SIZE_WARNING)
includes=$(INCLUDES)
depflags=$(DEPFLAGS)
ldflags=$(LDFLAGS)
release_enforced_ldflags=$(RELEASE_ENFORCED_LDFLAGS)
unsupported_required_cflags=$(UNSUPPORTED_RELEASE_REQUIRED_CFLAGS)
unsupported_required_ldflags=$(UNSUPPORTED_RELEASE_REQUIRED_LDFLAGS)
libs=$(LIBS)
readline_request=$(READLINE)
readline_effective=$(READLINE_OK)
readline_hint_cflags=$(READLINE_HINT_CFLAGS)
readline_hint_libs=$(READLINE_HINT_LIBS)
platform_os=$(UNAME_S)
platform_arch=$(UNAME_M)
release_artifact_format=$(RELEASE_ARTIFACT_FORMAT)
unsupported_release_ack=$(UNSUPPORTED_RELEASE_ACK)
cf_protection=$(CF_PROTECTION)
security_cflags_debug=$(SECURITY_CFLAGS_DEBUG)
security_ldflags_debug=$(SECURITY_LDFLAGS_DEBUG)
security_cflags_release=$(SECURITY_CFLAGS_RELEASE)
security_ldflags_release=$(SECURITY_LDFLAGS_RELEASE)
target=$(TARGET)
sources=$(SOURCES)
objects=$(OBJECTS)
source_dir=$(SRCDIR)
test_dir=$(TESTDIR)
endef
override GITSWITCH_BUILD_CONFIG = $(BUILD_STAMP_CONTENT)
override GITSWITCH_RELEASE_POLICY_OS := $(UNAME_S)
override GITSWITCH_RELEASE_POLICY_TRIPLE := $(TARGET_TRIPLE)
override GITSWITCH_RELEASE_POLICY_DETECTED_TRIPLE := $(TARGET_TRIPLE_DETECTED)
override GITSWITCH_RELEASE_POLICY_CC := $(CC_IDENTITY_FILE)
override GITSWITCH_RELEASE_POLICY_CC_VERSION := $(CC_VERSION_ID)
override GITSWITCH_RELEASE_POLICY_FINGERPRINT := $(TOOLCHAIN_FILE_FINGERPRINT)
override GITSWITCH_RELEASE_POLICY_ACK := $(UNSUPPORTED_RELEASE_ACK)
override GITSWITCH_RELEASE_POLICY_FORMAT := $(RELEASE_ARTIFACT_FORMAT)
override GITSWITCH_RELEASE_POLICY_CFLAGS := $(SECURITY_CFLAGS_RELEASE)
override GITSWITCH_RELEASE_POLICY_LDFLAGS := $(SECURITY_LDFLAGS_RELEASE)
override GITSWITCH_RELEASE_EFFECTIVE_CFLAGS := $(CFLAGS) \
	$(RELEASE_ENFORCED_CFLAGS) $(TU_HARDENING_FLAGS)
override GITSWITCH_RELEASE_EFFECTIVE_LDFLAGS := $(LDFLAGS) $(LIBS) \
	$(RELEASE_ENFORCED_LDFLAGS)
export GITSWITCH_BUILD_CONFIG
export GITSWITCH_RELEASE_POLICY_OS
export GITSWITCH_RELEASE_POLICY_TRIPLE
export GITSWITCH_RELEASE_POLICY_DETECTED_TRIPLE
export GITSWITCH_RELEASE_POLICY_CC
export GITSWITCH_RELEASE_POLICY_CC_VERSION
export GITSWITCH_RELEASE_POLICY_FINGERPRINT
export GITSWITCH_RELEASE_POLICY_ACK
export GITSWITCH_RELEASE_POLICY_FORMAT
export GITSWITCH_RELEASE_POLICY_CFLAGS
export GITSWITCH_RELEASE_POLICY_LDFLAGS
export GITSWITCH_RELEASE_EFFECTIVE_CFLAGS
export GITSWITCH_RELEASE_EFFECTIVE_LDFLAGS

.PHONY: release-policy-check
release-policy-check:
	@set -e; \
	printf '%s\n' "$$GITSWITCH_RELEASE_POLICY_TRIPLE" | \
		grep -Eq '^[A-Za-z0-9_.+]+(-[A-Za-z0-9_.+]+)+$$' || { \
		echo 'ERROR: compiler target triple is empty or invalid' >&2; exit 1; \
	}; \
	test "$$GITSWITCH_RELEASE_POLICY_TRIPLE" = \
	     "$$GITSWITCH_RELEASE_POLICY_DETECTED_TRIPLE" || { \
		echo 'ERROR: claimed release target differs from compiler target' >&2; exit 1; \
	}; \
	test -f "$$GITSWITCH_RELEASE_POLICY_CC" && \
	test -n "$$GITSWITCH_RELEASE_POLICY_CC_VERSION" || { \
		echo 'ERROR: compiler path and version are required' >&2; exit 1; \
	}; \
	case "$$GITSWITCH_RELEASE_POLICY_FINGERPRINT" in \
		''|$(TOOLCHAIN_FINGERPRINT_FAILURE)) \
			echo 'ERROR: complete compiler content fingerprint is required' >&2; exit 1 ;; \
		*) ;; \
	esac; \
	case "$$GITSWITCH_RELEASE_POLICY_OS" in \
		Linux|FreeBSD) \
			test "$$GITSWITCH_RELEASE_POLICY_FORMAT" = elf || { \
				echo 'ERROR: ELF platform lost its release inspection policy' >&2; exit 1; \
			} ;; \
		Darwin) \
			test "$$GITSWITCH_RELEASE_POLICY_FORMAT" = macho || { \
				echo 'ERROR: Darwin lost its release inspection policy' >&2; exit 1; \
			} ;; \
		*) \
			test "$$GITSWITCH_RELEASE_POLICY_ACK" = I_ACKNOWLEDGE_UNSUPPORTED_RELEASE || { \
				echo "ERROR: unsupported release OS '$$GITSWITCH_RELEASE_POLICY_OS' requires explicit acknowledgement" >&2; exit 1; \
			}; \
			case "$$GITSWITCH_RELEASE_POLICY_FORMAT" in elf|macho) ;; \
				*) echo 'ERROR: unsupported release requires elf or macho inspection policy' >&2; exit 1 ;; \
			esac; \
			for required in -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE; do \
				case " $$GITSWITCH_RELEASE_POLICY_CFLAGS " in *" $$required "*) ;; \
					*) echo "ERROR: unsupported release C flags omit $$required" >&2; exit 1 ;; \
				esac; \
			done; \
			for forbidden in -U_FORTIFY_SOURCE -fno-stack-protector \
				-fno-stack-protector-all -fno-stack-protector-strong \
				-fno-pie -fno-PIE; do \
				case " $$GITSWITCH_RELEASE_POLICY_CFLAGS " in *" $$forbidden "*) \
					echo "ERROR: unsupported release C flags conflict with $$forbidden" >&2; exit 1 ;; \
				esac; \
			done; \
			if test "$$GITSWITCH_RELEASE_POLICY_FORMAT" = elf; then \
				for required in -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack; do \
					case " $$GITSWITCH_RELEASE_POLICY_LDFLAGS " in *" $$required "*) ;; \
						*) echo "ERROR: unsupported ELF release linker flags omit $$required" >&2; exit 1 ;; \
					esac; \
				done; \
				for forbidden in -no-pie -nopie -Wl,-no-pie -Wl,-z,norelro \
					-Wl,-z,lazy -Wl,-z,execstack; do \
					case " $$GITSWITCH_RELEASE_POLICY_LDFLAGS " in *" $$forbidden "*) \
						echo "ERROR: unsupported ELF linker flags conflict with $$forbidden" >&2; exit 1 ;; \
					esac; \
				done; \
			fi ;; \
	esac; \
	for required in -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE; do \
		case " $$GITSWITCH_RELEASE_EFFECTIVE_CFLAGS " in *" $$required "*) ;; \
			*) echo "ERROR: effective release C flags omit $$required" >&2; exit 1 ;; \
		esac; \
	done; \
	case "$$GITSWITCH_RELEASE_POLICY_FORMAT" in \
		elf) for required in -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack; do \
			case " $$GITSWITCH_RELEASE_EFFECTIVE_LDFLAGS " in *" $$required "*) ;; \
				*) echo "ERROR: effective ELF release linker flags omit $$required" >&2; exit 1 ;; \
			esac; \
		done ;; \
		macho) case " $$GITSWITCH_RELEASE_EFFECTIVE_LDFLAGS " in \
			*' -Wl,-pie '*) ;; \
			*) echo 'ERROR: effective Mach-O release linker flags omit PIE' >&2; exit 1 ;; \
		esac ;; \
	esac

ifeq ($(BUILD_TYPE),release)
$(BUILDTYPE_STAMP): release-policy-check
endif
$(BUILDTYPE_STAMP): buildtype-force | $(OBJDIR)
	@set -e; \
	tmp="$@.tmp.$$$$"; \
	trap 'rm -f "$$tmp"' 0 1 2 3 15; \
	printf '%s\n' "$$GITSWITCH_BUILD_CONFIG" >"$$tmp"; \
	if test -r "$@" && cmp -s "$$tmp" "$@"; then \
		rm -f "$$tmp"; \
	else \
		mv -f "$$tmp" "$@"; \
	fi; \
	trap - 0 1 2 3 15

.PHONY: buildtype-force
buildtype-force:

# Compile source files
$(OBJDIR)/%.o: $(SRCDIR)/%.c $(BUILDTYPE_STAMP) | $(OBJDIR)
	@echo "Compiling $<..."
	$(CC) $(CPPFLAGS) $(CFLAGS) $(FRAME_SIZE_WARNING) $(INCLUDES) $(DEPFLAGS) \
		$(RELEASE_ENFORCED_CFLAGS) $(TU_HARDENING_FLAGS) -c $< -o $@

# Link main executable
$(BINDIR)/$(TARGET): $(OBJECTS) | $(BINDIR)
	@echo "Linking $@..."
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ $(LIBS) \
		$(RELEASE_ENFORCED_LDFLAGS)
	@echo "Build complete: $@"

# Install target.
#
# install does NOT depend on $(BINDIR)/$(TARGET): making it a build trigger
# meant `make install` with no BUILD_TYPE (the default, 'debug') flipped the
# .buildtype stamp and rebuilt the WHOLE tree as a debug/ASan binary, then
# installed THAT — even right after `make release`. That silently shipped an
# unhardened, ASan-linked binary from `sudo make install`, the RPM %install
# step, and every downstream packager (AR-06 F01). install now packages
# exactly the binary already built, and refuses to run if none exists, so the
# caller must build explicitly first (`make release` / `make`). BUILD_TYPE is
# irrelevant here — no rebuild happens.
.PHONY: install
ifeq ($(BUILD_TYPE),release)
install: release-policy-check
endif
install:
	@if [ ! -x "$(BINDIR)/$(TARGET)" ]; then \
		echo "Error: $(BINDIR)/$(TARGET) not built. Run 'make release' (or 'make') first." >&2; \
		exit 1; \
	fi
	@bt=`sed -n '1s/|.*//p' $(BUILDTYPE_STAMP) 2>/dev/null`; \
	if [ "$$bt" != "release" ]; then \
		echo "Warning: installing a '$$bt' build (not 'release'); run 'make release' for a hardened, non-ASan binary." >&2; \
	else \
		built_os=`sed -n 's/^platform_os=//p' $(BUILDTYPE_STAMP)`; \
		case "$$built_os" in Linux|Darwin|FreeBSD) ;; \
			*) built_ack=`sed -n 's/^unsupported_release_ack=//p' $(BUILDTYPE_STAMP)`; \
			   built_format=`sed -n 's/^release_artifact_format=//p' $(BUILDTYPE_STAMP)`; \
			   test "$$built_ack" = I_ACKNOWLEDGE_UNSUPPORTED_RELEASE && \
			   { test "$$built_format" = elf || test "$$built_format" = macho; } || { \
				echo 'ERROR: refusing release install without a recorded supported/acknowledged inspection policy' >&2; exit 1; \
			   } ;; \
			esac; \
		built_format=`sed -n 's/^release_artifact_format=//p' $(BUILDTYPE_STAMP)`; \
		built_triple=`sed -n 's/^target_triple=//p' $(BUILDTYPE_STAMP)`; \
		GITSWITCH_RELEASE_FORMAT="$$built_format" \
			sh tests/test_ar07_release.sh artifact \
			"$(BINDIR)/$(TARGET)" "$(BINDIR)/$(TARGET)" "$$built_triple" || { \
			echo 'ERROR: refusing to install an unverified release artifact' >&2; exit 1; \
		}; \
	fi
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
# AR-10 L15: test objects see the GITSWITCH_TESTING declarations (the suites
# link the testing signals object below); production objects never do.
$(PUBLIC_API_COVERAGE_STAMP): $(TESTDIR)/test_public_api.c \
		$(TESTDIR)/test_public_api_coverage.sh $(HEADERS) \
		$(BUILDTYPE_STAMP) | $(OBJDIR)
	@PUBLIC_API_CC="$(CC)" sh $(TESTDIR)/test_public_api_coverage.sh "$(CURDIR)"
	@touch $@

$(OBJDIR)/test_public_api.o: $(PUBLIC_API_COVERAGE_STAMP)

$(OBJDIR)/test_%.o: $(TESTDIR)/test_%.c $(BUILDTYPE_STAMP) | $(OBJDIR)
	@echo "Compiling test $<..."
	$(CC) $(CPPFLAGS) $(CFLAGS) $(INCLUDES) -I$(TESTDIR) $(DEPFLAGS) \
		-DGITSWITCH_TESTING \
		$(RELEASE_ENFORCED_CFLAGS) $(TU_HARDENING_FLAGS) -c $< -o $@

# Compile the same exhaustive registry without GITSWITCH_TESTING so an API
# accidentally available only to test objects cannot satisfy the production
# link contract (AR-11 L4).
$(PUBLIC_API_PRODUCTION_OBJECT): $(TESTDIR)/test_public_api.c \
		$(PUBLIC_API_COVERAGE_STAMP) $(BUILDTYPE_STAMP) | $(OBJDIR)
	@echo "Compiling production public API profile..."
	$(CC) $(CPPFLAGS) $(CFLAGS) $(INCLUDES) -I$(TESTDIR) $(DEPFLAGS) \
		$(RELEASE_ENFORCED_CFLAGS) $(TU_HARDENING_FLAGS) -c $< -o $@

# The reset suite calls the real CLI entry point in isolated child processes
# while installing deterministic in-process boundary hooks. Rename only this
# test object's main; the production binary remains free of those hooks.
$(AR07_RESET_MAIN_OBJECT): $(SRCDIR)/main.c $(BUILDTYPE_STAMP) | $(OBJDIR)
	@echo "Compiling AR-07 reset CLI test entry..."
	$(CC) $(CPPFLAGS) $(CFLAGS) $(FRAME_SIZE_WARNING) $(INCLUDES) $(DEPFLAGS) \
		-DGITSWITCH_TESTING -Dmain=gitswitch_cli_main \
		$(RELEASE_ENFORCED_CFLAGS) $(TU_HARDENING_FLAGS) -c $< -o $@

# The removal signal suite needs checkpoints inside accounts_remove(), while
# production accounts.o remains free of test hooks.
$(AR08_REMOVE_ACCOUNTS_OBJECT): $(SRCDIR)/accounts.c $(BUILDTYPE_STAMP) | $(OBJDIR)
	@echo "Compiling AR-08 removal signal test object..."
	$(CC) $(CPPFLAGS) $(CFLAGS) $(FRAME_SIZE_WARNING) $(INCLUDES) $(DEPFLAGS) \
		-DGITSWITCH_TESTING $(RELEASE_ENFORCED_CFLAGS) \
		$(TU_HARDENING_FLAGS) -c $< -o $@

# The resume-hint race suite replaces the artifact at exact parser boundaries.
# Keep its hook out of the production config object and binary.
$(AR08_HINT_CONFIG_OBJECT): $(SRCDIR)/config.c $(BUILDTYPE_STAMP) | $(OBJDIR)
	@echo "Compiling AR-08 resume-hint race test object..."
	$(CC) $(CPPFLAGS) $(CFLAGS) $(FRAME_SIZE_WARNING) $(INCLUDES) $(DEPFLAGS) \
		-DGITSWITCH_TESTING $(RELEASE_ENFORCED_CFLAGS) \
		$(TU_HARDENING_FLAGS) -c $< -o $@

# The copy/read, runner, and terminal-echo suites use deterministic descriptor,
# sigaction, and tcsetattr checkpoints; production utils.o contains none of
# those test-only hooks.
$(AR08_COPY_UTILS_OBJECT): $(SRCDIR)/utils.c $(BUILDTYPE_STAMP) | $(OBJDIR)
	@echo "Compiling AR-08 copy permission test object..."
	$(CC) $(CPPFLAGS) $(CFLAGS) $(FRAME_SIZE_WARNING) $(INCLUDES) $(DEPFLAGS) \
		-DGITSWITCH_TESTING $(RELEASE_ENFORCED_CFLAGS) \
		$(TU_HARDENING_FLAGS) -c $< -o $@

# The runtime-lock classification suite injects synthetic ownership and ACL
# facts so lifetime mutability is deterministic on every supported host.
$(AR09_SECURITY_UTILS_OBJECT): $(SRCDIR)/utils.c $(BUILDTYPE_STAMP) | $(OBJDIR)
	@echo "Compiling AR-09 runtime classification test object..."
	$(CC) $(CPPFLAGS) $(CFLAGS) $(FRAME_SIZE_WARNING) $(INCLUDES) $(DEPFLAGS) \
		-DGITSWITCH_TESTING $(RELEASE_ENFORCED_CFLAGS) \
		$(TU_HARDENING_FLAGS) -c $< -o $@

# Deferred-dispatch failure injection is test-build-only. Compile both sides
# of that private API into dedicated objects so the production binary and
# installed signals header surface contain no active fault state.
$(AR09_DISPATCH_SIGNALS_OBJECT): $(SRCDIR)/signals.c $(BUILDTYPE_STAMP) | $(OBJDIR)
	@echo "Compiling AR-09 signal dispatch test object..."
	$(CC) $(CPPFLAGS) $(CFLAGS) $(FRAME_SIZE_WARNING) $(INCLUDES) $(DEPFLAGS) \
		-DGITSWITCH_TESTING $(RELEASE_ENFORCED_CFLAGS) \
		$(TU_HARDENING_FLAGS) -c $< -o $@

$(AR09_DISPATCH_TEST_OBJECT): $(TESTDIR)/test_signals.c $(BUILDTYPE_STAMP) | $(OBJDIR)
	@echo "Compiling AR-09 signal dispatch test suite..."
	$(CC) $(CPPFLAGS) $(CFLAGS) $(INCLUDES) -I$(TESTDIR) $(DEPFLAGS) \
		-DGITSWITCH_TESTING $(RELEASE_ENFORCED_CFLAGS) \
		$(TU_HARDENING_FLAGS) -c $< -o $@

# Test executables (exclude main.o to avoid multiple main functions)
# AR-10 L15: suites link the GITSWITCH_TESTING signals object — the sigaction
# fault / guard-end sabotage seams no longer exist in the production object.
# AR-11 M13-M15: keep the real-Git exact-retirement transaction suite visible
# as an explicit focused target while retaining the common test link profile.
$(BINDIR)/test_ar11_retirement_atomic: \
		$(OBJDIR)/test_ar11_retirement_atomic.o

$(BINDIR)/test_%: $(OBJDIR)/test_%.o $(AR09_DISPATCH_SIGNALS_OBJECT) \
		$(filter-out $(OBJDIR)/main.o $(OBJDIR)/signals.o,$(OBJECTS)) | $(BINDIR)
	@echo "Linking test $@..."
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS) $(RELEASE_ENFORCED_LDFLAGS)

$(PUBLIC_API_PRODUCTION_TARGET): $(PUBLIC_API_PRODUCTION_OBJECT) \
		$(filter-out $(OBJDIR)/main.o,$(OBJECTS)) | $(BINDIR)
	@echo "Linking production public API profile..."
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS) $(RELEASE_ENFORCED_LDFLAGS)

# The lifecycle suite drives one remove through the real CLI entry with a
# one-shot post-runtime persistence fault; the production executable remains
# free of the renamed testing entry point.
$(BINDIR)/test_ar04_lifecycle: $(OBJDIR)/test_ar04_lifecycle.o \
		$(AR07_RESET_MAIN_OBJECT) \
		$(AR09_DISPATCH_SIGNALS_OBJECT) \
		$(filter-out $(OBJDIR)/main.o $(OBJDIR)/signals.o,$(OBJECTS)) | $(BINDIR)
	@echo "Linking test $@..."
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS) $(RELEASE_ENFORCED_LDFLAGS)

$(BINDIR)/test_ar07_reset: $(OBJDIR)/test_ar07_reset.o \
		$(AR07_RESET_MAIN_OBJECT) \
		$(AR09_DISPATCH_SIGNALS_OBJECT) \
		$(filter-out $(OBJDIR)/main.o $(OBJDIR)/signals.o,$(OBJECTS)) | $(BINDIR)
	@echo "Linking test $@..."
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS) $(RELEASE_ENFORCED_LDFLAGS)

# AR-11 M17 drives remove, targeted reset, and all-account reset through the
# real CLI entry while injecting only the existing private Git-retirement
# checkpoints. The production entry point remains unchanged.
$(BINDIR)/test_ar11_retirement_outcome: \
		$(OBJDIR)/test_ar11_retirement_outcome.o \
		$(AR07_RESET_MAIN_OBJECT) \
		$(AR09_DISPATCH_SIGNALS_OBJECT) \
		$(filter-out $(OBJDIR)/main.o $(OBJDIR)/signals.o,$(OBJECTS)) | $(BINDIR)
	@echo "Linking test $@..."
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS) $(RELEASE_ENFORCED_LDFLAGS)

# AR-11 M18 drives post-retirement config/state failures through the real CLI
# entry and proves the outer transaction's restore-or-block-resume contract.
$(BINDIR)/test_ar11_retirement_outer: \
		$(OBJDIR)/test_ar11_retirement_outer.o \
		$(AR07_RESET_MAIN_OBJECT) \
		$(AR09_DISPATCH_SIGNALS_OBJECT) \
		$(filter-out $(OBJDIR)/main.o $(OBJDIR)/signals.o,$(OBJECTS)) | $(BINDIR)
	@echo "Linking test $@..."
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS) $(RELEASE_ENFORCED_LDFLAGS)

# AR-11 M4 drives two consecutive invocations of the real CLI entry in one
# process so a retained abort-only context cannot hide behind process exit.
$(BINDIR)/test_ar11_cli_owner: $(OBJDIR)/test_ar11_cli_owner.o \
		$(AR07_RESET_MAIN_OBJECT) \
		$(AR09_DISPATCH_SIGNALS_OBJECT) \
		$(filter-out $(OBJDIR)/main.o $(OBJDIR)/signals.o,$(OBJECTS)) | $(BINDIR)
	@echo "Linking test $@..."
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS) $(RELEASE_ENFORCED_LDFLAGS)

$(BINDIR)/test_ar08_remove_signal: $(OBJDIR)/test_ar08_remove_signal.o \
		$(AR07_RESET_MAIN_OBJECT) \
		$(AR08_REMOVE_ACCOUNTS_OBJECT) \
		$(filter-out $(OBJDIR)/main.o $(OBJDIR)/accounts.o,$(OBJECTS)) | $(BINDIR)
	@echo "Linking test $@..."
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS) $(RELEASE_ENFORCED_LDFLAGS)

$(BINDIR)/test_ar08_resume_hint_race: \
		$(OBJDIR)/test_ar08_resume_hint_race.o \
		$(AR08_HINT_CONFIG_OBJECT) \
		$(filter-out $(OBJDIR)/main.o $(OBJDIR)/config.o,$(OBJECTS)) | $(BINDIR)
	@echo "Linking test $@..."
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS) $(RELEASE_ENFORCED_LDFLAGS)

# Deterministic retirement-guard namespace races use the same private config
# checkpoint object. Broad config suites continue to link production config.o.
$(BINDIR)/test_ar11_guard_clear: \
		$(OBJDIR)/test_ar11_guard_clear.o \
		$(AR08_HINT_CONFIG_OBJECT) \
		$(filter-out $(OBJDIR)/main.o $(OBJDIR)/config.o,$(OBJECTS)) | $(BINDIR)
	@echo "Linking test $@..."
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS) $(RELEASE_ENFORCED_LDFLAGS)

$(BINDIR)/test_ar08_copy_permissions: \
		$(OBJDIR)/test_ar08_copy_permissions.o \
		$(AR08_COPY_UTILS_OBJECT) \
		$(filter-out $(OBJDIR)/main.o $(OBJDIR)/utils.o,$(OBJECTS)) | $(BINDIR)
	@echo "Linking test $@..."
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS) $(RELEASE_ENFORCED_LDFLAGS)

$(BINDIR)/test_ar08_echo: \
		$(OBJDIR)/test_ar08_echo.o \
		$(AR08_COPY_UTILS_OBJECT) \
		$(filter-out $(OBJDIR)/main.o $(OBJDIR)/utils.o,$(OBJECTS)) | $(BINDIR)
	@echo "Linking test $@..."
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS) $(RELEASE_ENFORCED_LDFLAGS)

$(BINDIR)/test_ar07_runner: \
		$(OBJDIR)/test_ar07_runner.o \
		$(AR08_COPY_UTILS_OBJECT) \
		$(filter-out $(OBJDIR)/main.o $(OBJDIR)/utils.o,$(OBJECTS)) | $(BINDIR)
	@echo "Linking test $@..."
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS) $(RELEASE_ENFORCED_LDFLAGS)

# AR-11 trusted-exec fault seams are compiled only into these causal test
# profiles; the production utils object and installed binary retain no fault
# state or injection symbols.
$(BINDIR)/test_ar07_exec_trust: \
		$(OBJDIR)/test_ar07_exec_trust.o \
		$(AR08_COPY_UTILS_OBJECT) \
		$(AR09_DISPATCH_SIGNALS_OBJECT) \
		$(filter-out $(OBJDIR)/main.o $(OBJDIR)/utils.o $(OBJDIR)/signals.o,$(OBJECTS)) | $(BINDIR)
	@echo "Linking test $@..."
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS) $(RELEASE_ENFORCED_LDFLAGS)

$(BINDIR)/test_ar11_gpg_program: \
		$(OBJDIR)/test_ar11_gpg_program.o \
		$(AR08_COPY_UTILS_OBJECT) \
		$(AR09_DISPATCH_SIGNALS_OBJECT) \
		$(filter-out $(OBJDIR)/main.o $(OBJDIR)/utils.o $(OBJDIR)/signals.o,$(OBJECTS)) | $(BINDIR)
	@echo "Linking test $@..."
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS) $(RELEASE_ENFORCED_LDFLAGS)

$(BINDIR)/test_public_api: \
		$(OBJDIR)/test_public_api.o \
		$(AR08_COPY_UTILS_OBJECT) \
		$(AR09_DISPATCH_SIGNALS_OBJECT) \
		$(filter-out $(OBJDIR)/main.o $(OBJDIR)/utils.o $(OBJDIR)/signals.o,$(OBJECTS)) | $(BINDIR)
	@echo "Linking test $@..."
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS) $(RELEASE_ENFORCED_LDFLAGS)

$(BINDIR)/test_security: \
		$(OBJDIR)/test_security.o \
		$(AR09_SECURITY_UTILS_OBJECT) \
		$(filter-out $(OBJDIR)/main.o $(OBJDIR)/utils.o,$(OBJECTS)) | $(BINDIR)
	@echo "Linking test $@..."
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS) $(RELEASE_ENFORCED_LDFLAGS)

$(BINDIR)/test_signals: \
		$(AR09_DISPATCH_TEST_OBJECT) \
		$(AR09_DISPATCH_SIGNALS_OBJECT) \
		$(filter-out $(OBJDIR)/main.o $(OBJDIR)/signals.o,$(OBJECTS)) | $(BINDIR)
	@echo "Linking test $@..."
	$(CC) $(LDFLAGS) $^ -o $@ $(LIBS) $(RELEASE_ENFORCED_LDFLAGS)

# These suites execute the worktree production CLI instead of a linked test
# entry point. Keep the dependency explicit for focused invocations: the
# aggregate `make test` prerequisite must not be the only thing preventing a
# stale or missing selected-build CLI from being exercised (AR-08 M47).
$(CLI_E2E_TEST_TARGETS): | $(BINDIR)/$(TARGET)

# Dependency files are optional on the first build and authoritative
# thereafter. Keep this after `all` so an included -MP compatibility target
# can never become Make's accidental default goal.
-include $(DEPFILES)

# Build and run tests. The main binary is a dependency because the CLI-level
# tests exec the selected-build CLI: main.c is excluded from the test link (it
# defines main), so its command handlers are only reachable end-to-end through
# the binary itself. Override any inherited GITSWITCH_BIN so an alternate
# BUILDDIR can never test a stale CLI from another build.
.PHONY: test
ifeq ($(strip $(TEST_SOURCES)),)
test:
	@echo "ERROR: no C tests discovered under $(TESTDIR)/ (expected test_*.c)" >&2
	@exit 1
else
test: $(BINDIR)/$(TARGET) $(TEST_TARGETS)
	@echo "Running tests..."
	@GITSWITCH_BIN="$(abspath $(BINDIR)/$(TARGET))"; \
	export GITSWITCH_BIN; \
	GITSWITCH_SOURCE_ROOT="$(CURDIR)"; \
	export GITSWITCH_SOURCE_ROOT; \
	for test in $(TEST_TARGETS); do \
		echo "Running $$test..."; \
		"$$test" || exit 1; \
	done
	@echo "All tests passed!"
endif

# ShellCheck is intentionally a separate, fail-closed QA gate instead of an
# ordinary `make test` prerequisite: builds remain package-independent while
# CI and release reviewers can require every dialect parser explicitly.
.PHONY: shell-static-test ci-policy-test public-api-coverage-test
shell-static-test:
	@sh tests/test_shell_assets.sh "$(CURDIR)"

ci-policy-test:
	@sh tests/test_ci_policy.sh "$(CURDIR)"

public-api-coverage-test:
	@PUBLIC_API_CC="$(CC)" sh $(TESTDIR)/test_public_api_coverage.sh "$(CURDIR)"

# The small contract fixture proves both threshold metrics are wired to gcovr's
# documented nonzero exit bits; a no-op or report-only replacement cannot make
# the real coverage lane falsely green.
.PHONY: coverage-contract-test
coverage-contract-test:
	@COVERAGE_CC="$(COVERAGE_CC)" COVERAGE_GCOV="$(COVERAGE_GCOV)" \
		GCOVR="$(GCOVR)" sh tests/test_coverage.sh

.PHONY: coverage
coverage: coverage-contract-test
	@$(MAKE) clean
	@$(MAKE) CC="$(COVERAGE_CC)" BUILD_TYPE=coverage \
		READLINE="$(COVERAGE_READLINE)" WERROR=1 test
	@mkdir -p "$(COVERAGE_REPORT_DIR)"
	@$(GCOVR) --root "$(CURDIR)" \
		--gcov-executable "$(COVERAGE_GCOV)" \
		--filter "$(SRCDIR)/" \
		--txt="$(COVERAGE_REPORT_DIR)/coverage.txt" --print-summary \
		--html-details="$(COVERAGE_REPORT_DIR)/index.html" \
		--xml="$(COVERAGE_REPORT_DIR)/coverage.xml" --xml-pretty \
		--json="$(COVERAGE_REPORT_DIR)/coverage.json" --json-pretty \
		--json-summary="$(COVERAGE_REPORT_DIR)/coverage-summary.json" \
		--json-summary-pretty \
		"$(OBJDIR)"
	@$(GCOVR) --root "$(CURDIR)" \
		--json-add-tracefile "$(COVERAGE_REPORT_DIR)/coverage.json" \
		--txt="$(COVERAGE_REPORT_DIR)/threshold.txt" \
		--fail-under-line "$(COVERAGE_MIN_LINES)" \
		--fail-under-branch "$(COVERAGE_MIN_BRANCHES)"

# Static analysis
.PHONY: analyze
analyze:
	@echo "Running static analysis..."
	@if command -v cppcheck >/dev/null 2>&1; then \
		cppcheck --enable=warning,performance,portability \
			--error-exitcode=1 --std=c11 \
			--suppress=missingIncludeSystem $(SRCDIR) tools; \
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
# fixed or explicitly annotated. AR-10 L27: tools/ (the release publisher)
# ships in the pipeline's trust boundary and is scanned under the same gate.
.PHONY: security-scan
security-scan:
	@echo "Running security scan..."
	@if command -v flawfinder >/dev/null 2>&1; then \
		flawfinder --error-level=4 $(SRCDIR) tools; \
	else \
		echo "flawfinder not installed - skipping security scan"; \
	fi

# Memory check (requires Valgrind and a clean BUILD_TYPE=release build). ASan
# instrumentation and Valgrind must not be combined in the same binary.
# AR-06 F36: the memcheck lane used to cover only test_runner + test_security
# (2 of 21 suites). Broaden it to the deterministic, non-forking logic suites
# (parser, config, validation, git_ops fake-runner, gpg colon parsing, and
# display formatting/capture) so release-path allocation/free bugs across the
# core are actually exercised under Valgrind. The fork/timing-heavy end-to-end
# suites (cli, pty, ssh_reuse,
# gpg_switch/reset, ar04/ar05 e2e) are deliberately excluded: Valgrind traces
# into forked children and real ssh-agent/gpg subprocesses, making them slow and
# flaky in CI. ASan/UBSan (the debug `test` lane) covers those paths.
MEMCHECK_TARGETS = $(BINDIR)/test_runner $(BINDIR)/test_security \
	$(BINDIR)/test_toml $(BINDIR)/test_validation \
	$(BINDIR)/test_config_security $(BINDIR)/test_git_ops \
	$(BINDIR)/test_gpg_parse $(BINDIR)/test_ar05_unit \
	$(BINDIR)/test_display

.PHONY: memcheck
ifeq ($(BUILD_TYPE),release)
memcheck: $(BINDIR)/$(TARGET) $(MEMCHECK_TARGETS)
	@echo "Running memory check..."
	@set -e; \
	if command -v valgrind >/dev/null 2>&1; then \
		for target in $(MEMCHECK_TARGETS) "$(BINDIR)/$(TARGET) --help"; do \
			echo "Valgrind: $$target"; \
			log="valgrind-$$(echo "$$target" | tr -c 'A-Za-z0-9._-' '_').log"; \
			if ! valgrind --tool=memcheck --leak-check=full \
				--show-leak-kinds=all --track-origins=yes \
				--error-exitcode=99 --log-file="$$log" $$target; then \
				echo "=== Valgrind reported errors for: $$target ==="; \
				cat "$$log"; \
				exit 99; \
			fi; \
		done; \
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
override GITSWITCH_CLEAN_BUILDDIR := $(BUILDDIR)
export GITSWITCH_CLEAN_BUILDDIR
.PHONY: clean _clean-release-locked
clean: tools/release_publish_lock.sh
	+@sh tools/release_publish_lock.sh "$(DIST_PUBLISH_LOCK)" \
		"$(MAKE_COMMAND)" --no-print-directory _clean-release-locked

_clean-release-locked:
	@lock_token=$${GITSWITCH_RELEASE_LOCK_TOKEN-}; \
	test -n "$$lock_token" && test -d "$$lock_token" && \
	test ! -L "$$lock_token" && \
	test -d "$(DIST_PUBLISH_LOCK)" && \
	test ! -L "$(DIST_PUBLISH_LOCK)" && \
	IFS= read -r lock_owner <"$(DIST_PUBLISH_LOCK)/owner" && \
	test "$$lock_owner" = "$$lock_token" || { \
		echo 'ERROR: clean requires ownership of the release-publisher lock' >&2; \
		exit 1; \
	}
	@echo "Cleaning build files..."
	@set -e; \
	clean_path=$$GITSWITCH_CLEAN_BUILDDIR; \
	while test "$$clean_path" != / && \
	      test "$${clean_path%/}" != "$$clean_path"; do \
		clean_path=$${clean_path%/}; \
	done; \
	case "$$clean_path" in \
		''|/|.|..) \
			echo "ERROR: refusing unsafe BUILDDIR cleanup: $$clean_path" >&2; \
			exit 1 ;; \
	esac; \
	clean_project=`CDPATH='' cd . && pwd -P` || exit 1; \
	case "$$clean_path" in \
		"$$clean_project") \
			echo 'ERROR: refusing to clean the project root' >&2; exit 1 ;; \
		"$$clean_project"/*) \
			clean_path=.$${clean_path#"$$clean_project"} ;; \
		/*) clean_component_path=/ ;; \
		*) clean_component_path=. ;; \
	esac; \
	case "$$clean_path" in \
		/*) clean_remaining=$${clean_path#/} ;; \
		*) clean_remaining=$$clean_path ;; \
	esac; \
	case "$$clean_path" in \
		/*) : ;; \
		*) clean_component_path=. ;; \
	esac; \
	if test -z "$${clean_component_path-}"; then \
		clean_component_path=.; \
	fi; \
	while test -n "$$clean_remaining"; do \
		case "$$clean_remaining" in \
			*/*) \
				clean_component=$${clean_remaining%%/*}; \
				clean_remaining=$${clean_remaining#*/} ;; \
			*) clean_component=$$clean_remaining; clean_remaining= ;; \
		esac; \
		case "$$clean_component" in \
			''|.) continue ;; \
			..) \
				echo 'ERROR: refusing BUILDDIR cleanup containing ..' >&2; \
				exit 1 ;; \
		esac; \
		if test "$$clean_component_path" = /; then \
			clean_component_path=/$$clean_component; \
		else \
			clean_component_path=$$clean_component_path/$$clean_component; \
		fi; \
		if test -n "$$clean_remaining" && \
		   test -L "$$clean_component_path"; then \
			echo "ERROR: refusing BUILDDIR with symlinked component: $$clean_component_path" >&2; \
			exit 1; \
		fi; \
	done; \
	case "$$clean_component_path" in \
		/|.) echo 'ERROR: refusing unsafe resolved BUILDDIR cleanup' >&2; exit 1 ;; \
	esac; \
	case "$$clean_component_path" in \
		./build) clean_is_canonical=1 ;; \
		*) clean_is_canonical=0 ;; \
	esac; \
	if test -L "$$clean_component_path"; then \
		test "$$clean_is_canonical" -eq 1 || { \
			echo "ERROR: refusing unowned redirected BUILDDIR symlink: $$clean_component_path" >&2; \
			exit 1; \
		}; \
		rm -f "$$clean_component_path"; \
	elif test -d "$$clean_component_path"; then \
		clean_physical=`CDPATH='' cd "$$clean_component_path" && pwd -P` || exit 1; \
		case "$$clean_physical" in \
			/|"$$clean_project") \
				echo "ERROR: refusing unsafe physical BUILDDIR cleanup: $$clean_physical" >&2; \
				exit 1 ;; \
		esac; \
		if test "$$clean_is_canonical" -ne 1; then \
			clean_marker="$$clean_component_path/$(BUILD_ROOT_MARKER_NAME)"; \
			test -f "$$clean_marker" && test ! -L "$$clean_marker" || { \
				echo "ERROR: refusing unowned redirected BUILDDIR cleanup: $$clean_component_path" >&2; \
				exit 1; \
			}; \
			clean_marker_mode=`find "$$clean_marker" -prune -type f \
				-perm 0600 -print 2>/dev/null`; \
			test "$$clean_marker_mode" = "$$clean_marker" && \
			{ \
				printf '%s\n' 'schema=gitswitch-build-root-v1'; \
				printf 'project=%s\n' "$$clean_project"; \
				printf 'build=%s\n' "$$clean_physical"; \
			} | cmp -s - "$$clean_marker" || { \
				echo "ERROR: refusing unowned redirected BUILDDIR cleanup: $$clean_component_path" >&2; \
				exit 1; \
			}; \
		fi; \
		rm -rf "$$clean_component_path"; \
	elif test -e "$$clean_component_path"; then \
		test "$$clean_is_canonical" -eq 1 || { \
			echo "ERROR: refusing unowned redirected BUILDDIR file: $$clean_component_path" >&2; \
			exit 1; \
		}; \
		rm -f "$$clean_component_path"; \
	fi
	@set -e; \
	if test -L build; then \
		rm -f build; \
	elif test -d build; then \
		if test -L "$(TOOLBUILDDIR)"; then \
			rm -f "$(TOOLBUILDDIR)"; \
		elif test -d "$(TOOLBUILDDIR)"; then \
			rm -rf "$(TOOLBUILDDIR)"; \
		elif test -e "$(TOOLBUILDDIR)"; then \
			rm -f "$(TOOLBUILDDIR)"; \
		fi; \
	elif test -e build; then \
		rm -f build; \
	fi
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
	@echo "Compiler identity: $(CC_IDENTITY_FILE)"
	@echo "Compiler version: $(CC_VERSION_ID)"
	@echo "Target triple: $(TARGET_TRIPLE)"
	@echo "Toolchain fingerprint: $(TOOLCHAIN_FILE_FINGERPRINT)"
	@echo "CFLAGS: $(CFLAGS) $(RELEASE_ENFORCED_CFLAGS) $(TU_HARDENING_FLAGS)"
	@echo "LDFLAGS: $(LDFLAGS) $(RELEASE_ENFORCED_LDFLAGS)"
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
	@echo "  shell-static-test Lint and native-parse shipped shell assets"
	@echo "  ci-policy-test Verify immutable, least-privilege CI policy"
	@echo "  coverage     Run tests and enforce the GCC/gcovr coverage ratchet"
	@echo "  coverage-contract-test Verify gcovr threshold failure plumbing"
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
	@echo "  release-contract-test Verify commit-pinned release inputs"
	@echo "  release-artifact-test Inspect built and staged release hardening"
	@echo "  qa-contract-test Verify QA failure and cleanup contracts"
	@echo "  rpm          Build RPM package"
	@echo "  help         Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  BUILD_TYPE   debug (default), release, or coverage"
	@echo "  CC           Compiler (default: gcc)"
	@echo "  TARGET_TRIPLE Validated compiler target (default: CC -dumpmachine)"
	@echo "  TOOLCHAIN_IDENTITY_FILES Compiler/wrapper files to fingerprint"
	@echo "  UNSUPPORTED_RELEASE_ACK/RELEASE_ARTIFACT_FORMAT Audited release override"
	@echo "  COVERAGE_MIN_LINES/COVERAGE_MIN_BRANCHES Coverage floors (69/58)"
	@echo "  DESTDIR      Installation prefix"

# RPM package building
override PACKAGE := gitswitcher
# Release artifacts are named and populated from one immutable commit. Regular
# developer builds may still override VERSION, but dist/RPM metadata may not be
# mixed with that live value. Command-line overrides are deliberately ignored
# for RELEASE_COMMIT/RELEASE_VERSION/DIST_ROOT so the archive contract cannot
# be renamed away from the VERSION committed at HEAD. Resolve these only for a
# goal that consumes release metadata; ordinary builds otherwise paid for two
# unrelated Git processes on every Make invocation (AR-07 L25).
RELEASE_METADATA_GOALS = release-manifest-check dist distcheck \
	release-contract-test _dist-release-locked \
	_release-contract-test-locked rpm
ifneq ($(strip $(filter $(RELEASE_METADATA_GOALS),$(MAKECMDGOALS))),)
    override RELEASE_COMMIT := $(shell git rev-parse --verify HEAD^{commit} 2>/dev/null)
    override RELEASE_VERSION := $(shell git show $(RELEASE_COMMIT):VERSION 2>/dev/null)
else
    override RELEASE_COMMIT :=
    override RELEASE_VERSION :=
endif
RPM_VERSION = $(RELEASE_VERSION)
override DIST_ROOT := $(PACKAGE)-$(RELEASE_VERSION)
# Release output has one dedicated, ignored namespace. DIST_ARCHIVE remains a
# compatibility/request variable, but the dist recipe accepts only this exact
# path (relative or physical absolute spelling); it is never interpolated as
# shell syntax. Consumers use the fixed canonical path below.
override DIST_ARTIFACT_DIR := build/dist
override DIST_ARCHIVE_NAME := $(DIST_ROOT).tar.gz
override DIST_ARCHIVE_PATH := $(CURDIR)/$(DIST_ARTIFACT_DIR)/$(DIST_ARCHIVE_NAME)
DIST_ARCHIVE ?= $(DIST_ARTIFACT_DIR)/$(DIST_ARCHIVE_NAME)
override GITSWITCH_DIST_ARCHIVE_REQUEST := $(DIST_ARCHIVE)
override GITSWITCH_DIST_ARCHIVE_PATH := $(DIST_ARCHIVE_PATH)
override GITSWITCH_DIST_ARCHIVE_NAME := $(DIST_ARCHIVE_NAME)
override GITSWITCH_DIST_ROOT := $(DIST_ROOT)
export GITSWITCH_DIST_ARCHIVE_REQUEST
export GITSWITCH_DIST_ARCHIVE_PATH
export GITSWITCH_DIST_ARCHIVE_NAME
export GITSWITCH_DIST_ROOT
# Reviewed allowlist. Copying only these entries inherently excludes VCS/OMX
# state, build products, cores, logs, and previously generated archives.
override DIST_MANIFEST := src tests tools completions VERSION LICENSE README.md Makefile $(PACKAGE).spec

.PHONY: release-manifest-check dist _dist-release-locked distcheck \
	release-contract-test _release-contract-test-locked \
	freebsd-platform-contract-test release-artifact-test qa-contract-test \
	sig-repro-test rpm
# Fail closed before producing an artifact when any tracked or untracked
# release-manifest path differs from the exact commit selected above. Besides
# preventing a live VERSION from naming committed payload, this makes the spec
# consumed by `rpm` review-identical to the spec shipped in the archive.
release-manifest-check:
	@git rev-parse --git-dir >/dev/null 2>&1 || \
		{ echo "ERROR: release artifacts require a git checkout" >&2; exit 1; }
	@test -n "$(RELEASE_COMMIT)" && test -n "$(RELEASE_VERSION)" || \
		{ echo "ERROR: cannot resolve committed release VERSION at HEAD" >&2; exit 1; }
	@if ! git diff --quiet --no-ext-diff "$(RELEASE_COMMIT)" -- $(DIST_MANIFEST); then \
		echo "ERROR: release manifest differs from committed HEAD" >&2; \
		git status --short --untracked-files=all -- $(DIST_MANIFEST) >&2; \
		exit 1; \
	fi
	@if test -n "`git ls-files --others --exclude-standard -- $(DIST_MANIFEST)`"; then \
		echo "ERROR: release manifest contains untracked paths" >&2; \
		git status --short --untracked-files=all -- $(DIST_MANIFEST) >&2; \
		exit 1; \
	fi
	@spec_version=`git show "$(RELEASE_COMMIT):$(PACKAGE).spec" | \
		sed -n 's/^Version:[[:space:]]*//p' | sed -n '1p'`; \
	if test "$$spec_version" != "$(RELEASE_VERSION)"; then \
		echo "ERROR: committed spec Version '$$spec_version' differs from VERSION '$(RELEASE_VERSION)'" >&2; \
		exit 1; \
	fi

# Archive COMMITTED VCS content, not the live working tree: the old cp -R of
# the manifest directories shipped any stray file nested inside src/, tests/,
# or completions/ (editor backups, experiment files, test-run droppings), so
# release tarballs were not reproducible from a tag and could leak unreviewed
# content (AR-05 L5). git archive draws from HEAD, which also inherently
# excludes VCS state, build products, cores, logs, and prior archives.
dist: tools/release_publish_lock.sh
	+@sh tools/release_publish_lock.sh "$(DIST_PUBLISH_LOCK)" \
		"$(MAKE_COMMAND)" --no-print-directory _dist-release-locked

_dist-release-locked: release-manifest-check \
		_release-publish-helpers-locked
	@set -e; \
	root_physical=`CDPATH='' cd "$(CURDIR)" && pwd -P`; \
	request="$$GITSWITCH_DIST_ARCHIVE_REQUEST"; \
	expected_rel="$(DIST_ARTIFACT_DIR)/$$GITSWITCH_DIST_ARCHIVE_NAME"; \
	expected_abs="$$root_physical/$$expected_rel"; \
	case "$(RELEASE_VERSION)" in \
		''|*[!A-Za-z0-9._+-]*) \
			echo 'ERROR: committed release VERSION is not path-safe' >&2; exit 1 ;; \
	esac; \
	case "$$request" in \
		"$$expected_rel"|"$$expected_abs") ;; \
		*) echo "ERROR: DIST_ARCHIVE must be exactly $$expected_rel" >&2; exit 1 ;; \
	esac; \
	if git ls-files --error-unmatch -- "$$expected_rel" >/dev/null 2>&1; then \
		echo 'ERROR: distribution output aliases a tracked path' >&2; exit 1; \
	fi; \
	if ! git check-ignore -q -- "$$expected_rel"; then \
		echo 'ERROR: distribution output directory is not ignored' >&2; exit 1; \
	fi; \
	for component in build "$(DIST_ARTIFACT_DIR)"; do \
		if test -L "$$component"; then \
			echo "ERROR: distribution directory is a symlink: $$component" >&2; exit 1; \
		fi; \
		if test -e "$$component" && ! test -d "$$component"; then \
			echo "ERROR: distribution directory is not a directory: $$component" >&2; exit 1; \
		fi; \
		test -d "$$component" || mkdir "$$component"; \
	done; \
	cd "$(DIST_ARTIFACT_DIR)"; \
	actual_dir=`pwd -P`; \
	if test "$$actual_dir" != "$$root_physical/$(DIST_ARTIFACT_DIR)"; then \
		echo 'ERROR: distribution directory resolved outside its dedicated namespace' >&2; exit 1; \
	fi; \
	if test -e "$$GITSWITCH_DIST_ARCHIVE_NAME" || \
	   test -L "$$GITSWITCH_DIST_ARCHIVE_NAME"; then \
		echo 'ERROR: distribution archive already exists; refusing to replace it' >&2; exit 1; \
	fi; \
	echo "Creating distribution tarball: $$expected_rel"; \
	"$$root_physical/$(DIST_PUBLISH_HELPER)" . "$$actual_dir" \
		"$$GITSWITCH_DIST_ARCHIVE_NAME" -- \
		git -C "$$root_physical" archive --format=tar.gz \
		--prefix="$$GITSWITCH_DIST_ROOT/" \
		"$(RELEASE_COMMIT)" -- $(DIST_MANIFEST)

distcheck: dist
	@sh tests/test_dist.sh "$$GITSWITCH_DIST_ARCHIVE_PATH" \
		"$$GITSWITCH_DIST_ROOT" \
		"$(PREFIX)" "$(MAKE_COMMAND)"

# Keep the declared FreeBSD floor tied to both its required headers and the
# exact hosted release that executes publication/reset behavior.
freebsd-platform-contract-test:
	@FREEBSD_CONTRACT_CC="$(CC)" \
		sh tests/test_ar11_freebsd_floor.sh "$(CURDIR)"

# Negative release-input checks run in isolated local clones, so they can dirty
# VERSION/spec/manifest fixtures without touching the operator's checkout.
release-contract-test: tools/release_publish_lock.sh
	+@sh tools/release_publish_lock.sh "$(DIST_PUBLISH_LOCK)" \
		"$(MAKE_COMMAND)" --no-print-directory \
		_release-contract-test-locked

_release-contract-test-locked: freebsd-platform-contract-test \
		_release-publish-helpers-locked
	@sh tests/test_ar07_release.sh manifest "$(CURDIR)" "$(MAKE_COMMAND)" \
		"$(CURDIR)/$(DIST_PUBLISH_NAMED_TEST_HELPER)"

# Inspect the exact release binary and byte-identical staged-install copy with
# native ELF or Mach-O tooling. The shell test owns its temporary stage.
ifeq ($(BUILD_TYPE),release)
release-artifact-test: $(BINDIR)/$(TARGET)
	@set -e; \
	stage=`mktemp -d "$${TMPDIR:-/tmp}/gitswitch-release-stage.XXXXXX"`; \
	trap 'status=$$?; trap - 0 1 2 3 15; rm -rf "$$stage"; exit $$status' 0 1 2 3 15; \
	install_log="$$stage/install.log"; \
	if ! $(MAKE) BUILD_TYPE=release install DESTDIR="$$stage" PREFIX="$(PREFIX)" \
		>"$$install_log" 2>&1; then \
		cat "$$install_log" >&2; \
		exit 1; \
	fi; \
	if grep -F 'Warning: installing a' "$$install_log" >/dev/null; then \
		cat "$$install_log" >&2; \
		echo 'ERROR: release build stamp was not recognized by install' >&2; \
		exit 1; \
	fi; \
	stack_home="$$stage/stack-home"; \
	stack_runtime="$$stage/stack-runtime"; \
	mkdir -m 700 "$$stack_home" "$$stack_runtime"; \
	stack_log="$$stage/stack.log"; \
	if ! (ulimit -s 256; \
		"$(BINDIR)/$(TARGET)" --help >/dev/null && \
		"$(BINDIR)/$(TARGET)" --version >/dev/null && \
		HOME="$$stack_home" XDG_RUNTIME_DIR="$$stack_runtime" \
			"$(BINDIR)/$(TARGET)" -n -C config </dev/null >/dev/null) \
			>"$$stack_log" 2>&1; then \
		cat "$$stack_log" >&2; \
		echo 'ERROR: release CLI failed under a 256 KiB stack' >&2; \
		exit 1; \
	fi; \
	echo 'Release stack check passed: help/version/config at 256 KiB'; \
	GITSWITCH_RELEASE_FORMAT="$(RELEASE_ARTIFACT_FORMAT)" \
	sh tests/test_ar07_release.sh artifact "$(BINDIR)/$(TARGET)" \
		"$$stage$(PREFIX)/bin/$(TARGET)" "$(TARGET_TRIPLE)"; \
	# Exercise the compiler-argv contract even when CC itself is one word. \
	GITSWITCH_RELEASE_FORMAT="$(RELEASE_ARTIFACT_FORMAT)" \
	sh tests/test_ar07_release.sh neuter \
		"$(SECURITY_CFLAGS_RELEASE)" \
		"$(CURDIR)/$(SRCDIR)/release_hardening.h" \
		"$(MAKE_COMMAND)" -- env $(CC)
else
release-artifact-test:
	@echo "ERROR: release-artifact-test requires BUILD_TYPE=release" >&2
	@exit 2
endif

qa-contract-test:
	@sh tests/test_qa.sh "$(CURDIR)" "$(MAKE_COMMAND)"
	@sh tests/test_release_publish_lock.sh "$(CURDIR)"
	@sh tests/test_ar07_build.sh "$(CURDIR)" "$(MAKE_COMMAND)"
	@sh tests/test_ci_policy.sh "$(CURDIR)"

# AR-06 F32: the SIG-01/SIG-02/F4 end-to-end signal-interruption repro was
# tracked but executed by nothing (not `make test`, not CI). Wire it in against
# the freshly built binary. Local development may still skip on a minimal host,
# but a lane that lists the exact `openssh` capability as required must fail
# closed if the real agent/key tools are unavailable (AR-08 M46).
sig-repro-test: $(BINDIR)/$(TARGET)
	@if command -v ssh-agent >/dev/null 2>&1 && \
	   command -v ssh-add >/dev/null 2>&1 && \
	   command -v ssh-keygen >/dev/null 2>&1; then \
		sh tests/repro_sig01.sh; \
	else \
		case ",$${GITSWITCH_TEST_REQUIRED_CAPS-}," in \
			*,openssh,*) \
				echo "ERROR: sig-repro-test requires OpenSSH test tools in this lane" >&2; \
				exit 1 ;; \
			*) \
				echo "SKIP sig-repro-test: OpenSSH test tools are unavailable" ;; \
		esac; \
	fi

rpm: dist
	@echo "Building RPM package..."
	@command -v rpmbuild >/dev/null 2>&1 || (echo "rpmbuild not available - install rpm-build package" && exit 1)
	mkdir -p ~/rpmbuild/BUILD ~/rpmbuild/RPMS ~/rpmbuild/SOURCES \
		~/rpmbuild/SPECS ~/rpmbuild/SRPMS
	cp "$$GITSWITCH_DIST_ARCHIVE_PATH" ~/rpmbuild/SOURCES/
	# Consume the review-identical spec embedded in the commit-pinned archive,
	# never a second live-checkout input.
	tar -xOf "$$GITSWITCH_DIST_ARCHIVE_PATH" \
		"$$GITSWITCH_DIST_ROOT/$(PACKAGE).spec" > \
		~/rpmbuild/SPECS/$(PACKAGE).spec
	rpmbuild -ba ~/rpmbuild/SPECS/$(PACKAGE).spec
	@echo "RPM packages created in ~/rpmbuild/RPMS/"

# Prevent make from removing intermediate files
.SECONDARY: $(OBJECTS) $(TEST_OBJECTS) $(PUBLIC_API_PRODUCTION_OBJECT) \
	$(AR07_RESET_MAIN_OBJECT) \
	$(AR08_REMOVE_ACCOUNTS_OBJECT) $(AR08_HINT_CONFIG_OBJECT)
