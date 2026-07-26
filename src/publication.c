/* Strict, bounded durable Git-publication provenance. */

#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif
/* FreeBSD exposes O_PATH only in its default BSD namespace. */
#if !defined(__FreeBSD__)
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#endif

#include "publication.h"

#include "error.h"
#include "utils.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
# if !defined(O_NOFOLLOW) || O_NOFOLLOW == 0
#  error "O_NOFOLLOW is required on supported platforms"
# endif
#elif !defined(O_NOFOLLOW)
#define O_NOFOLLOW 0
#endif

typedef struct {
    const unsigned char *cursor;
    const unsigned char *end;
} publication_reader_t;

typedef struct {
    unsigned char *data;
    size_t length;
    size_t capacity;
} publication_writer_t;

static int publication_writer_printf(publication_writer_t *writer,
                                     const char *format, ...)
    GS_PRINTF_FMT(2, 3);

static bool publication_identity_is_zero(
    const publication_identity_t *identity) {
    return identity && !identity->present && identity->device == 0U &&
           identity->inode == 0U && identity->mode == 0U &&
           identity->uid == 0U && identity->gid == 0U &&
           identity->link_count == 0U && identity->size == 0U &&
           identity->mtime_seconds == 0 &&
           identity->mtime_nanoseconds == 0U &&
           identity->ctime_seconds == 0 &&
           identity->ctime_nanoseconds == 0U;
}

static bool publication_string_terminated(const char *value, size_t size) {
    return value && memchr(value, '\0', size) != NULL;
}

static bool publication_identity_is_type(
    const publication_identity_t *identity, bool directory) {
    mode_t mode;
    if (!identity || !identity->present || identity->link_count == 0U) {
        return false;
    }
    mode = (mode_t)identity->mode;
    if ((uintmax_t)mode != identity->mode) return false;
    return directory ? S_ISDIR(mode) : S_ISREG(mode);
}

static int publication_invalid(const char *message) {
    set_error(ERR_CONFIG_INVALID, "%s", message);
    return -1;
}

void publication_identity_from_stat(publication_identity_t *identity,
                                    const struct stat *st) {
    if (!identity) return;
    memset(identity, 0, sizeof(*identity));
    if (!st) return;
    identity->present = true;
    identity->device = (uintmax_t)st->st_dev;
    identity->inode = (uintmax_t)st->st_ino;
    identity->mode = (uintmax_t)st->st_mode;
    identity->uid = (uintmax_t)st->st_uid;
    identity->gid = (uintmax_t)st->st_gid;
    identity->link_count = (uintmax_t)st->st_nlink;
    identity->size = st->st_size < 0 ? 0U : (uintmax_t)st->st_size;
#if defined(__APPLE__)
    identity->mtime_seconds = (int64_t)st->st_mtimespec.tv_sec;
    identity->mtime_nanoseconds = (uint32_t)st->st_mtimespec.tv_nsec;
    identity->ctime_seconds = (int64_t)st->st_ctimespec.tv_sec;
    identity->ctime_nanoseconds = (uint32_t)st->st_ctimespec.tv_nsec;
#else
    identity->mtime_seconds = (int64_t)st->st_mtim.tv_sec;
    identity->mtime_nanoseconds = (uint32_t)st->st_mtim.tv_nsec;
    identity->ctime_seconds = (int64_t)st->st_ctim.tv_sec;
    identity->ctime_nanoseconds = (uint32_t)st->st_ctim.tv_nsec;
#endif
}

bool publication_identity_equal(const publication_identity_t *left,
                                const publication_identity_t *right) {
    if (!left || !right || left->present != right->present) return false;
    if (!left->present) return true;
    return left->device == right->device && left->inode == right->inode &&
           left->mode == right->mode && left->uid == right->uid &&
           left->gid == right->gid &&
           left->link_count == right->link_count &&
           left->size == right->size &&
           left->mtime_seconds == right->mtime_seconds &&
           left->mtime_nanoseconds == right->mtime_nanoseconds &&
           left->ctime_seconds == right->ctime_seconds &&
           left->ctime_nanoseconds == right->ctime_nanoseconds;
}

static bool publication_identity_same_object(
    const publication_identity_t *left,
    const publication_identity_t *right) {
    return left && right && left->present && right->present &&
           left->device == right->device && left->inode == right->inode;
}

typedef enum {
    PUBLICATION_PATH_CONFIG,
    PUBLICATION_PATH_REPOSITORY
} publication_path_kind_t;

/* Produce only the lexical normalizations that do not consult the process
 * working directory or reinterpret ancestry: repeated separators and literal
 * "." components. Any ".." component leaves the spelling byte-exact unless
 * the anchored physical resolution below succeeds. */
static bool publication_path_lexical_key(
    const char *path, char out[MAX_PATH_LEN]) {
    const char *cursor;
    size_t path_length;
    size_t used = 1U;

    if (!path || !out ||
        (path_length = strnlen(path, MAX_PATH_LEN)) >= MAX_PATH_LEN ||
        path[0] != '/') {
        return false;
    }
    cursor = path;
    while (*cursor) {
        const char *component;
        size_t length;

        while (*cursor == '/') cursor++;
        component = cursor;
        while (*cursor && *cursor != '/') cursor++;
        length = (size_t)(cursor - component);
        if (length == 2U && component[0] == '.' &&
            component[1] == '.') {
            memcpy(out, path, path_length + 1U);
            return true;
        }
    }

    out[0] = '/';
    cursor = path;
    while (*cursor) {
        const char *component;
        size_t length;

        while (*cursor == '/') cursor++;
        component = cursor;
        while (*cursor && *cursor != '/') cursor++;
        length = (size_t)(cursor - component);
        if (length == 0U ||
            (length == 1U && component[0] == '.')) {
            continue;
        }
        if (used > 1U) out[used++] = '/';
        memcpy(out + used, component, length);
        used += length;
    }
    out[used] = '\0';
    return true;
}

static bool publication_path_parent_and_leaf(
    const char *path, char parent[MAX_PATH_LEN], const char **leaf) {
    const char *slash;
    size_t parent_length;

    if (!path || !parent || !leaf || path[0] != '/') return false;
    slash = strrchr(path, '/');
    if (!slash || !slash[1] || strcmp(slash + 1U, ".") == 0 ||
        strcmp(slash + 1U, "..") == 0) {
        return false;
    }
    parent_length = slash == path ? 1U : (size_t)(slash - path);
    if (parent_length >= MAX_PATH_LEN) return false;
    memcpy(parent, path, parent_length);
    parent[parent_length] = '\0';
    *leaf = slash + 1U;
    return true;
}

static bool publication_directory_anchor_matches_path(
    const char *path, const publication_identity_t *identity,
    int *directory_fd) {
    struct stat st;
    int fd;

    if (directory_fd) *directory_fd = -1;
    if (!path || !identity || !identity->present) return false;
    fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) ||
        identity->device != (uintmax_t)st.st_dev ||
        identity->inode != (uintmax_t)st.st_ino) {
        (void)close(fd);
        return false;
    }
    if (directory_fd) {
        *directory_fd = fd;
    } else {
        (void)close(fd);
    }
    return true;
}

static bool publication_config_physical_key(
    const char *path, const publication_identity_t *config_parent,
    char out[MAX_PATH_LEN]) {
    char canonical[MAX_PATH_LEN];
    char parent[MAX_PATH_LEN];
    char canonical_parent[MAX_PATH_LEN];
    const char *leaf;
    struct stat leaf_stat;
    int parent_fd = -1;
    int resolve_errno;
    size_t parent_length;
    size_t leaf_length;

    if (realpath(path, canonical) != NULL) {
        if (!publication_path_parent_and_leaf(canonical, parent, &leaf) ||
            !publication_directory_anchor_matches_path(
                parent, config_parent, NULL)) {
            return false;
        }
        memcpy(out, canonical, strlen(canonical) + 1U);
        return true;
    }
    resolve_errno = errno;
    if (resolve_errno != ENOENT ||
        !publication_path_parent_and_leaf(path, parent, &leaf) ||
        realpath(parent, canonical_parent) == NULL ||
        !publication_directory_anchor_matches_path(
            canonical_parent, config_parent, &parent_fd)) {
        return false;
    }
    errno = 0;
    if (fstatat(parent_fd, leaf, &leaf_stat, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT) {
        (void)close(parent_fd);
        return false;
    }
    (void)close(parent_fd);
    parent_length = strlen(canonical_parent);
    leaf_length = strlen(leaf);
    if (parent_length + (parent_length == 1U ? 0U : 1U) + leaf_length >=
        MAX_PATH_LEN) {
        return false;
    }
    memcpy(out, canonical_parent, parent_length);
    if (parent_length != 1U) out[parent_length++] = '/';
    memcpy(out + parent_length, leaf, leaf_length + 1U);
    return true;
}

static bool publication_repository_physical_key(
    const char *path, const publication_identity_t *repository,
    char out[MAX_PATH_LEN]) {
    char canonical[MAX_PATH_LEN];

    if (realpath(path, canonical) == NULL ||
        !publication_directory_anchor_matches_path(
            canonical, repository, NULL)) {
        return false;
    }
    memcpy(out, canonical, strlen(canonical) + 1U);
    return true;
}

/* Derive one stable destination key without ever changing the caller's error
 * state. Anchored physical resolution wins when it can be proven. Offline or
 * otherwise unresolved legacy spellings retain only the safe lexical
 * normalization above and remain serializable byte-for-byte. */
static bool publication_destination_path_key(
    const char *path, const publication_identity_t *anchor,
    publication_path_kind_t kind, char out[MAX_PATH_LEN]) {
    char physical[MAX_PATH_LEN];
    int saved_errno = errno;
    bool physical_ready;

    if (kind == PUBLICATION_PATH_REPOSITORY && path && path[0] == '\0') {
        out[0] = '\0';
        errno = saved_errno;
        return true;
    }
    if (!publication_path_lexical_key(path, out)) {
        errno = saved_errno;
        return false;
    }
    physical_ready =
        kind == PUBLICATION_PATH_CONFIG
            ? publication_config_physical_key(path, anchor, physical)
            : publication_repository_physical_key(path, anchor, physical);
    if (physical_ready) {
        memcpy(out, physical, strlen(physical) + 1U);
    }
    errno = saved_errno;
    return true;
}

bool publication_record_same_config_destination(
    const publication_record_t *left,
    const publication_record_t *right) {
    char left_path[MAX_PATH_LEN];
    char right_path[MAX_PATH_LEN];

    return left && right &&
           publication_destination_path_key(
               left->config_path, &left->config_parent,
               PUBLICATION_PATH_CONFIG, left_path) &&
           publication_destination_path_key(
               right->config_path, &right->config_parent,
               PUBLICATION_PATH_CONFIG, right_path) &&
           strcmp(left_path, right_path) == 0 &&
           publication_identity_same_object(&left->config_parent,
                                            &right->config_parent);
}

void publication_record_init(publication_record_t *record) {
    if (!record) return;
    memset(record, 0, sizeof(*record));
    record->scope = PUBLICATION_SCOPE_LOCAL;
    record->state = PUBLICATION_STATE_PUBLISHED;
}

static bool publication_fingerprint_valid(const char *fingerprint) {
    size_t length;
    if (!fingerprint) return false;
    length = strlen(fingerprint);
    if (length != 40U && length != 64U) return false;
    for (size_t i = 0; i < length; i++) {
        unsigned char byte = (unsigned char)fingerprint[i];
        if (!isdigit(byte) && (byte < 'A' || byte > 'F')) return false;
    }
    return true;
}

int publication_normalize_gpg_selector(
    const char *selector, char normalized[MAX_GPG_SELECTOR_LEN]) {
    const char *digits;
    size_t selector_length;
    size_t length;

    if (!normalized) return publication_invalid("NULL GPG selector output");
    normalized[0] = '\0';
    if (!selector) {
        return publication_invalid("Invalid publication GPG selector");
    }
    selector_length = strnlen(selector, MAX_GPG_SELECTOR_LEN);
    if (selector_length == MAX_GPG_SELECTOR_LEN) {
        return publication_invalid("Invalid publication GPG selector length");
    }
    digits = selector;
    if (digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) {
        digits += 2;
    }
    length = selector_length - (size_t)(digits - selector);
    if (length == 0U || length >= MAX_GPG_FINGERPRINT_LEN) {
        return publication_invalid("Invalid publication GPG selector length");
    }
    for (size_t i = 0; i < length; i++) {
        unsigned char byte = (unsigned char)digits[i];

        if (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') {
            normalized[i] = (char)byte;
        } else if (byte >= (unsigned char)'A' &&
                   byte <= (unsigned char)'F') {
            normalized[i] = (char)byte;
        } else if (byte >= (unsigned char)'a' &&
                   byte <= (unsigned char)'f') {
            normalized[i] = (char)(byte - (unsigned char)'a' +
                                   (unsigned char)'A');
        } else {
            normalized[0] = '\0';
            return publication_invalid("Invalid publication GPG selector");
        }
    }
    normalized[length] = '\0';
    return 0;
}

static bool publication_selector_valid(const char *selector) {
    char normalized[MAX_GPG_SELECTOR_LEN];

    return selector && publication_normalize_gpg_selector(
                           selector, normalized) == 0 &&
           strcmp(selector, normalized) == 0;
}

int publication_extract_ssh_program(const char *command, char *out,
                                    size_t out_size) {
    size_t command_length;
    size_t cursor;
    size_t used = 0;

    if (!out || out_size == 0U) {
        return publication_invalid("Invalid publication SSH program output");
    }
    out[0] = '\0';
    if (!command || command[0] != '\'') {
        return publication_invalid(
            "Publication SSH command has no canonical executable word");
    }
    command_length = strnlen(command, PUBLICATION_SSH_COMMAND_MAX);
    if (command_length == PUBLICATION_SSH_COMMAND_MAX) {
        return publication_invalid(
            "Publication SSH command exceeds durable storage");
    }

    cursor = 1U;
    while (cursor < command_length) {
        unsigned char byte = (unsigned char)command[cursor];

        if (byte == (unsigned char)'\'') {
            if (cursor + 3U < command_length &&
                command[cursor + 1U] == '\\' &&
                command[cursor + 2U] == '\'' &&
                command[cursor + 3U] == '\'') {
                if (used + 1U >= out_size) goto too_long;
                out[used++] = '\'';
                cursor += 4U;
                continue;
            }
            cursor++;
            if (command_length - cursor < sizeof(" -i '") - 1U ||
                memcmp(command + cursor, " -i '",
                       sizeof(" -i '") - 1U) != 0 ||
                used == 0U || out[0] != '/') {
                return publication_invalid(
                    "Publication SSH command does not match the managed command grammar");
            }
            out[used] = '\0';
            return 0;
        }
        if (byte < 0x20U || byte == 0x7fU) {
            return publication_invalid(
                "Publication SSH executable contains a control character");
        }
        if (used + 1U >= out_size) goto too_long;
        out[used++] = command[cursor++];
    }
    return publication_invalid(
        "Publication SSH command has an unterminated executable word");

too_long:
    out[0] = '\0';
    return publication_invalid(
        "Publication SSH executable exceeds durable storage");
}

int publication_record_validate(const publication_record_t *record) {
    bool local_destination;
    uint32_t gpg_capabilities;
    uint32_t ssh_capabilities;
    char extracted_ssh_program[MAX_PATH_LEN];
    if (!record) return publication_invalid("NULL publication record");
    if (!publication_string_terminated(record->config_path,
                                       sizeof(record->config_path)) ||
        !publication_string_terminated(
            record->account_incarnation,
            sizeof(record->account_incarnation)) ||
        !publication_string_terminated(record->repository_path,
                                       sizeof(record->repository_path)) ||
        !publication_string_terminated(record->gpg_fingerprint,
                                       sizeof(record->gpg_fingerprint)) ||
        !publication_string_terminated(record->gpg_selector,
                                       sizeof(record->gpg_selector)) ||
        !publication_string_terminated(record->gpg_program,
                                       sizeof(record->gpg_program)) ||
        !publication_string_terminated(record->ssh_command,
                                       sizeof(record->ssh_command)) ||
        !publication_string_terminated(record->ssh_program,
                                       sizeof(record->ssh_program))) {
        return publication_invalid("Unterminated publication record field");
    }
    if (record->account_id == 0U) {
        return publication_invalid("Publication account ID must be nonzero");
    }
    if (!account_incarnation_is_valid(record->account_incarnation)) {
        return publication_invalid(
            "Publication account incarnation must be 64 uppercase hexadecimal digits");
    }
    if (record->scope != PUBLICATION_SCOPE_LOCAL &&
        record->scope != PUBLICATION_SCOPE_GLOBAL &&
        record->scope != PUBLICATION_SCOPE_WORKTREE) {
        return publication_invalid("Invalid publication scope");
    }
    if (record->state != PUBLICATION_STATE_PUBLISHED &&
        record->state != PUBLICATION_STATE_RETIRING) {
        return publication_invalid("Invalid publication state");
    }
    if ((record->capabilities & ~PUBLICATION_CAP_ALL) != 0U ||
        (record->capabilities & PUBLICATION_CAP_DESTINATION) == 0U) {
        return publication_invalid("Invalid publication capability set");
    }
    gpg_capabilities = record->capabilities &
        (PUBLICATION_CAP_GPG_FINGERPRINT | PUBLICATION_CAP_GPG_PROGRAM |
         PUBLICATION_CAP_GPG_SELECTOR);
    /* Records written before selector binding carried the fingerprint/program
     * pair only. Keep those parseable for retirement and explicit
     * status-incomplete diagnostics, but never accept one half of the pair or
     * a selector without both canonical publication witnesses. */
    if (gpg_capabilities != 0U &&
        gpg_capabilities !=
            (PUBLICATION_CAP_GPG_FINGERPRINT |
             PUBLICATION_CAP_GPG_PROGRAM) &&
        gpg_capabilities !=
            (PUBLICATION_CAP_GPG_FINGERPRINT |
             PUBLICATION_CAP_GPG_PROGRAM |
             PUBLICATION_CAP_GPG_SELECTOR)) {
        return publication_invalid("Incomplete publication GPG provenance tuple");
    }
    if (gpg_capabilities != 0U &&
        (record->capabilities & PUBLICATION_CAP_POST_GENERATION) == 0U) {
        return publication_invalid(
            "Publication GPG provenance requires a post-config generation");
    }
    if ((record->capabilities &
         PUBLICATION_CAP_GPG_SIGNING_STATE) != 0U) {
        if ((gpg_capabilities &
             (PUBLICATION_CAP_GPG_FINGERPRINT |
              PUBLICATION_CAP_GPG_PROGRAM)) !=
            (PUBLICATION_CAP_GPG_FINGERPRINT |
             PUBLICATION_CAP_GPG_PROGRAM)) {
            return publication_invalid(
                "Publication signing state requires complete GPG provenance");
        }
    } else if (record->gpg_signing_enabled) {
        return publication_invalid(
            "Publication signing state lacks its capability bit");
    }
    ssh_capabilities = record->capabilities &
        (PUBLICATION_CAP_SSH_COMMAND | PUBLICATION_CAP_SSH_PROGRAM);
    if (ssh_capabilities != 0U &&
        ssh_capabilities !=
            (PUBLICATION_CAP_SSH_COMMAND | PUBLICATION_CAP_SSH_PROGRAM)) {
        return publication_invalid(
            "Incomplete publication SSH provenance tuple");
    }
    if (ssh_capabilities != 0U &&
        (record->capabilities & PUBLICATION_CAP_POST_GENERATION) == 0U) {
        return publication_invalid(
            "Publication SSH provenance requires a post-config generation");
    }
    if (record->config_path[0] != '/' ||
        !publication_identity_is_type(&record->config_parent, true)) {
        return publication_invalid(
            "Publication destination requires an absolute config path and directory identity");
    }
    local_destination = record->scope == PUBLICATION_SCOPE_LOCAL ||
                        record->scope == PUBLICATION_SCOPE_WORKTREE;
    if (local_destination) {
        if (record->repository_path[0] != '/' ||
            !publication_identity_is_type(&record->repository, true)) {
            return publication_invalid(
                "Local publication requires an absolute repository and directory identity");
        }
    } else if (record->repository_path[0] != '\0' ||
               !publication_identity_is_zero(&record->repository)) {
        return publication_invalid(
            "Global publication cannot carry a repository identity");
    }
    if ((record->capabilities & PUBLICATION_CAP_POST_GENERATION) != 0U) {
        if (!publication_identity_is_type(&record->post_config, false)) {
            return publication_invalid(
                "Publication post-generation capability requires a regular-file identity");
        }
    } else {
        if (!publication_identity_is_zero(&record->post_config)) {
            return publication_invalid(
                "Publication post-generation data lacks its capability bit");
        }
    }
    if ((record->capabilities & PUBLICATION_CAP_GPG_FINGERPRINT) != 0U) {
        if (!publication_fingerprint_valid(record->gpg_fingerprint)) {
            return publication_invalid(
                "Publication GPG fingerprint is not canonical uppercase hex");
        }
    } else if (record->gpg_fingerprint[0] != '\0') {
        return publication_invalid(
            "Publication GPG fingerprint lacks its capability bit");
    }
    if ((record->capabilities & PUBLICATION_CAP_GPG_SELECTOR) != 0U) {
        if (!publication_selector_valid(record->gpg_selector)) {
            return publication_invalid(
                "Publication GPG selector is not canonical uppercase hex");
        }
    } else if (record->gpg_selector[0] != '\0') {
        return publication_invalid(
            "Publication GPG selector lacks its capability bit");
    }
    if ((record->capabilities & PUBLICATION_CAP_GPG_PROGRAM) != 0U) {
        if (record->gpg_program[0] != '/' ||
            !publication_identity_is_type(&record->gpg_program_identity,
                                          false)) {
            return publication_invalid(
                "Publication GPG program requires an absolute path and regular-file identity");
        }
    } else if (record->gpg_program[0] != '\0' ||
               !publication_identity_is_zero(
                   &record->gpg_program_identity)) {
        return publication_invalid(
            "Publication GPG program lacks its capability bit");
    }
    if (ssh_capabilities == 0U && record->ssh_command[0] != '\0') {
        return publication_invalid(
            "Publication SSH command lacks its capability bit");
    }
    if (ssh_capabilities != 0U && record->ssh_command[0] == '\0') {
        return publication_invalid("Publication SSH command is empty");
    }
    if (ssh_capabilities != 0U) {
        if (record->ssh_program[0] != '/' ||
            !publication_identity_is_type(&record->ssh_program_identity,
                                          false)) {
            return publication_invalid(
                "Publication SSH program requires an absolute path and regular-file identity");
        }
        if (publication_extract_ssh_program(
                record->ssh_command, extracted_ssh_program,
                sizeof(extracted_ssh_program)) != 0 ||
            strcmp(extracted_ssh_program, record->ssh_program) != 0) {
            return publication_invalid(
                "Publication SSH command executable does not match its persisted program");
        }
    } else if (record->ssh_program[0] != '\0' ||
               !publication_identity_is_zero(
                   &record->ssh_program_identity)) {
        return publication_invalid(
            "Publication SSH program lacks its capability bit");
    }
    if (record->config_parent.mtime_nanoseconds >= UINT32_C(1000000000) ||
        record->config_parent.ctime_nanoseconds >= UINT32_C(1000000000) ||
        record->repository.mtime_nanoseconds >= UINT32_C(1000000000) ||
        record->repository.ctime_nanoseconds >= UINT32_C(1000000000) ||
        record->post_config.mtime_nanoseconds >= UINT32_C(1000000000) ||
        record->post_config.ctime_nanoseconds >= UINT32_C(1000000000) ||
        record->gpg_program_identity.mtime_nanoseconds >=
            UINT32_C(1000000000) ||
        record->gpg_program_identity.ctime_nanoseconds >=
            UINT32_C(1000000000) ||
        record->ssh_program_identity.mtime_nanoseconds >=
            UINT32_C(1000000000) ||
        record->ssh_program_identity.ctime_nanoseconds >=
            UINT32_C(1000000000)) {
        return publication_invalid("Publication identity has invalid nanoseconds");
    }
    return 0;
}

static const char *publication_destination_scope_name(
    publication_scope_t scope) {
    switch (scope) {
        case PUBLICATION_SCOPE_GLOBAL: return "global";
        case PUBLICATION_SCOPE_LOCAL: return "local";
        case PUBLICATION_SCOPE_WORKTREE: return "worktree";
        default: return "invalid";
    }
}

static bool publication_directory_identity_matches_stat(
    const publication_identity_t *identity, const struct stat *st) {
    return identity && identity->present && st &&
           identity->device == (uintmax_t)st->st_dev &&
           identity->inode == (uintmax_t)st->st_ino &&
           (identity->mode & (uintmax_t)S_IFMT) ==
               ((uintmax_t)st->st_mode & (uintmax_t)S_IFMT);
}

int publication_record_verify_live_destination(
    const publication_record_t *record,
    const publication_record_t *const generation_records[],
    size_t generation_count,
    const publication_record_t **live_generation) {
    char destination_config[MAX_PATH_LEN];
    char destination_repository[MAX_PATH_LEN];
    char parent_path[MAX_PATH_LEN];
    const char *slash;
    const char *leaf;
    publication_identity_t live_config;
    struct stat parent_stat;
    struct stat config_stat;
    struct stat repository_stat;
    int parent_fd = -1;
    int config_fd = -1;
    int repository_fd = -1;
    bool generation_matches = false;
    bool destination_matches = false;

    if (live_generation) *live_generation = NULL;
    if (!record || !generation_records || generation_count == 0U ||
        generation_count > PUBLICATION_LEDGER_MAX_RECORDS) {
        errno = EINVAL;
        set_error(ERR_INVALID_ARGS,
                  "Invalid publication destination verification arguments");
        return -1;
    }
    if (publication_record_validate(record) != 0) return -1;
    if ((record->capabilities & PUBLICATION_CAP_POST_GENERATION) == 0U) {
        goto mismatch;
    }
    for (size_t i = 0; i < generation_count; i++) {
        if (!generation_records[i] ||
            publication_record_validate(generation_records[i]) != 0) {
            return -1;
        }
    }

    if (!publication_destination_path_key(
            record->config_path, &record->config_parent,
            PUBLICATION_PATH_CONFIG, destination_config)) {
        goto mismatch;
    }
    slash = strrchr(destination_config, '/');
    if (!slash || !slash[1]) goto mismatch;
    leaf = slash + 1U;
    if (slash == destination_config) {
        if (safe_strncpy(parent_path, "/", sizeof(parent_path)) != 0) {
            goto mismatch;
        }
    } else {
        size_t parent_length = (size_t)(slash - destination_config);

        if (parent_length >= sizeof(parent_path)) goto mismatch;
        memcpy(parent_path, destination_config, parent_length);
        parent_path[parent_length] = '\0';
    }
    parent_fd = open(parent_path,
                     O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (parent_fd < 0 || fstat(parent_fd, &parent_stat) != 0 ||
        !publication_directory_identity_matches_stat(
            &record->config_parent, &parent_stat)) {
        goto mismatch;
    }
    config_fd = openat(parent_fd, leaf, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (config_fd < 0 || fstat(config_fd, &config_stat) != 0 ||
        !S_ISREG(config_stat.st_mode)) {
        goto mismatch;
    }
    publication_identity_from_stat(&live_config, &config_stat);
    for (size_t i = 0; i < generation_count; i++) {
        const publication_record_t *candidate = generation_records[i];

        if (candidate->account_id == record->account_id &&
            strcmp(candidate->account_incarnation,
                   record->account_incarnation) == 0 &&
            candidate->state == PUBLICATION_STATE_PUBLISHED &&
            (candidate->capabilities & PUBLICATION_CAP_POST_GENERATION) != 0U &&
            publication_record_same_config_destination(record, candidate) &&
            publication_identity_equal(&candidate->post_config,
                                       &live_config)) {
            generation_matches = true;
            if (live_generation) *live_generation = candidate;
            break;
        }
    }
    if (!generation_matches) goto mismatch;

    if (record->scope == PUBLICATION_SCOPE_GLOBAL) {
        destination_matches = true;
        goto cleanup;
    }
    if (!publication_destination_path_key(
            record->repository_path, &record->repository,
            PUBLICATION_PATH_REPOSITORY, destination_repository)) {
        goto mismatch;
    }
    repository_fd = open(destination_repository,
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (repository_fd < 0 || fstat(repository_fd, &repository_stat) != 0 ||
        !publication_directory_identity_matches_stat(
            &record->repository, &repository_stat)) {
        goto mismatch;
    }
    destination_matches = true;
    goto cleanup;

mismatch:
    errno = ESTALE;
    set_error(
        ERR_GIT_CONFIG_FAILED,
        "Recorded %s Git publication destination generation is inaccessible or changed",
        publication_destination_scope_name(record->scope));
cleanup:
    if (repository_fd >= 0) (void)close(repository_fd);
    if (config_fd >= 0) (void)close(config_fd);
    if (parent_fd >= 0) (void)close(parent_fd);
    return destination_matches ? 0 : -1;
}

bool publication_record_same_destination(const publication_record_t *left,
                                         const publication_record_t *right) {
    char left_repository[MAX_PATH_LEN];
    char right_repository[MAX_PATH_LEN];

    if (!left || !right) return false;
    return left->scope == right->scope &&
           publication_record_same_config_destination(left, right) &&
           publication_destination_path_key(
               left->repository_path, &left->repository,
               PUBLICATION_PATH_REPOSITORY, left_repository) &&
           publication_destination_path_key(
               right->repository_path, &right->repository,
               PUBLICATION_PATH_REPOSITORY, right_repository) &&
           strcmp(left_repository, right_repository) == 0 &&
           ((left->repository_path[0] == '\0' &&
             right->repository_path[0] == '\0') ||
            publication_identity_same_object(&left->repository,
                                             &right->repository));
}

/* The v1 ledger records only a destination identity and a last published file
 * generation.  Neither a same-device ENOENT observation nor a replacement
 * inode proves permanent deletion: another process can rename the exact
 * destination away and restore it later.  Keep the exported query for source
 * compatibility, but fail closed until a future ledger format carries a
 * durable retirement/deletion witness. */
bool publication_record_destination_provably_absent(
    const publication_record_t *record) {
    (void)record;
    return false;
}

/* Automatic v1 reclamation is intentionally disabled.  PUBLISHED authority
 * and RETIRING settlement obligations survive every observational filesystem
 * state; explicit retirement settlement is the only removal path. */
size_t publication_ledger_reclaim_absent(publication_ledger_t *ledger) {
    (void)ledger;
    return 0U;
}

bool publication_ledger_destination_present(
    const publication_ledger_t *ledger,
    const publication_record_t *record) {
    if (!ledger || !record) return false;
    for (size_t i = 0U; i < ledger->count; i++) {
        if (publication_record_same_destination(&ledger->records[i],
                                                record)) {
            return true;
        }
    }
    return false;
}

void publication_ledger_init(publication_ledger_t *ledger) {
    if (!ledger) return;
    memset(ledger, 0, sizeof(*ledger));
}

void publication_ledger_clear(publication_ledger_t *ledger) {
    if (!ledger) return;
    if (ledger->records) {
        secure_zero_memory(ledger->records,
                           ledger->count * sizeof(*ledger->records));
        free(ledger->records);
    }
    memset(ledger, 0, sizeof(*ledger));
}

int publication_ledger_upsert(publication_ledger_t *ledger,
                              const publication_record_t *record) {
    publication_record_t canonical;
    publication_record_t *grown;
    size_t matching_index = SIZE_MAX;

    if (!ledger || publication_record_validate(record) != 0) return -1;
    canonical = *record;
    if (!publication_destination_path_key(
            record->config_path, &record->config_parent,
            PUBLICATION_PATH_CONFIG, canonical.config_path) ||
        !publication_destination_path_key(
            record->repository_path, &record->repository,
            PUBLICATION_PATH_REPOSITORY, canonical.repository_path) ||
        publication_record_validate(&canonical) != 0) {
        return -1;
    }
    if (ledger->present && ledger->version != PUBLICATION_LEDGER_VERSION) {
        return publication_invalid("Unsupported publication ledger version");
    }
    for (size_t i = 0; i < ledger->count; i++) {
        if (publication_record_same_destination(&ledger->records[i],
                                                &canonical)) {
            if (matching_index != SIZE_MAX) {
                return publication_invalid(
                    "Publication ledger upsert destination is ambiguous");
            }
            matching_index = i;
        }
    }
    if (matching_index != SIZE_MAX) {
        ledger->records[matching_index] = canonical;
        ledger->present = true;
        ledger->version = PUBLICATION_LEDGER_VERSION;
        return 0;
    }
    if (ledger->count >= PUBLICATION_LEDGER_MAX_RECORDS) {
        errno = ENOSPC;
        set_error(ERR_CONFIG_INVALID,
                  "Publication ledger record limit reached");
        return -1;
    }
    grown = realloc(ledger->records,
                    (ledger->count + 1U) * sizeof(*ledger->records));
    if (!grown) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Cannot grow publication ledger");
        return -1;
    }
    ledger->records = grown;
    ledger->records[ledger->count++] = canonical;
    ledger->present = true;
    ledger->version = PUBLICATION_LEDGER_VERSION;
    return 0;
}

publication_lookup_status_t publication_ledger_find(
    const publication_ledger_t *ledger, uint32_t account_id,
    const char *account_incarnation,
    publication_scope_t scope, const char *config_path,
    const char *repository_path, const publication_record_t **record) {
    const publication_record_t *match = NULL;
    const char *repository = repository_path ? repository_path : "";

    if (record) *record = NULL;
    if (!ledger || !record || !config_path || account_id == 0U ||
        !account_incarnation_is_valid(account_incarnation) ||
        (scope != PUBLICATION_SCOPE_LOCAL &&
         scope != PUBLICATION_SCOPE_GLOBAL &&
         scope != PUBLICATION_SCOPE_WORKTREE) ||
        strnlen(config_path, MAX_PATH_LEN) >= MAX_PATH_LEN ||
        config_path[0] != '/' ||
        (repository_path &&
         strnlen(repository_path, MAX_PATH_LEN) >= MAX_PATH_LEN) ||
        ((scope == PUBLICATION_SCOPE_LOCAL ||
          scope == PUBLICATION_SCOPE_WORKTREE) &&
         (!repository_path || repository_path[0] != '/')) ||
        (scope == PUBLICATION_SCOPE_GLOBAL && repository[0] != '\0')) {
        set_error(ERR_INVALID_ARGS, "Invalid publication ledger lookup");
        return PUBLICATION_LOOKUP_ERROR;
    }
    if (!ledger->present) {
        if (ledger->version != 0U || ledger->records || ledger->count != 0U) {
            publication_invalid("Inconsistent absent publication ledger");
            return PUBLICATION_LOOKUP_ERROR;
        }
        return PUBLICATION_LOOKUP_ABSENT;
    }
    if (ledger->version != PUBLICATION_LEDGER_VERSION ||
        ledger->count > PUBLICATION_LEDGER_MAX_RECORDS ||
        (ledger->count == 0U && ledger->records) ||
        (ledger->count != 0U && !ledger->records)) {
        publication_invalid("Invalid publication ledger model");
        return PUBLICATION_LOOKUP_ERROR;
    }
    for (size_t i = 0; i < ledger->count; i++) {
        const publication_record_t *candidate = &ledger->records[i];
        char candidate_config[MAX_PATH_LEN];
        char candidate_repository[MAX_PATH_LEN];
        char query_config[MAX_PATH_LEN];
        char query_repository[MAX_PATH_LEN];

        if (publication_record_validate(candidate) != 0) {
            return PUBLICATION_LOOKUP_ERROR;
        }
        for (size_t j = 0; j < i; j++) {
            if (publication_record_same_destination(candidate,
                                                    &ledger->records[j])) {
                publication_invalid(
                    "Publication ledger contains duplicate destinations");
                return PUBLICATION_LOOKUP_ERROR;
            }
        }
        if (candidate->account_id != account_id ||
            strcmp(candidate->account_incarnation,
                   account_incarnation) != 0 ||
            candidate->scope != scope ||
            !publication_destination_path_key(
                candidate->config_path, &candidate->config_parent,
                PUBLICATION_PATH_CONFIG, candidate_config) ||
            !publication_destination_path_key(
                config_path, &candidate->config_parent,
                PUBLICATION_PATH_CONFIG, query_config) ||
            strcmp(candidate_config, query_config) != 0 ||
            !publication_destination_path_key(
                candidate->repository_path, &candidate->repository,
                PUBLICATION_PATH_REPOSITORY, candidate_repository) ||
            !publication_destination_path_key(
                repository, &candidate->repository,
                PUBLICATION_PATH_REPOSITORY, query_repository) ||
            strcmp(candidate_repository, query_repository) != 0) {
            continue;
        }
        if (match) {
            publication_invalid("Publication ledger lookup is ambiguous");
            return PUBLICATION_LOOKUP_ERROR;
        }
        match = candidate;
    }
    if (!match) return PUBLICATION_LOOKUP_ABSENT;
    *record = match;
    return PUBLICATION_LOOKUP_FOUND;
}

static int publication_read_line(publication_reader_t *reader,
                                 const unsigned char **line,
                                 size_t *length) {
    const unsigned char *newline;
    if (!reader || !line || !length || reader->cursor >= reader->end) {
        return publication_invalid("Truncated publication ledger");
    }
    newline = memchr(reader->cursor, '\n',
                     (size_t)(reader->end - reader->cursor));
    if (!newline) return publication_invalid("Publication line lacks newline");
    *line = reader->cursor;
    *length = (size_t)(newline - reader->cursor);
    reader->cursor = newline + 1;
    return 0;
}

static int publication_expect_literal(publication_reader_t *reader,
                                      const char *expected) {
    const unsigned char *line;
    size_t length;
    size_t expected_length = strlen(expected);
    if (publication_read_line(reader, &line, &length) != 0) return -1;
    if (length != expected_length || memcmp(line, expected, length) != 0) {
        return publication_invalid("Unexpected publication ledger line");
    }
    return 0;
}

static int publication_read_field(publication_reader_t *reader, size_t index,
                                  const char *name,
                                  const unsigned char **value,
                                  size_t *value_length) {
    char prefix[96];
    const unsigned char *line;
    size_t length;
    int written = snprintf(prefix, sizeof(prefix), "p.%zu.%s=", index, name);
    if (written < 0 || (size_t)written >= sizeof(prefix) ||
        publication_read_line(reader, &line, &length) != 0) {
        return -1;
    }
    if (length < (size_t)written ||
        memcmp(line, prefix, (size_t)written) != 0) {
        return publication_invalid("Unexpected publication record field");
    }
    *value = line + (size_t)written;
    *value_length = length - (size_t)written;
    return 0;
}

static bool publication_next_field_is(const publication_reader_t *reader,
                                      size_t index, const char *name) {
    char prefix[96];
    const unsigned char *newline;
    size_t line_length;
    int written;

    if (!reader || !name || reader->cursor >= reader->end) return false;
    written = snprintf(prefix, sizeof(prefix), "p.%zu.%s=", index, name);
    if (written < 0 || (size_t)written >= sizeof(prefix)) return false;
    newline = memchr(reader->cursor, '\n',
                     (size_t)(reader->end - reader->cursor));
    if (!newline) return false;
    line_length = (size_t)(newline - reader->cursor);
    return line_length >= (size_t)written &&
           memcmp(reader->cursor, prefix, (size_t)written) == 0;
}

static int publication_copy_token(const unsigned char *value, size_t length,
                                  char *out, size_t out_size) {
    if (!value || !out || out_size == 0U || length >= out_size ||
        memchr(value, '\0', length) != NULL) {
        return publication_invalid("Invalid publication token length");
    }
    memcpy(out, value, length);
    out[length] = '\0';
    return 0;
}

static int publication_parse_uintmax(const unsigned char *value,
                                     size_t length, uintmax_t maximum,
                                     uintmax_t *out) {
    char token[64];
    char canonical[64];
    char *end = NULL;
    uintmax_t parsed;
    int written;
    if (!out) {
        return publication_invalid("NULL publication integer output");
    }
    if (publication_copy_token(value, length, token, sizeof(token)) != 0) {
        return -1;
    }
    if (token[0] == '\0') {
        return publication_invalid("Empty publication integer");
    }
    errno = 0;
    parsed = strtoumax(token, &end, 10);
    if (errno != 0 || end == token || *end != '\0' || parsed > maximum) {
        return publication_invalid("Invalid publication integer");
    }
    /* Constant numeric format; bounded output and exact length checked. */
    // flawfinder: ignore
    written = snprintf(canonical, sizeof(canonical), "%" PRIuMAX, parsed);
    if (written < 0 || (size_t)written != length ||
        memcmp(canonical, value, length) != 0) {
        return publication_invalid("Noncanonical publication integer");
    }
    *out = parsed;
    return 0;
}

static int publication_parse_int64(const unsigned char *value, size_t length,
                                   int64_t *out) {
    char token[64];
    char canonical[64];
    char *end = NULL;
    intmax_t parsed;
    int written;

    if (!out) {
        return publication_invalid("NULL publication signed-integer output");
    }
    if (publication_copy_token(value, length, token, sizeof(token)) != 0) {
        return -1;
    }
    if (token[0] == '\0') {
        return publication_invalid("Empty publication signed integer");
    }
    errno = 0;
    parsed = strtoimax(token, &end, 10);
    if (errno != 0 || end == token || *end != '\0' ||
        parsed < INT64_MIN || parsed > INT64_MAX) {
        return publication_invalid("Invalid publication signed integer");
    }
    /* Constant numeric format; bounded output and exact length checked. */
    // flawfinder: ignore
    written = snprintf(canonical, sizeof(canonical), "%" PRId64,
                       (int64_t)parsed);
    if (written < 0 || (size_t)written != length ||
        memcmp(canonical, value, length) != 0) {
        return publication_invalid(
            "Noncanonical publication signed integer");
    }
    *out = (int64_t)parsed;
    return 0;
}

static int publication_parse_identity(const unsigned char *value,
                                      size_t length,
                                      publication_identity_t *identity) {
    const unsigned char *fields[11];
    size_t field_lengths[11];
    const unsigned char *cursor;
    const unsigned char *end;
    uintmax_t dev, ino, mode, uid, gid, link_count, size, mtime_nsec,
              ctime_nsec;
    int64_t mtime, ctime;

    if (!identity) return publication_invalid("NULL publication identity");
    memset(identity, 0, sizeof(*identity));
    if (!value) return publication_invalid("NULL publication identity value");
    if (length == 1U && value[0] == '-') return 0;
    cursor = value;
    end = value + length;
    for (size_t i = 0; i < 11U; i++) {
        const unsigned char *separator =
            memchr(cursor, ':', (size_t)(end - cursor));
        if (i < 10U) {
            if (!separator || separator == cursor) {
                return publication_invalid(
                    "Invalid publication identity field count");
            }
            fields[i] = cursor;
            field_lengths[i] = (size_t)(separator - cursor);
            cursor = separator + 1U;
        } else {
            if (separator || cursor == end) {
                return publication_invalid(
                    "Invalid publication identity field count");
            }
            fields[i] = cursor;
            field_lengths[i] = (size_t)(end - cursor);
        }
    }
    if (publication_parse_uintmax(fields[0], field_lengths[0], UINTMAX_MAX,
                                  &dev) != 0 ||
        publication_parse_uintmax(fields[1], field_lengths[1], UINTMAX_MAX,
                                  &ino) != 0 ||
        publication_parse_uintmax(fields[2], field_lengths[2], UINTMAX_MAX,
                                  &mode) != 0 ||
        publication_parse_uintmax(fields[3], field_lengths[3], UINTMAX_MAX,
                                  &uid) != 0 ||
        publication_parse_uintmax(fields[4], field_lengths[4], UINTMAX_MAX,
                                  &gid) != 0 ||
        publication_parse_uintmax(fields[5], field_lengths[5], UINTMAX_MAX,
                                  &link_count) != 0 ||
        publication_parse_uintmax(fields[6], field_lengths[6], UINTMAX_MAX,
                                  &size) != 0 ||
        publication_parse_int64(fields[7], field_lengths[7], &mtime) != 0 ||
        publication_parse_uintmax(fields[8], field_lengths[8],
                                  UINTMAX_C(999999999), &mtime_nsec) != 0 ||
        publication_parse_int64(fields[9], field_lengths[9], &ctime) != 0 ||
        publication_parse_uintmax(fields[10], field_lengths[10],
                                  UINTMAX_C(999999999), &ctime_nsec) != 0) {
        return -1;
    }
    identity->present = true;
    identity->device = dev;
    identity->inode = ino;
    identity->mode = mode;
    identity->uid = uid;
    identity->gid = gid;
    identity->link_count = link_count;
    identity->size = size;
    identity->mtime_seconds = mtime;
    identity->mtime_nanoseconds = (uint32_t)mtime_nsec;
    identity->ctime_seconds = ctime;
    identity->ctime_nanoseconds = (uint32_t)ctime_nsec;
    return 0;
}

static int publication_decode_hex(const unsigned char *value, size_t length,
                                  char *out, size_t out_size) {
    size_t decoded;
    if (!out || out_size == 0U) return publication_invalid("Invalid hex output");
    out[0] = '\0';
    if (length == 1U && value[0] == '-') return 0;
    if (length == 0U || (length & 1U) != 0U) {
        return publication_invalid("Invalid publication hex length");
    }
    decoded = length / 2U;
    if (decoded >= out_size) {
        return publication_invalid("Publication string exceeds field bound");
    }
    for (size_t i = 0; i < decoded; i++) {
        unsigned char high = value[i * 2U];
        unsigned char low = value[i * 2U + 1U];
        unsigned int hi;
        unsigned int lo;
        if (high >= '0' && high <= '9') hi = (unsigned int)(high - '0');
        else if (high >= 'A' && high <= 'F') hi = (unsigned int)(high - 'A') + 10U;
        else return publication_invalid("Publication hex is not uppercase");
        if (low >= '0' && low <= '9') lo = (unsigned int)(low - '0');
        else if (low >= 'A' && low <= 'F') lo = (unsigned int)(low - 'A') + 10U;
        else return publication_invalid("Publication hex is not uppercase");
        out[i] = (char)((hi << 4U) | lo);
        if (out[i] == '\0') {
            secure_zero_memory(out, out_size);
            return publication_invalid("Publication string contains NUL");
        }
    }
    out[decoded] = '\0';
    return 0;
}

static int publication_parse_record(publication_reader_t *reader,
                                    size_t index,
                                    publication_record_t *record) {
    const unsigned char *value;
    size_t length;
    uintmax_t number;
    char token[96];
    publication_record_init(record);
#define READ_FIELD(name) \
    if (publication_read_field(reader, index, (name), &value, &length) != 0) \
        return -1
    READ_FIELD("account");
    if (publication_parse_uintmax(value, length, UINT32_MAX, &number) != 0) return -1;
    record->account_id = (uint32_t)number;
    READ_FIELD("incarnation");
    if (publication_copy_token(value, length, record->account_incarnation,
                               sizeof(record->account_incarnation)) != 0) {
        return -1;
    }
    READ_FIELD("scope");
    if (publication_copy_token(value, length, token, sizeof(token)) != 0) return -1;
    if (strcmp(token, "local") == 0) record->scope = PUBLICATION_SCOPE_LOCAL;
    else if (strcmp(token, "global") == 0) record->scope = PUBLICATION_SCOPE_GLOBAL;
    else if (strcmp(token, "worktree") == 0) record->scope = PUBLICATION_SCOPE_WORKTREE;
    else return publication_invalid("Invalid publication scope token");
    READ_FIELD("config");
    if (publication_decode_hex(value, length, record->config_path,
                               sizeof(record->config_path)) != 0) return -1;
    READ_FIELD("config_parent");
    if (publication_parse_identity(value, length, &record->config_parent) != 0) return -1;
    READ_FIELD("repository");
    if (publication_decode_hex(value, length, record->repository_path,
                               sizeof(record->repository_path)) != 0) return -1;
    READ_FIELD("repository_identity");
    if (publication_parse_identity(value, length, &record->repository) != 0) return -1;
    READ_FIELD("post_config");
    if (publication_parse_identity(value, length, &record->post_config) != 0) return -1;
    READ_FIELD("capabilities");
    /* AR-12 L16: name the rejection instead of surfacing a stale earlier
     * diagnostic through the bare -1. */
    if (length != 8U) {
        return publication_invalid(
            "Invalid publication capability mask length");
    }
    if (publication_copy_token(value, length, token,
                               sizeof(token)) != 0) return -1;
    for (size_t i = 0; i < length; i++) {
        if (!isdigit((unsigned char)token[i]) &&
            (token[i] < 'A' || token[i] > 'F')) {
            return publication_invalid("Invalid publication capability mask");
        }
    }
    errno = 0;
    {
        char *end = NULL;
        uintmax_t parsed = strtoumax(token, &end, 16);
        if (errno != 0 || !end || *end != '\0' || parsed > UINT32_MAX) {
            return publication_invalid("Invalid publication capability mask");
        }
        record->capabilities = (uint32_t)parsed;
    }
    READ_FIELD("gpg_fingerprint");
    /* AR-12 L17: '-' is the ONLY canonical empty spelling; a zero-length
     * value would alias it, breaking the byte-for-byte round-trip the
     * serializer guarantees. */
    if (length == 1U && value[0] == '-') record->gpg_fingerprint[0] = '\0';
    else if (length == 0U) {
        return publication_invalid(
            "Empty publication gpg_fingerprint requires '-'");
    } else if (publication_copy_token(value, length, record->gpg_fingerprint,
                                      sizeof(record->gpg_fingerprint)) != 0) {
        return -1;
    }
    /* Selector provenance was added to v1 while it was still an internal,
     * unreleased ledger. Accept the older fingerprint->program sequence so
     * such records remain available for exact retirement, but leave the
     * selector capability absent so status requires a fresh switch. */
    if (publication_next_field_is(reader, index, "gpg_selector")) {
        READ_FIELD("gpg_selector");
        if (length == 1U && value[0] == '-') {
            record->gpg_selector[0] = '\0';
        } else if (length == 0U) {
            return publication_invalid(
                "Empty publication gpg_selector requires '-'");
        } else if (publication_copy_token(
                       value, length, record->gpg_selector,
                       sizeof(record->gpg_selector)) != 0) {
            return -1;
        }
    }
    READ_FIELD("gpg_program");
    if (publication_decode_hex(value, length, record->gpg_program,
                               sizeof(record->gpg_program)) != 0) return -1;
    READ_FIELD("gpg_program_identity");
    if (publication_parse_identity(value, length,
                                   &record->gpg_program_identity) != 0) return -1;
    /* Signing-state provenance was added compatibly to the internal v1
     * ledger. Its capability bit distinguishes an explicit false value from
     * an older record with no durable commit.gpgsign witness. */
    if (publication_next_field_is(reader, index,
                                  "gpg_signing_enabled")) {
        if ((record->capabilities &
             PUBLICATION_CAP_GPG_SIGNING_STATE) == 0U) {
            return publication_invalid(
                "Publication signing-state field lacks its capability bit");
        }
        READ_FIELD("gpg_signing_enabled");
        if (publication_copy_token(value, length, token,
                                   sizeof(token)) != 0) {
            return -1;
        }
        if (strcmp(token, "true") == 0) {
            record->gpg_signing_enabled = true;
        } else if (strcmp(token, "false") == 0) {
            record->gpg_signing_enabled = false;
        } else {
            return publication_invalid(
                "Invalid publication signing-state token");
        }
    } else if ((record->capabilities &
                PUBLICATION_CAP_GPG_SIGNING_STATE) != 0U) {
        return publication_invalid(
            "Publication signing-state capability lacks its field");
    }
    READ_FIELD("ssh_command");
    if (publication_decode_hex(value, length, record->ssh_command,
                               sizeof(record->ssh_command)) != 0) return -1;
    READ_FIELD("ssh_program");
    if (publication_decode_hex(value, length, record->ssh_program,
                               sizeof(record->ssh_program)) != 0) return -1;
    READ_FIELD("ssh_program_identity");
    if (publication_parse_identity(value, length,
                                   &record->ssh_program_identity) != 0) return -1;
    READ_FIELD("state");
    if (publication_copy_token(value, length, token, sizeof(token)) != 0) return -1;
    if (strcmp(token, "published") == 0) record->state = PUBLICATION_STATE_PUBLISHED;
    else if (strcmp(token, "retiring") == 0) record->state = PUBLICATION_STATE_RETIRING;
    else return publication_invalid("Invalid publication state token");
#undef READ_FIELD
    return publication_record_validate(record);
}

int publication_ledger_parse(const unsigned char *data, size_t length,
                             publication_ledger_t *ledger) {
    publication_reader_t reader;
    publication_ledger_t parsed;
    const unsigned char *value;
    size_t value_length;
    uintmax_t count;
    if (!ledger || (!data && length != 0U) ||
        length > PUBLICATION_LEDGER_MAX_BYTES) {
        return publication_invalid("Invalid publication ledger input");
    }
    publication_ledger_init(&parsed);
    if (length == 0U) {
        publication_ledger_clear(ledger);
        *ledger = parsed;
        return 0;
    }
    reader.cursor = data;
    reader.end = data + length;
    if (publication_expect_literal(&reader, "publications=v1") != 0 ||
        publication_read_line(&reader, &value, &value_length) != 0) {
        publication_ledger_clear(&parsed);
        return -1;
    }
    /* AR-12 L16: name the count-line rejection instead of returning a bare
     * -1 that surfaces a stale earlier diagnostic. */
    if (value_length < sizeof("count=") - 1U ||
        memcmp(value, "count=", sizeof("count=") - 1U) != 0) {
        publication_ledger_clear(&parsed);
        return publication_invalid(
            "Malformed publication ledger count line");
    }
    if (publication_parse_uintmax(
            value + sizeof("count=") - 1U,
            value_length - (sizeof("count=") - 1U),
            PUBLICATION_LEDGER_MAX_RECORDS, &count) != 0) {
        publication_ledger_clear(&parsed);
        return -1;
    }
    if (count != 0U) {
        parsed.records = calloc((size_t)count, sizeof(*parsed.records));
        if (!parsed.records) {
            set_error(ERR_MEMORY_ALLOCATION,
                      "Cannot allocate publication ledger");
            return -1;
        }
    }
    parsed.count = (size_t)count;
    parsed.present = true;
    parsed.version = PUBLICATION_LEDGER_VERSION;
    for (size_t i = 0; i < parsed.count; i++) {
        if (publication_parse_record(&reader, i, &parsed.records[i]) != 0) {
            publication_ledger_clear(&parsed);
            return -1;
        }
        for (size_t j = 0; j < i; j++) {
            if (publication_record_same_destination(&parsed.records[i],
                                                    &parsed.records[j])) {
                publication_ledger_clear(&parsed);
                return publication_invalid(
                    "Publication ledger contains duplicate destinations");
            }
        }
    }
    /* AR-14 L9: an absent, truncated, or noncanonical terminator is malformed
     * structure, not trailing data. Reserve the trailing-bytes diagnostic for
     * bytes observed only after a complete canonical `end=v1\n` marker. */
    if (publication_expect_literal(&reader, "end=v1") != 0) {
        publication_ledger_clear(&parsed);
        return publication_invalid(
            "Malformed or missing publication ledger end marker");
    }
    if (reader.cursor != reader.end) {
        publication_ledger_clear(&parsed);
        return publication_invalid("Trailing publication ledger bytes");
    }
    publication_ledger_clear(ledger);
    *ledger = parsed;
    return 0;
}

static int publication_writer_append(publication_writer_t *writer,
                                     const void *data, size_t length) {
    if (!writer || !data || length > writer->capacity - writer->length) {
        return publication_invalid("Publication ledger exceeds byte limit");
    }
    memcpy(writer->data + writer->length, data, length);
    writer->length += length;
    return 0;
}

static int publication_writer_printf(publication_writer_t *writer,
                                     const char *format, ...) {
    va_list args;
    int written;
    size_t remaining;
    if (!writer || !format || writer->length > writer->capacity) return -1;
    remaining = writer->capacity - writer->length;
    va_start(args, format);
    /* This static, compiler-format-checked helper has literal-only callers;
     * the bounded write rejects every truncation. */
    // flawfinder: ignore
    written = vsnprintf((char *)writer->data + writer->length, remaining,
                        format, args);
    va_end(args);
    if (written < 0 || (size_t)written >= remaining) {
        return publication_invalid("Publication ledger exceeds byte limit");
    }
    writer->length += (size_t)written;
    return 0;
}

static int publication_writer_hex(publication_writer_t *writer,
                                  const char *value) {
    static const char digits[] = "0123456789ABCDEF";
    if (!value || value[0] == '\0') {
        return publication_writer_append(writer, "-", 1U);
    }
    for (const unsigned char *cursor = (const unsigned char *)value;
         *cursor; cursor++) {
        char encoded[2] = {
            digits[*cursor >> 4U], digits[*cursor & 0x0fU]
        };
        if (publication_writer_append(writer, encoded, sizeof(encoded)) != 0) {
            return -1;
        }
    }
    return 0;
}

static int publication_writer_identity(
    publication_writer_t *writer, const publication_identity_t *identity) {
    if (!identity || !identity->present) {
        return publication_writer_append(writer, "-", 1U);
    }
    return publication_writer_printf(
        writer,
        "%" PRIuMAX ":%" PRIuMAX ":%" PRIuMAX ":%" PRIuMAX ":%" PRIuMAX
        ":%" PRIuMAX ":%" PRIuMAX ":%" PRId64 ":%" PRIu32
        ":%" PRId64 ":%" PRIu32,
        identity->device, identity->inode, identity->mode, identity->uid,
        identity->gid, identity->link_count, identity->size,
        identity->mtime_seconds, identity->mtime_nanoseconds,
        identity->ctime_seconds, identity->ctime_nanoseconds);
}

static int publication_writer_named_hex(publication_writer_t *writer,
                                        size_t index, const char *name,
                                        const char *value) {
    return publication_writer_printf(writer, "p.%zu.%s=", index, name) == 0 &&
           publication_writer_hex(writer, value) == 0 &&
           publication_writer_append(writer, "\n", 1U) == 0 ? 0 : -1;
}

static int publication_writer_named_identity(
    publication_writer_t *writer, size_t index, const char *name,
    const publication_identity_t *identity) {
    return publication_writer_printf(writer, "p.%zu.%s=", index, name) == 0 &&
           publication_writer_identity(writer, identity) == 0 &&
           publication_writer_append(writer, "\n", 1U) == 0 ? 0 : -1;
}

static int publication_writer_signing_state(
    publication_writer_t *writer, size_t index,
    const publication_record_t *record) {
    if ((record->capabilities &
         PUBLICATION_CAP_GPG_SIGNING_STATE) == 0U) {
        return 0;
    }
    return publication_writer_printf(
        writer, "p.%zu.gpg_signing_enabled=%s\n", index,
        record->gpg_signing_enabled ? "true" : "false");
}

static const char *publication_scope_name(publication_scope_t scope) {
    switch (scope) {
        case PUBLICATION_SCOPE_LOCAL: return "local";
        case PUBLICATION_SCOPE_GLOBAL: return "global";
        case PUBLICATION_SCOPE_WORKTREE: return "worktree";
        default: return NULL;
    }
}

int publication_ledger_serialize(const publication_ledger_t *ledger,
                                 unsigned char **data, size_t *length) {
    publication_writer_t writer;
    unsigned char *shrunk;
    if (!ledger || !data || !length) {
        return publication_invalid("Invalid publication serialization output");
    }
    *data = NULL;
    *length = 0U;
    if (!ledger->present) {
        if (ledger->version != 0U || ledger->records || ledger->count != 0U) {
            return publication_invalid("Inconsistent absent publication ledger");
        }
        return 0;
    }
    if (ledger->version != PUBLICATION_LEDGER_VERSION ||
        ledger->count > PUBLICATION_LEDGER_MAX_RECORDS ||
        (ledger->count != 0U && !ledger->records)) {
        return publication_invalid("Invalid publication ledger model");
    }
    for (size_t i = 0; i < ledger->count; i++) {
        if (publication_record_validate(&ledger->records[i]) != 0) {
            return -1;
        }
        for (size_t j = 0; j < i; j++) {
            if (publication_record_same_destination(&ledger->records[i],
                                                    &ledger->records[j])) {
                return publication_invalid(
                    "Publication ledger contains duplicate destinations");
            }
        }
    }
    memset(&writer, 0, sizeof(writer));
    writer.capacity = PUBLICATION_LEDGER_MAX_BYTES;
    writer.data = malloc(writer.capacity);
    if (!writer.data) {
        set_error(ERR_MEMORY_ALLOCATION,
                  "Cannot allocate serialized publication ledger");
        return -1;
    }
    if (publication_writer_printf(&writer, "publications=v1\ncount=%zu\n",
                                  ledger->count) != 0) goto fail;
    for (size_t i = 0; i < ledger->count; i++) {
        const publication_record_t *record = &ledger->records[i];
        const char *scope;
        const char *state;
        scope = publication_scope_name(record->scope);
        state = record->state == PUBLICATION_STATE_PUBLISHED
                    ? "published" : "retiring";
        if (!scope ||
            publication_writer_printf(&writer, "p.%zu.account=%" PRIu32 "\n",
                                      i, record->account_id) != 0 ||
            publication_writer_printf(
                &writer, "p.%zu.incarnation=%s\n", i,
                record->account_incarnation) != 0 ||
            publication_writer_printf(&writer, "p.%zu.scope=%s\n", i,
                                      scope) != 0 ||
            publication_writer_named_hex(&writer, i, "config",
                                         record->config_path) != 0 ||
            publication_writer_named_identity(&writer, i, "config_parent",
                                              &record->config_parent) != 0 ||
            publication_writer_named_hex(&writer, i, "repository",
                                         record->repository_path) != 0 ||
            publication_writer_named_identity(
                &writer, i, "repository_identity", &record->repository) != 0 ||
            publication_writer_named_identity(&writer, i, "post_config",
                                              &record->post_config) != 0 ||
            publication_writer_printf(&writer,
                                      "p.%zu.capabilities=%08" PRIX32 "\n",
                                      i, record->capabilities) != 0 ||
            publication_writer_printf(
                &writer, "p.%zu.gpg_fingerprint=%s\n", i,
                record->gpg_fingerprint[0] ? record->gpg_fingerprint : "-") != 0 ||
            publication_writer_printf(
                &writer, "p.%zu.gpg_selector=%s\n", i,
                record->gpg_selector[0] ? record->gpg_selector : "-") != 0 ||
            publication_writer_named_hex(&writer, i, "gpg_program",
                                         record->gpg_program) != 0 ||
            publication_writer_named_identity(
                &writer, i, "gpg_program_identity",
                &record->gpg_program_identity) != 0 ||
            publication_writer_signing_state(&writer, i, record) != 0 ||
            publication_writer_named_hex(&writer, i, "ssh_command",
                                         record->ssh_command) != 0 ||
            publication_writer_named_hex(&writer, i, "ssh_program",
                                         record->ssh_program) != 0 ||
            publication_writer_named_identity(
                &writer, i, "ssh_program_identity",
                &record->ssh_program_identity) != 0 ||
            publication_writer_printf(&writer, "p.%zu.state=%s\n", i,
                                      state) != 0) {
            goto fail;
        }
    }
    if (publication_writer_append(&writer, "end=v1\n",
                                  sizeof("end=v1\n") - 1U) != 0) goto fail;
    shrunk = realloc(writer.data, writer.length == 0U ? 1U : writer.length);
    if (shrunk) writer.data = shrunk;
    *data = writer.data;
    *length = writer.length;
    return 0;

fail:
    secure_zero_memory(writer.data, writer.capacity);
    free(writer.data);
    return -1;
}
