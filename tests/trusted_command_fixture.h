/* Private trusted PATH fixtures for command-mocking test suites. */
#ifndef GITSWITCH_TRUSTED_COMMAND_FIXTURE_H
#define GITSWITCH_TRUSTED_COMMAND_FIXTURE_H

#include "test.h"
#include "utils.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char directory[MAX_PATH_LEN];
    char *saved_path;
    bool saved_path_present;
    bool active;
} ts_trusted_command_fixture_t;

static inline bool ts_trusted_command_name_is_safe(const char *name) {
    if (!name || !*name) return false;
    for (const unsigned char *byte = (const unsigned char *)name;
         *byte; byte++) {
        if (!((*byte >= 'a' && *byte <= 'z') ||
              (*byte >= 'A' && *byte <= 'Z') ||
              (*byte >= '0' && *byte <= '9') ||
              *byte == '-' || *byte == '_')) {
            return false;
        }
    }
    return true;
}

static inline void ts_trusted_command_fixture_remove(
    ts_trusted_command_fixture_t *fixture) {
    if (fixture && fixture->directory[0] != '\0') {
        ts_rm_rf(fixture->directory);
        fixture->directory[0] = '\0';
    }
}

static inline int ts_trusted_command_fixture_restore(
    ts_trusted_command_fixture_t *fixture) {
    int rc = 0;
    int restore_errno = 0;

    if (!fixture) {
        errno = EINVAL;
        return -1;
    }
    if (fixture->active) {
        rc = fixture->saved_path_present
                 ? setenv("PATH", fixture->saved_path, 1)
                 : unsetenv("PATH");
        if (rc != 0) restore_errno = errno;
    }
    free(fixture->saved_path);
    fixture->saved_path = NULL;
    fixture->saved_path_present = false;
    fixture->active = false;
    ts_trusted_command_fixture_remove(fixture);
    if (rc != 0) errno = restore_errno;
    return rc;
}

/* Mock runners still exercise production command resolution before they see
 * an argv. Install inert, runnable scripts below canonical HOME so every host
 * proves the same trusted-executable boundary instead of depending on its
 * package-manager prefix. `names` is a non-empty NULL-terminated list. */
static inline int ts_trusted_command_fixture_install(
    ts_trusted_command_fixture_t *fixture, const char *stem,
    const char *const names[]) {
    static const char program[] = "#!/bin/sh\nexit 0\n";
    const char *path;
    char *fixture_path = NULL;
    size_t directory_length;
    size_t path_length;
    size_t fixture_path_length;

    if (!fixture || fixture->active || !stem || !*stem || !names ||
        !names[0]) {
        errno = fixture && fixture->active ? EALREADY : EINVAL;
        return -1;
    }
    memset(fixture, 0, sizeof(*fixture));
    path = getenv("PATH");
    fixture->saved_path_present = path != NULL;
    if (path) {
        fixture->saved_path = strdup(path);
        if (!fixture->saved_path) return -1;
    }
    if (!ts_mkdtemp_trusted(fixture->directory,
                            sizeof(fixture->directory), stem)) {
        free(fixture->saved_path);
        fixture->saved_path = NULL;
        fixture->saved_path_present = false;
        return -1;
    }

    for (size_t i = 0; names[i]; i++) {
        char executable[MAX_PATH_LEN];

        if (!ts_trusted_command_name_is_safe(names[i])) {
            errno = EINVAL;
            goto fail_before_path;
        }
        if (safe_snprintf(executable, sizeof(executable), "%s/%s",
                          fixture->directory, names[i]) != 0 ||
            write_string_to_file(executable, program, 0700) != 0 ||
            chmod(executable, 0700) != 0) {
            goto fail_before_path;
        }
    }

    directory_length = strlen(fixture->directory);
    path_length = path ? strlen(path) : 0;
    if (path_length > SIZE_MAX - directory_length - 2U) {
        errno = EOVERFLOW;
        goto fail_before_path;
    }
    fixture_path_length = directory_length +
                          (path_length > 0 ? path_length + 1U : 0U) + 1U;
    fixture_path = malloc(fixture_path_length);
    if (!fixture_path) goto fail_before_path;
    memcpy(fixture_path, fixture->directory, directory_length);
    if (path_length > 0) {
        fixture_path[directory_length] = ':';
        memcpy(fixture_path + directory_length + 1U, path,
               path_length + 1U);
    } else {
        fixture_path[directory_length] = '\0';
    }
    if (setenv("PATH", fixture_path, 1) != 0) {
        free(fixture_path);
        goto fail_before_path;
    }
    free(fixture_path);
    fixture->active = true;

    for (size_t i = 0; names[i]; i++) {
        char executable[MAX_PATH_LEN];
        char resolved[MAX_PATH_LEN];

        if (safe_snprintf(executable, sizeof(executable), "%s/%s",
                          fixture->directory, names[i]) != 0 ||
            find_command_path(names[i], resolved, sizeof(resolved)) != 0 ||
            strcmp(resolved, executable) != 0) {
            int saved_errno = errno ? errno : ENOEXEC;

            (void)ts_trusted_command_fixture_restore(fixture);
            errno = saved_errno;
            return -1;
        }
    }
    return 0;

fail_before_path:
    {
        int saved_errno = errno;

        free(fixture->saved_path);
        fixture->saved_path = NULL;
        fixture->saved_path_present = false;
        ts_trusted_command_fixture_remove(fixture);
        errno = saved_errno;
        return -1;
    }
}

#endif /* GITSWITCH_TRUSTED_COMMAND_FIXTURE_H */
