/* Utility functions and helpers with security focus
 * Provides secure, validated utility functions for gitswitch-c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <pwd.h>
#include <termios.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <regex.h>

#if defined(__linux__)
#include <sys/mman.h>
#include <linux/random.h>
#include <sys/syscall.h>
#endif

#include "utils.h"
#include "error.h"

/* Static variables for terminal state management */
static struct termios g_original_termios;
static bool g_echo_disabled = false;

/* String utilities */

char *trim_whitespace(char *str) {
    char *end;
    
    if (!str) return NULL;
    
    /* Trim leading space */
    while (isspace((unsigned char)*str)) str++;
    
    /* All spaces? */
    if (*str == '\0') return str;
    
    /* Trim trailing space */
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    
    /* Write new null terminator */
    end[1] = '\0';
    
    return str;
}

bool string_empty(const char *str) {
    return !str || *str == '\0';
}

bool string_equals(const char *a, const char *b) {
    if (!a && !b) return true;
    if (!a || !b) return false;
    return strcmp(a, b) == 0;
}

bool string_starts_with(const char *str, const char *prefix) {
    if (!str || !prefix) return false;
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

bool string_ends_with(const char *str, const char *suffix) {
    if (!str || !suffix) return false;
    
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
    
    if (suffix_len > str_len) return false;
    
    return strcmp(str + str_len - suffix_len, suffix) == 0;
}

int string_replace(char *str, size_t str_size, const char *old, const char *new) {
    if (!str || !old || !new) {
        set_error(ERR_INVALID_ARGS, "NULL arguments to string_replace");
        return -1;
    }
    
    char *pos = strstr(str, old);
    if (!pos) return 0; /* No replacement needed */
    
    size_t old_len = strlen(old);
    size_t new_len = strlen(new);
    size_t str_len = strlen(str);
    
    /* Check if replacement would overflow buffer */
    if (str_len - old_len + new_len >= str_size) {
        set_error(ERR_INVALID_ARGS, "String replacement would overflow buffer");
        return -1;
    }
    
    /* Move the rest of the string */
    memmove(pos + new_len, pos + old_len, strlen(pos + old_len) + 1);
    
    /* Copy new string */
    memcpy(pos, new, new_len);
    
    return 1;
}

/* Path utilities */

int expand_path(const char *path, char *expanded_path, size_t path_size) {
    if (!path || !expanded_path || path_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to expand_path");
        return -1;
    }
    
    /* Handle tilde expansion */
    if (path[0] == '~') {
        char home_path[MAX_PATH_LEN];

        /* Only the current user's home is supported: "~" and "~/...". A
         * "~user/..." form is rejected rather than silently mis-expanded to
         * "$HOME/user/..." (which produced confusing "not found" paths and,
         * if such a path happened to exist, could load the wrong key). */
        if (path[1] != '\0' && path[1] != '/') {
            set_error(ERR_INVALID_ARGS,
                      "~user paths are not supported; use an absolute path or ~/: %s", path);
            return -1;
        }

        if (get_home_directory(home_path, sizeof(home_path)) != 0) {
            return -1;
        }

        /* Handle ~/path and ~ cases */
        const char *rest = (path[1] == '/') ? path + 2 : path + 1;

        if (snprintf(expanded_path, path_size, "%s/%s", home_path, rest) >= (int)path_size) {
            set_error(ERR_INVALID_ARGS, "Expanded path too long");
            return -1;
        }
    } else {
        /* Path doesn't need expansion */
        if (strlen(path) >= path_size) {
            set_error(ERR_INVALID_ARGS, "Path too long for buffer");
            return -1;
        }
        strcpy(expanded_path, path);
    }
    
    return 0;
}

int get_home_directory(char *home_path, size_t path_size) {
    const char *home = getenv("HOME");
    
    if (!home) {
        /* Fall back to password database */
        struct passwd *pw = getpwuid(getuid());
        if (!pw) {
            set_system_error(ERR_SYSTEM_CALL, "Failed to get user home directory");
            return -1;
        }
        home = pw->pw_dir;
    }
    
    if (strlen(home) >= path_size) {
        set_error(ERR_INVALID_ARGS, "Home directory path too long");
        return -1;
    }
    
    strcpy(home_path, home);
    return 0;
}

int join_path(char *result, size_t result_size, const char *base, const char *component) {
    if (!result || !base || !component || result_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to join_path");
        return -1;
    }
    
    size_t base_len = strlen(base);
    size_t comp_len = strlen(component);
    bool needs_separator = (base_len > 0 && base[base_len - 1] != '/') && 
                          (comp_len > 0 && component[0] != '/');
    
    size_t total_len = base_len + comp_len + (needs_separator ? 1 : 0);
    
    if (total_len >= result_size) {
        set_error(ERR_INVALID_ARGS, "Joined path too long for buffer");
        return -1;
    }
    
    strcpy(result, base);
    if (needs_separator) {
        strcat(result, "/");
    }
    strcat(result, component);
    
    return 0;
}

bool path_exists(const char *path) {
    struct stat st;
    return path && stat(path, &st) == 0;
}

bool is_directory(const char *path) {
    struct stat st;
    return path && stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

bool is_regular_file(const char *path) {
    struct stat st;
    return path && stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

int create_directory_recursive(const char *path, mode_t mode) {
    if (!path) {
        set_error(ERR_INVALID_ARGS, "NULL path to create_directory_recursive");
        return -1;
    }
    
    char temp_path[MAX_PATH_LEN];
    char *p = NULL;
    size_t len;
    
    if ((size_t)snprintf(temp_path, sizeof(temp_path), "%s", path) >= sizeof(temp_path)) {
        set_error(ERR_INVALID_ARGS, "Path too long");
        return -1;
    }
    
    len = strlen(temp_path);
    if (temp_path[len - 1] == '/') {
        temp_path[len - 1] = '\0';
    }
    
    for (p = temp_path + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(temp_path, mode) != 0 && errno != EEXIST) {
                set_system_error(ERR_FILE_IO, "Failed to create directory: %s", temp_path);
                return -1;
            }
            *p = '/';
        }
    }
    
    if (mkdir(temp_path, mode) != 0 && errno != EEXIST) {
        set_system_error(ERR_FILE_IO, "Failed to create directory: %s", temp_path);
        return -1;
    }

    return 0;
}

int ensure_private_dir(const char *path) {
    struct stat st;

    if (!path || !*path) {
        set_error(ERR_INVALID_ARGS, "NULL path to ensure_private_dir");
        return -1;
    }

    if (lstat(path, &st) != 0) {
        if (errno != ENOENT) {
            set_system_error(ERR_FILE_IO, "Cannot stat directory: %s", path);
            return -1;
        }
        /* Create it (parents may already exist with other ownership, which is
         * fine — only the leaf holds our private material). */
        if (create_directory_recursive(path, 0700) != 0) {
            return -1;
        }
        if (lstat(path, &st) != 0) {
            set_system_error(ERR_FILE_IO, "Cannot stat created directory: %s", path);
            return -1;
        }
    }

    /* Must be a real directory (lstat does not follow symlinks), owned by us,
     * with no group/other access — refuse a hostile pre-created/redirected dir. */
    if (S_ISLNK(st.st_mode) || !S_ISDIR(st.st_mode)) {
        set_error(ERR_PERMISSION_DENIED, "Refusing to use non-directory/symlink path: %s", path);
        return -1;
    }
    if (st.st_uid != getuid()) {
        set_error(ERR_PERMISSION_DENIED, "Directory not owned by current user: %s", path);
        return -1;
    }
    if (st.st_mode & 077) {
        /* Tighten if we can; refuse if it then still isn't private. */
        if (chmod(path, 0700) != 0 || (lstat(path, &st) == 0 && (st.st_mode & 077))) {
            set_error(ERR_PERMISSION_DENIED, "Directory has unsafe permissions: %s", path);
            return -1;
        }
    }
    return 0;
}

int atomic_symlink(const char *target, const char *linkpath) {
    char tmp[MAX_PATH_LEN];

    if (!target || !linkpath) {
        set_error(ERR_INVALID_ARGS, "NULL args to atomic_symlink");
        return -1;
    }
    if ((size_t)snprintf(tmp, sizeof(tmp), "%s.tmp.%d", linkpath, (int)getpid()) >= sizeof(tmp)) {
        set_error(ERR_INVALID_PATH, "Symlink temp path too long");
        return -1;
    }
    unlink(tmp); /* clear any stale temp */
    if (symlink(target, tmp) != 0) {
        set_system_error(ERR_FILE_IO, "Failed to create symlink: %s", linkpath);
        return -1;
    }
    if (rename(tmp, linkpath) != 0) {
        unlink(tmp);
        set_system_error(ERR_FILE_IO, "Failed to install symlink: %s", linkpath);
        return -1;
    }
    return 0;
}

int get_file_permissions(const char *path, mode_t *mode) {
    struct stat st;
    
    if (!path || !mode) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to get_file_permissions");
        return -1;
    }
    
    if (stat(path, &st) != 0) {
        set_system_error(ERR_FILE_IO, "Failed to stat file: %s", path);
        return -1;
    }
    
    *mode = st.st_mode & 07777; /* Only permission bits */
    return 0;
}

int set_file_permissions(const char *path, mode_t mode) {
    if (!path) {
        set_error(ERR_INVALID_ARGS, "NULL path to set_file_permissions");
        return -1;
    }
    
    if (chmod(path, mode) != 0) {
        set_system_error(ERR_PERMISSION_DENIED, "Failed to set permissions on: %s", path);
        return -1;
    }
    
    return 0;
}

/* File utilities */

int read_file_to_string(const char *file_path, char *buffer, size_t buffer_size) {
    FILE *file;
    size_t bytes_read;
    
    if (!file_path || !buffer || buffer_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to read_file_to_string");
        return -1;
    }
    
    /* "e" = O_CLOEXEC on every fopen here: belt-and-braces with the child fd
     * sweep in run_argv, so a file held open across a spawn can never leak
     * into a long-lived git/gpg/ssh child (fd-CLOEXEC finding). */
    file = fopen(file_path, "re");
    if (!file) {
        set_system_error(ERR_FILE_IO, "Failed to open file for reading: %s", file_path);
        return -1;
    }
    
    bytes_read = fread(buffer, 1, buffer_size - 1, file);
    if (ferror(file)) {
        set_system_error(ERR_FILE_IO, "Failed to read from file: %s", file_path);
        fclose(file);
        return -1;
    }

    /* If we filled the buffer without reaching EOF, the file is larger than the
     * caller's buffer — fail rather than silently returning a truncated copy. */
    if (bytes_read == buffer_size - 1 && !feof(file)) {
        set_error(ERR_FILE_IO, "File too large for buffer: %s", file_path);
        fclose(file);
        return -1;
    }

    buffer[bytes_read] = '\0';
    fclose(file);

    /* bytes_read <= buffer_size-1, so the cast is safe for any sane buffer. */
    return (int)bytes_read;
}

int write_string_to_file(const char *file_path, const char *content, mode_t mode) {
    FILE *file;
    size_t content_len, bytes_written;
    
    if (!file_path || !content) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to write_string_to_file");
        return -1;
    }
    
    file = fopen(file_path, "we");
    if (!file) {
        set_system_error(ERR_FILE_IO, "Failed to open file for writing: %s", file_path);
        return -1;
    }
    
    content_len = strlen(content);
    bytes_written = fwrite(content, 1, content_len, file);
    
    if (bytes_written != content_len) {
        set_system_error(ERR_FILE_IO, "Failed to write complete content to: %s", file_path);
        fclose(file);
        return -1;
    }
    
    fclose(file);
    
    /* Set file permissions */
    if (set_file_permissions(file_path, mode) != 0) {
        return -1;
    }
    
    return 0;
}

int copy_file(const char *src_path, const char *dst_path) {
    FILE *src, *dst;
    char buffer[4096];
    size_t bytes;
    int result = 0;
    
    if (!src_path || !dst_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to copy_file");
        return -1;
    }
    
    src = fopen(src_path, "rbe");
    if (!src) {
        set_system_error(ERR_FILE_IO, "Failed to open source file: %s", src_path);
        return -1;
    }
    
    dst = fopen(dst_path, "wbe");
    if (!dst) {
        set_system_error(ERR_FILE_IO, "Failed to open destination file: %s", dst_path);
        fclose(src);
        return -1;
    }
    
    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        if (fwrite(buffer, 1, bytes, dst) != bytes) {
            set_system_error(ERR_FILE_IO, "Failed to write to destination file: %s", dst_path);
            result = -1;
            break;
        }
    }
    
    if (ferror(src)) {
        set_system_error(ERR_FILE_IO, "Error reading source file: %s", src_path);
        result = -1;
    }
    
    fclose(src);
    fclose(dst);
    
    /* Copy permissions from source to destination */
    if (result == 0) {
        struct stat src_stat;
        if (stat(src_path, &src_stat) == 0) {
            chmod(dst_path, src_stat.st_mode);
        }
    }
    
    return result;
}

int backup_file(const char *file_path, const char *backup_suffix) {
    char backup_path[MAX_PATH_LEN];
    
    if (!file_path || !backup_suffix) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to backup_file");
        return -1;
    }
    
    if ((size_t)snprintf(backup_path, sizeof(backup_path), "%s%s", 
                        file_path, backup_suffix) >= sizeof(backup_path)) {
        set_error(ERR_INVALID_ARGS, "Backup path too long");
        return -1;
    }
    
    return copy_file(file_path, backup_path);
}

bool file_is_readable(const char *file_path) {
    return file_path && access(file_path, R_OK) == 0;
}

bool file_is_writable(const char *file_path) {
    return file_path && access(file_path, W_OK) == 0;
}

size_t get_file_size(const char *file_path) {
    struct stat st;
    
    if (!file_path || stat(file_path, &st) != 0) {
        return 0;
    }
    
    return (size_t)st.st_size;
}

time_t get_file_mtime(const char *file_path) {
    struct stat st;
    
    if (!file_path || stat(file_path, &st) != 0) {
        return 0;
    }
    
    return st.st_mtime;
}

/* Process utilities */

/* ---- Shell-free subprocess execution -------------------------------------
 *
 * run_argv_real spawns argv[0] via fork+execvp (no shell) with optional
 * stdin input, stdout capture, extra environment, and stderr policy. I/O is
 * driven by poll() so an input+output pair cannot deadlock regardless of
 * payload size. The real child exit code is reported via WEXITSTATUS. */

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl != -1) {
        (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    }
}

/* Close every descriptor >= lowfd in the forked child before exec (fd-CLOEXEC).
 * Without this, any fd the parent left open without O_CLOEXEC — a config or
 * backup FILE*, the isolated-home lock, a stray dup — leaks into every git/
 * gpg/ssh child, where a long-lived agent could hold it (and whatever it
 * guards) open indefinitely. Runs post-fork, pre-exec, so only plain syscalls
 * are used. */
static void child_close_fds_from(int lowfd) {
#if defined(__linux__) && defined(SYS_close_range)
    /* close_range(2) is Linux >= 5.9. Invoke via syscall(): the libc wrapper
     * only exists in glibc >= 2.34, and building against newer kernel headers
     * than the running kernel is common — on ENOSYS fall through to the loop. */
    if (syscall(SYS_close_range, (unsigned int)lowfd, ~0U, 0U) == 0) {
        return;
    }
#elif defined(__FreeBSD__)
    /* FreeBSD has closefrom(2) since 8.0, well before our 12.2 floor. Other
     * BSDs and macOS take the portable loop below. */
    closefrom(lowfd);
    return;
#endif
    /* Portable fallback (macOS has neither call): close(2) on an unused fd is
     * harmless (EBADF). Cap the sweep — sysconf can report "unlimited" or a
     * raised RLIMIT_NOFILE in the millions, and this runs on every spawn. */
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 65536) {
        maxfd = 65536;
    }
    for (long fd = lowfd; fd < maxfd; fd++) {
        (void)close((int)fd);
    }
}

int run_argv_real(const char *const argv[], const run_opts_t *opts, run_result_t *result) {
    run_opts_t no_opts;
    run_result_t local;
    memset(&no_opts, 0, sizeof(no_opts));
    if (!opts) opts = &no_opts;
    if (!result) result = &local;
    result->exit_code = -1;
    result->term_signal = 0;
    result->spawned = false;
    result->out_len = 0;
    result->out_truncated = false;

    if (!argv || !argv[0]) {
        set_error(ERR_INVALID_ARGS, "run_argv: empty argv");
        return -1;
    }

    /* PS-1/PS-2: pin the helper to an absolute path resolved through the
     * sanitized PATH walk in find_command_path() and exec exactly that path
     * with execv() below. execvp()'s own PATH search would happily pick a
     * shadowing "git"/"ssh-add" out of a relative or world-writable PATH
     * entry — and since `gitswitch resume` runs from every interactive shell
     * startup, that is arbitrary code execution with the user's keys in
     * scope. Resolving in the parent also yields a real error message instead
     * of a bare 127. */
    char exec_path[MAX_PATH_LEN];
    if (find_command_path(argv[0], exec_path, sizeof(exec_path)) != 0) {
        set_error(ERR_SYSTEM_CALL,
                  "run_argv: '%s' not found in any trusted PATH directory", argv[0]);
        return -1;
    }

    bool want_in = (opts->input != NULL);
    bool want_out = (opts->out && opts->out_size > 0);
    if (want_out) opts->out[0] = '\0';

    int in_pipe[2] = {-1, -1};
    int out_pipe[2] = {-1, -1};
    if (want_in && pipe(in_pipe) != 0) {
        set_system_error(ERR_SYSTEM_CALL, "pipe() failed");
        return -1;
    }
    if (want_out && pipe(out_pipe) != 0) {
        set_system_error(ERR_SYSTEM_CALL, "pipe() failed");
        if (want_in) { close(in_pipe[0]); close(in_pipe[1]); }
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        set_system_error(ERR_SYSTEM_CALL, "fork() failed");
        if (want_in) { close(in_pipe[0]); close(in_pipe[1]); }
        if (want_out) { close(out_pipe[0]); close(out_pipe[1]); }
        return -1;
    }

    if (pid == 0) {
        /* ---- child ---- */
        int devnull = open("/dev/null", O_RDWR);
        if (want_in) { dup2(in_pipe[0], STDIN_FILENO); }
        else if (devnull >= 0) { dup2(devnull, STDIN_FILENO); }
        if (want_out) { dup2(out_pipe[1], STDOUT_FILENO); }
        else if (devnull >= 0) { dup2(devnull, STDOUT_FILENO); }
        if (opts->merge_stderr) { dup2(STDOUT_FILENO, STDERR_FILENO); }
        else if (opts->stderr_to_devnull && devnull >= 0) { dup2(devnull, STDERR_FILENO); }

        if (in_pipe[0] >= 0) close(in_pipe[0]);
        if (in_pipe[1] >= 0) close(in_pipe[1]);
        if (out_pipe[0] >= 0) close(out_pipe[0]);
        if (out_pipe[1] >= 0) close(out_pipe[1]);
        if (devnull >= 0) close(devnull);

        /* fd-CLOEXEC: the explicit closes above only cover our own pipes;
         * sweep everything else the parent had open so the child starts with
         * just stdin/stdout/stderr. Nothing in this codebase intentionally
         * hands an fd to a child (SSH_AUTH_SOCK etc. are paths, not fds). */
        child_close_fds_from(3);

        if (opts->extra_env) {
            for (size_t i = 0; opts->extra_env[i]; i++) {
                const char *e = opts->extra_env[i];
                const char *eq = strchr(e, '=');
                if (eq) {
                    char key[256];
                    size_t klen = (size_t)(eq - e);
                    if (klen < sizeof(key)) {
                        memcpy(key, e, klen);
                        key[klen] = '\0';
                        setenv(key, eq + 1, 1);
                    }
                }
            }
        }

        /* execv, not execvp: the path was pinned pre-fork; re-searching PATH
         * here would reopen the PS-1 window between resolve and exec. */
        execv(exec_path, (char *const *)argv);
        _exit(127); /* exec failed (e.g. binary vanished after resolution) */
    }

    /* ---- parent ---- */
    result->spawned = true;
    if (want_in) close(in_pipe[0]);
    if (want_out) close(out_pipe[1]);
    void (*old_sigpipe)(int) = signal(SIGPIPE, SIG_IGN);

    int infd = want_in ? in_pipe[1] : -1;
    int outfd = want_out ? out_pipe[0] : -1;
    size_t in_off = 0, out_off = 0;
    /* Function-scope (not loop-scope) so it can be scrubbed after the loop:
     * captured child stdout transits this buffer, and for the GPG secret-key
     * export that is unencrypted private-key material — the caller scrubs its
     * own copy, but these bytes would otherwise stay resident in this frame
     * after return (AR-02 #25). */
    char rdbuf[4096];
    if (infd >= 0) set_nonblock(infd);
    if (outfd >= 0) set_nonblock(outfd);

    while (infd >= 0 || outfd >= 0) {
        struct pollfd pfds[2];
        int n = 0, in_idx = -1, out_idx = -1;
        if (infd >= 0) { pfds[n].fd = infd; pfds[n].events = POLLOUT; in_idx = n++; }
        if (outfd >= 0) { pfds[n].fd = outfd; pfds[n].events = POLLIN; out_idx = n++; }

        if (poll(pfds, (nfds_t)n, -1) < 0) {
            if (errno == EINTR) continue;
            /* Close both pipe ends before bailing: leaving infd open means a
             * child reading stdin (e.g. `gpg --import`) never sees EOF, and
             * the waitpid() below would then block forever. Closing also lets
             * a child blocked writing a full pipe get SIGPIPE and exit. */
            if (infd >= 0) { close(infd); infd = -1; }
            if (outfd >= 0) { close(outfd); outfd = -1; }
            break;
        }

        if (in_idx >= 0 && (pfds[in_idx].revents & (POLLOUT | POLLERR | POLLHUP))) {
            if (pfds[in_idx].revents & (POLLERR | POLLHUP)) {
                close(infd); infd = -1;
            } else {
                ssize_t w = write(infd, opts->input + in_off, opts->input_len - in_off);
                if (w > 0) {
                    in_off += (size_t)w;
                    if (in_off >= opts->input_len) { close(infd); infd = -1; }
                } else if (w < 0 && errno != EAGAIN && errno != EINTR) {
                    close(infd); infd = -1;
                }
            }
        }

        if (out_idx >= 0 && (pfds[out_idx].revents & (POLLIN | POLLERR | POLLHUP))) {
            ssize_t r = read(outfd, rdbuf, sizeof(rdbuf));
            if (r > 0) {
                size_t cp = 0;
                if (out_off < opts->out_size - 1) {
                    size_t space = opts->out_size - 1 - out_off;
                    cp = ((size_t)r < space) ? (size_t)r : space;
                    memcpy(opts->out + out_off, rdbuf, cp);
                    out_off += cp;
                }
                /* Bytes beyond the capture buffer are still drained (so the
                 * child never blocks) but LOST — record that, so callers that
                 * feed `out` onward can refuse the incomplete copy instead of
                 * silently processing corrupt data (AR-02 #4). */
                if (cp < (size_t)r) {
                    result->out_truncated = true;
                }
            } else if (r == 0) {
                close(outfd); outfd = -1;
            } else if (r < 0 && errno != EAGAIN && errno != EINTR) {
                close(outfd); outfd = -1;
            }
        }
    }
    if (want_out) {
        opts->out[out_off] = '\0';
        /* Drop the transit copy of the child's output (AR-02 #25). */
        secure_zero_memory(rdbuf, sizeof(rdbuf));
    }
    result->out_len = out_off;

    int status = 0;
    pid_t w;
    do { w = waitpid(pid, &status, 0); } while (w < 0 && errno == EINTR);
    signal(SIGPIPE, old_sigpipe);

    if (w < 0) {
        set_system_error(ERR_SYSTEM_CALL, "waitpid() failed");
        return -1;
    }
    if (WIFEXITED(status)) {
        result->exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        result->term_signal = WTERMSIG(status);
        result->exit_code = -1;
    }
    return (result->spawned && result->exit_code == 0) ? 0 : -1;
}

static command_runner_fn g_runner = run_argv_real;

command_runner_fn run_set_runner(command_runner_fn fn) {
    command_runner_fn prev = g_runner;
    g_runner = fn ? fn : run_argv_real;
    return prev;
}

int run_argv(const char *const argv[], const run_opts_t *opts, run_result_t *result) {
    return g_runner(argv, opts, result);
}

/* PS-1/PS-2 PATH supply-chain defense: every trusted helper (git, gpg,
 * ssh-add, ssh-agent, gpgconf, ...) is resolved through these checks before it
 * is executed, and `gitswitch resume` runs from every interactive shell
 * startup — so a shadowing binary in a hostile PATH entry would otherwise run
 * automatically with the user's keys in scope.
 *
 * A directory may supply an executable only if it is an absolute path to a
 * real directory that is not world-writable. Relative entries (".", "", "bin")
 * resolve against the CWD — inside a freshly cloned repo that is attacker
 * territory. World-writable dirs are rejected even with the sticky bit set:
 * sticky only stops deleting other users' files, anyone can still CREATE a
 * shadowing "git" there. User-owned prefixes like ~/.local/bin, Homebrew's
 * /opt/homebrew/bin, or Nix profiles are 0755-or-tighter and keep working. */
static bool exec_dir_is_trusted(const char *dir) {
    struct stat st;

    if (dir[0] != '/') {
        return false;
    }
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        return false;
    }
    if (st.st_mode & S_IWOTH) {
        return false;
    }
    return true;
}

/* The resolved binary itself must be a regular file (access(X_OK) alone would
 * happily "find" a directory named git) and not world-writable — a o+w binary
 * in an otherwise sane directory is just as replaceable as a o+w directory. */
static bool exec_candidate_is_trusted(const char *path) {
    struct stat st;

    if (stat(path, &st) != 0) {
        return false;
    }
    if (!S_ISREG(st.st_mode) || (st.st_mode & S_IWOTH)) {
        return false;
    }
    return access(path, X_OK) == 0;
}

/* Process-lifetime memo for find_command_path (AR-02 #24): one switch
 * resolves the same handful of helpers (git, ssh-add, gpg, ...) ~16 times —
 * init-time probes plus every run_argv spawn — and each resolution walks the
 * trusted-PATH at ~3 syscalls per entry, ~550 redundant stat/access calls per
 * switch. Sub-millisecond warm, but each stat is a network round trip on cold
 * NFS/autofs PATH entries. Keyed on the exact PATH string so an intra-process
 * PATH change (tests do this) drops the cache. Positive results only: a miss
 * usually aborts the command anyway, and caching one could outlive a
 * transient failure. Single-threaded, like the other utils caches. */
#define CMD_MEMO_SLOTS 16
#define CMD_MEMO_NAME_LEN 32
typedef struct {
    char name[CMD_MEMO_NAME_LEN];
    char path[MAX_PATH_LEN];
} cmd_memo_slot_t;
static cmd_memo_slot_t g_cmd_memo[CMD_MEMO_SLOTS];
static size_t g_cmd_memo_used = 0;
static char *g_cmd_memo_pathenv = NULL;

int find_command_path(const char *name, char *buf, size_t size) {
    const char *path_env;
    const char *p;

    if (!name || !buf || size == 0 || name[0] == '\0') {
        return -1;
    }

    /* A name containing a slash is used directly, no PATH search — but only
     * if absolute ("./git" or "bin/git" would resolve against the CWD, which
     * is exactly the hole this function closes) and only out of a trusted
     * directory, same rules as a PATH entry. */
    if (strchr(name, '/')) {
        char dir[MAX_PATH_LEN];
        const char *slash = strrchr(name, '/');
        /* Keep the leading '/' when the binary sits directly under the root. */
        size_t dirlen = (slash == name) ? 1 : (size_t)(slash - name);

        if (name[0] != '/' || dirlen >= sizeof(dir)) {
            return -1;
        }
        memcpy(dir, name, dirlen);
        dir[dirlen] = '\0';

        if (!exec_dir_is_trusted(dir) || !exec_candidate_is_trusted(name)) {
            return -1;
        }
        if (safe_strncpy(buf, name, size) != 0) return -1;
        return 0;
    }

    path_env = getenv("PATH");
    if (!path_env || !*path_env) {
        path_env = "/usr/local/bin:/usr/bin:/bin";
    }

    /* Memo lookup, valid only while PATH is byte-identical to the PATH the
     * cache was filled under. Staleness within one short-lived process (a
     * memoized binary deleted mid-run) is the same resolve-to-exec TOCTOU
     * window that already exists for a single call. */
    if (!g_cmd_memo_pathenv || strcmp(g_cmd_memo_pathenv, path_env) != 0) {
        free(g_cmd_memo_pathenv);
        g_cmd_memo_pathenv = strdup(path_env);
        g_cmd_memo_used = 0;
    } else {
        for (size_t i = 0; i < g_cmd_memo_used; i++) {
            if (strcmp(g_cmd_memo[i].name, name) == 0) {
                return safe_strncpy(buf, g_cmd_memo[i].path, size);
            }
        }
    }

    /* Walk colon-separated PATH entries, testing <dir>/<name> in each trusted
     * directory. Untrusted entries are skipped, not fatal: a stray "." or o+w
     * dir in PATH must not hide the real /usr/bin/git behind it. An empty
     * entry historically means the CWD — refused, not honored. */
    p = path_env;
    while (*p) {
        const char *colon = strchr(p, ':');
        size_t dirlen = colon ? (size_t)(colon - p) : strlen(p);
        char dir[MAX_PATH_LEN];
        char candidate[MAX_PATH_LEN];

        if (dirlen > 0 && dirlen < sizeof(dir) &&
            dirlen + 1 + strlen(name) + 1 <= sizeof(candidate)) {
            memcpy(dir, p, dirlen);
            dir[dirlen] = '\0';
            memcpy(candidate, dir, dirlen);
            candidate[dirlen] = '/';
            strcpy(candidate + dirlen + 1, name);
            if (exec_dir_is_trusted(dir) && exec_candidate_is_trusted(candidate)) {
                if (g_cmd_memo_pathenv && g_cmd_memo_used < CMD_MEMO_SLOTS &&
                    strlen(name) < CMD_MEMO_NAME_LEN) {
                    cmd_memo_slot_t *slot = &g_cmd_memo[g_cmd_memo_used];
                    if (safe_strncpy(slot->name, name, sizeof(slot->name)) == 0 &&
                        safe_strncpy(slot->path, candidate, sizeof(slot->path)) == 0) {
                        g_cmd_memo_used++;
                    }
                }
                if (safe_strncpy(buf, candidate, size) != 0) return -1;
                return 0;
            }
        }

        if (!colon) break;
        p = colon + 1;
    }
    return -1;
}

bool command_exists(const char *command) {
    char path[MAX_PATH_LEN];
    if (!command) return false;
    return find_command_path(command, path, sizeof(path)) == 0;
}

bool process_is_running(pid_t pid) {
    if (pid <= 0) return false;
    return kill(pid, 0) == 0;
}

/* Environment utilities */

int get_env_var(const char *name, char *buffer, size_t buffer_size) {
    const char *value;
    
    if (!name || !buffer || buffer_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to get_env_var");
        return -1;
    }
    
    value = getenv(name);
    if (!value) {
        buffer[0] = '\0';
        return 1; /* Not an error, just not found */
    }
    
    if (strlen(value) >= buffer_size) {
        set_error(ERR_INVALID_ARGS, "Environment variable value too long");
        return -1;
    }
    
    strcpy(buffer, value);
    return 0;
}

int set_env_var(const char *name, const char *value, bool overwrite) {
    if (!name || !value) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to set_env_var");
        return -1;
    }
    
    if (setenv(name, value, overwrite ? 1 : 0) != 0) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to set environment variable: %s", name);
        return -1;
    }
    
    return 0;
}

int unset_env_var(const char *name) {
    if (!name) {
        set_error(ERR_INVALID_ARGS, "NULL name to unset_env_var");
        return -1;
    }
    
    if (unsetenv(name) != 0) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to unset environment variable: %s", name);
        return -1;
    }
    
    return 0;
}

/* Validation utilities */

bool validate_email(const char *email) {
    /* Compile the constant pattern once and reuse it. This is called 2N+ times
     * per config load (schema + security validation per account, plus on
     * switch), on the every-shell init/resume path, so recompiling the same
     * regex each time was pure waste. Single-threaded, so a static cache is safe. */
    static regex_t regex;
    static bool compiled = false;

    /* >= not >: account_t.email[MAX_EMAIL_LEN] stores at most MAX_EMAIL_LEN-1
     * chars plus the NUL, so an exactly-MAX_EMAIL_LEN-char address would pass
     * here only to have the copy into the account fail (AR-03 L1). Matches
     * validate_name's bound. */
    if (!email || strlen(email) >= MAX_EMAIL_LEN) {
        return false;
    }

    if (!compiled) {
        /* Basic email regex - not RFC compliant but good enough for git configs */
        const char *pattern = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";
        if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
            return false;
        }
        compiled = true;
    }

    return regexec(&regex, email, 0, NULL, 0) == 0;
}

bool validate_name(const char *name) {
    if (!name || strlen(name) == 0 || strlen(name) >= MAX_NAME_LEN) {
        return false;
    }

    /* The account name doubles as a filesystem path component (the isolated
     * GNUPGHOME <base>/<name> and the ssh-agent.<name>.sock socket) as well as
     * the git user.name. So it must stay a single, safe path component while
     * still allowing ordinary display names with spaces and parentheses
     * ("Jane Doe (Work)"). Reject path separators and traversal, control
     * characters, and a leading '-'/'.' (option-like / hidden / '..'). */
    if (name[0] == '-' || name[0] == '.') {
        return false;
    }
    if (strstr(name, "..") != NULL) {
        return false;
    }
    for (const char *p = name; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '/' || c == '\\' || c < 0x20 || c == 0x7f) {
            return false;
        }
    }

    /* Reserve "current": the per-account GNUPGHOME is <base>/<name>, and the
     * stable GPG symlink the shell integration exports is <base>/current. An
     * account literally named "current" would create a real directory there,
     * so the symlink could never be installed/retargeted and every other
     * account's switch would silently keep pointing GNUPGHOME at this one. */
    if (strcasecmp(name, "current") == 0) {
        return false;
    }

    /* Name should contain at least one non-whitespace character */
    for (const char *p = name; *p; p++) {
        if (!isspace((unsigned char)*p)) {
            return true;
        }
    }

    return false;
}

/* ssh-1 (shared; moved from git_ops.c for AR-02 #10): the account SSH key
 * path ends up in two security-sensitive sinks, and EACH sink must apply this
 * check itself rather than assume the other (or the TOML-load sanitizer)
 * already did:
 *
 *  1. core.sshCommand — the ONE git config value git hands to /bin/sh. The
 *     path is wrapped in single quotes; inside '...' the shell treats every
 *     byte literally EXCEPT a single quote, which ends the quote and lets a
 *     crafted path smuggle extra ssh options (-oProxyCommand=..., i.e.
 *     arbitrary code on the next fetch). Guarded in git_configure_ssh.
 *  2. ~/.ssh/config — the same path is emitted as an "IdentityFile <path>"
 *     line by the host-alias support. There, a \n or \r starts a new line,
 *     i.e. injects an arbitrary ssh_config keyword (ProxyCommand again), and
 *     a quote breaks the directive's tokenization. Guarded in
 *     ssh_configure_host_alias.
 *
 * So reject both quote characters and every control byte (\n and \r included)
 * up front, before the path is probed or written anywhere. A real SSH key
 * path never needs any of these. */
bool is_safe_ssh_key_path(const char *path) {
    for (const char *p = path; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c == 0x7f || c == '\'' || c == '"') {
            return false;
        }
    }
    return true;
}

/* Shared strict UTF-8 decoding and terminal-safety policy — moved here from
 * config.c so the TOML parser's raw-buffer charset gate can apply the same
 * rules instead of rejecting every byte >= 0x80 (AR-02 #6). See utils.h for
 * the full rationale. */
size_t utf8_decode(const unsigned char *s, uint32_t *cp_out) {
    unsigned char b0 = s[0];

    if (b0 < 0x80) {
        *cp_out = b0;
        return 1;
    }
    if (b0 >= 0xC2 && b0 <= 0xDF) {
        if ((s[1] & 0xC0) != 0x80) return 0;
        *cp_out = ((uint32_t)(b0 & 0x1F) << 6) | (s[1] & 0x3F);
        return 2;
    }
    if (b0 >= 0xE0 && b0 <= 0xEF) {
        if ((s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80) return 0;
        if (b0 == 0xE0 && s[1] < 0xA0) return 0;              /* overlong */
        if (b0 == 0xED && s[1] >= 0xA0) return 0;             /* surrogate */
        *cp_out = ((uint32_t)(b0 & 0x0F) << 12) |
                  ((uint32_t)(s[1] & 0x3F) << 6) | (s[2] & 0x3F);
        return 3;
    }
    if (b0 >= 0xF0 && b0 <= 0xF4) {
        if ((s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80 || (s[3] & 0xC0) != 0x80) return 0;
        if (b0 == 0xF0 && s[1] < 0x90) return 0;              /* overlong */
        if (b0 == 0xF4 && s[1] > 0x8F) return 0;              /* > U+10FFFF */
        *cp_out = ((uint32_t)(b0 & 0x07) << 18) | ((uint32_t)(s[1] & 0x3F) << 12) |
                  ((uint32_t)(s[2] & 0x3F) << 6) | (s[3] & 0x3F);
        return 4;
    }
    return 0; /* 0x80-0xC1 lead (bare continuation/overlong) or 0xF5+ */
}

bool tty_safe_codepoint(uint32_t cp) {
    return cp >= 0x20 && cp != 0x7F && !(cp >= 0x80 && cp <= 0x9F);
}

bool validate_key_id(const char *key_id) {
    if (!key_id || strlen(key_id) == 0 || strlen(key_id) >= MAX_KEY_ID_LEN) {
        return false;
    }

    /* Accept the common "0x" prefix that `gpg -k` and keyservers display —
     * gpg itself accepts a 0x-prefixed key id, so rejecting it only tripped up
     * users pasting the id exactly as shown. The remainder must be hex. */
    const char *p = key_id;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
    }
    if (*p == '\0') {
        return false; /* "0x" with no digits */
    }
    for (; *p; p++) {
        if (!isxdigit((unsigned char)*p)) {
            return false;
        }
    }

    return true;
}

bool validate_file_path(const char *path) {
    char expanded[MAX_PATH_LEN];
    
    if (!path || strlen(path) == 0 || strlen(path) >= MAX_PATH_LEN) {
        return false;
    }
    
    /* Expand path and check if it exists */
    if (expand_path(path, expanded, sizeof(expanded)) != 0) {
        return false;
    }
    
    return path_exists(expanded);
}

/* Security utilities */

void secure_zero_memory(void *ptr, size_t size) {
    if (!ptr || size == 0) return;
    
    /* Use explicit_bzero if available, otherwise volatile memset */
#ifdef __GLIBC__
    explicit_bzero(ptr, size);
#else
    volatile unsigned char *p = ptr;
    while (size--) {
        *p++ = 0;
    }
#endif
}

int generate_random_string(char *buffer, size_t buffer_size, const char *charset) {
    size_t charset_len;
    size_t i;
    FILE *urandom;
    
    if (!buffer || buffer_size == 0 || !charset) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to generate_random_string");
        return -1;
    }
    
    charset_len = strlen(charset);
    if (charset_len == 0) {
        set_error(ERR_INVALID_ARGS, "Empty charset");
        return -1;
    }
    
    urandom = fopen("/dev/urandom", "rbe");
    if (!urandom) {
        set_system_error(ERR_FILE_IO, "Failed to open /dev/urandom");
        return -1;
    }
    
    for (i = 0; i < buffer_size - 1; i++) {
        unsigned char rand_byte;
        if (fread(&rand_byte, 1, 1, urandom) != 1) {
            set_system_error(ERR_FILE_IO, "Failed to read random data");
            fclose(urandom);
            return -1;
        }
        buffer[i] = charset[rand_byte % charset_len];
    }
    
    buffer[buffer_size - 1] = '\0';
    fclose(urandom);
    
    return 0;
}

bool check_file_permissions_safe(const char *file_path, mode_t expected_mode) {
    mode_t actual_mode;
    
    if (!file_path) return false;
    
    if (get_file_permissions(file_path, &actual_mode) != 0) {
        return false;
    }
    
    /* Check if permissions are as expected or more restrictive */
    return (actual_mode & 07777) == expected_mode;
}

/* Configuration utilities */

int get_config_directory(char *config_dir, size_t dir_size) {
    char home[MAX_PATH_LEN];
    
    if (!config_dir || dir_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to get_config_directory");
        return -1;
    }
    
    if (get_home_directory(home, sizeof(home)) != 0) {
        return -1;
    }
    
    if (snprintf(config_dir, dir_size, "%s/%s", home, DEFAULT_CONFIG_DIR) >= (int)dir_size) {
        set_error(ERR_INVALID_ARGS, "Config directory path too long");
        return -1;
    }
    
    return 0;
}

int ensure_config_directory_exists(void) {
    char config_dir[MAX_PATH_LEN];
    
    if (get_config_directory(config_dir, sizeof(config_dir)) != 0) {
        return -1;
    }
    
    if (!is_directory(config_dir)) {
        if (create_directory_recursive(config_dir, PERM_USER_RWX) != 0) {
            return -1;
        }
        log_info("Created config directory: %s", config_dir);
    }
    
    return 0;
}

/* Terminal utilities */

bool is_terminal(int fd) {
    return isatty(fd) == 1;
}

int get_terminal_size(int *width, int *height) {
    struct winsize ws;

    if (!width || !height) {
        set_error(ERR_INVALID_ARGS, "NULL arguments to get_terminal_size");
        return -1;
    }

    /* Skip the ioctl when stdout isn't a terminal (piped, redirected,
     * command-substituted). Return failure silently so callers fall back to
     * their default width without spamming stderr on every invocation. */
    if (!isatty(STDOUT_FILENO)) {
        return -1;
    }

    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to get terminal size");
        return -1;
    }

    *width = ws.ws_col;
    *height = ws.ws_row;

    return 0;
}

void disable_echo(void) {
    struct termios new_termios;
    
    if (g_echo_disabled) return;
    
    if (tcgetattr(STDIN_FILENO, &g_original_termios) != 0) {
        return; /* Can't save original, don't disable echo */
    }
    
    new_termios = g_original_termios;
    new_termios.c_lflag &= ~ECHO;
    
    if (tcsetattr(STDIN_FILENO, TCSANOW, &new_termios) == 0) {
        g_echo_disabled = true;
    }
}

void enable_echo(void) {
    if (!g_echo_disabled) return;
    
    tcsetattr(STDIN_FILENO, TCSANOW, &g_original_termios);
    g_echo_disabled = false;
}

/* Time utilities */

void get_current_time_string(char *buffer, size_t buffer_size) {
    time_t now;
    struct tm *tm_info;
    
    if (!buffer || buffer_size == 0) return;
    
    time(&now);
    tm_info = localtime(&now);
    
    if (tm_info) {
        strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S", tm_info);
    } else {
        strncpy(buffer, "UNKNOWN", buffer_size - 1);
        buffer[buffer_size - 1] = '\0';
    }
}

void get_timestamp_string(char *buffer, size_t buffer_size) {
    time_t now;
    
    if (!buffer || buffer_size == 0) return;
    
    time(&now);
    snprintf(buffer, buffer_size, "%ld", (long)now);
}

bool is_timestamp_expired(time_t timestamp, int max_age_seconds) {
    time_t now;
    time(&now);
    return (now - timestamp) > max_age_seconds;
}

/* Comparison utilities */

int compare_strings(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

int compare_accounts_by_id(const void *a, const void *b) {
    const account_t *acc_a = (const account_t *)a;
    const account_t *acc_b = (const account_t *)b;
    
    if (acc_a->id < acc_b->id) return -1;
    if (acc_a->id > acc_b->id) return 1;
    return 0;
}

int compare_accounts_by_name(const void *a, const void *b) {
    const account_t *acc_a = (const account_t *)a;
    const account_t *acc_b = (const account_t *)b;
    
    return strcmp(acc_a->name, acc_b->name);
}

/* Array utilities */

void sort_accounts(account_t *accounts, size_t count, 
                   int (*compare)(const void *, const void *)) {
    if (accounts && count > 1 && compare) {
        qsort(accounts, count, sizeof(account_t), compare);
    }
}

account_t *find_account_in_array(account_t *accounts, size_t count, 
                                 const char *identifier) {
    if (!accounts || !identifier || count == 0) {
        return NULL;
    }
    
    /* Try numeric ID first */
    char *endptr;
    unsigned long id = strtoul(identifier, &endptr, 10);
    if (*endptr == '\0') {
        /* It's a number - search by ID */
        for (size_t i = 0; i < count; i++) {
            if (accounts[i].id == (uint32_t)id) {
                return &accounts[i];
            }
        }
    }
    
    /* Search by name or description */
    for (size_t i = 0; i < count; i++) {
        if (strstr(accounts[i].name, identifier) ||
            strstr(accounts[i].description, identifier) ||
            strcmp(accounts[i].email, identifier) == 0) {
            return &accounts[i];
        }
    }
    
    return NULL;
}

/* Memory utilities */

void *safe_memset(void *ptr, int value, size_t size) {
    if (!ptr || size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to safe_memset");
        return NULL;
    }
    
    return memset(ptr, value, size);
}

void *safe_memcpy(void *dest, const void *src, size_t size) {
    if (!dest || !src || size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to safe_memcpy");
        return NULL;
    }
    
    return memcpy(dest, src, size);
}

int safe_mlock(void *ptr, size_t size) {
#if defined(__linux__)
    if (!ptr || size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to safe_mlock");
        return -1;
    }
    
    if (mlock(ptr, size) != 0) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to lock memory");
        return -1;
    }
    
    return 0;
#else
    /* Not supported on this platform */
    (void)ptr;
    (void)size;
    return 0;
#endif
}

int safe_munlock(void *ptr, size_t size) {
#if defined(__linux__)
    if (!ptr || size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to safe_munlock");
        return -1;
    }
    
    if (munlock(ptr, size) != 0) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to unlock memory");
        return -1;
    }
    
    return 0;
#else
    /* Not supported on this platform */
    (void)ptr;
    (void)size;
    return 0;
#endif
}

/* Debug utilities */

void dump_account(const account_t *account) {
    if (!account) {
        log_debug("Account: NULL");
        return;
    }
    
    log_debug("Account dump:");
    log_debug("  ID: %u", account->id);
    log_debug("  Name: %s", account->name);
    log_debug("  Email: %s", account->email);
    log_debug("  Description: %s", account->description);
    log_debug("  SSH enabled: %s", account->ssh_enabled ? "yes" : "no");
    log_debug("  SSH key: %s", account->ssh_key_path);
    log_debug("  GPG enabled: %s", account->gpg_enabled ? "yes" : "no");
    log_debug("  GPG signing: %s", account->gpg_signing_enabled ? "yes" : "no");
    log_debug("  GPG key: %s", account->gpg_key_id);
}

void dump_config(const config_t *config) {
    if (!config) {
        log_debug("Config: NULL");
        return;
    }
    
    log_debug("Config dump:");
    log_debug("  Default scope: %d", config->default_scope);
    log_debug("  Config path: %s", config->config_path);
    log_debug("  Verbose: %s", config->verbose ? "yes" : "no");
    log_debug("  Dry run: %s", config->dry_run ? "yes" : "no");
    log_debug("  Color output: %s", config->color_output ? "yes" : "no");
}

void dump_context(const gitswitch_ctx_t *ctx) {
    if (!ctx) {
        log_debug("Context: NULL");
        return;
    }
    
    log_debug("Context dump:");
    log_debug("  Account count: %zu", ctx->account_count);
    log_debug("  Current account: %s", 
              ctx->current_account ? ctx->current_account->name : "none");
    
    dump_config(&ctx->config);
    
    for (size_t i = 0; i < ctx->account_count; i++) {
        dump_account(&ctx->accounts[i]);
    }
}