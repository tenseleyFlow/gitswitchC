/* AR-04 account lifecycle regressions: active-edit refusal, remove teardown,
 * and exact current-account detection for names containing ".sock". */

#include "test.h"
#include "accounts.h"
#include "config.h"
#include "error.h"
#include "git_ops.h"
#include "publication.h"
#include "gitswitch.h"
#include "ssh_manager.h"
#include "utils.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static char g_bin[PATH_MAX];
static char g_self[PATH_MAX];

#define LIFE_WORK_INCARNATION \
    "1111111111111111111111111111111111111111111111111111111111111111"
#define LIFE_OTHER_INCARNATION \
    "2222222222222222222222222222222222222222222222222222222222222222"

int gitswitch_cli_main(int argc, char **argv);

static int install_live_current_socket(const char *runtime,
                                       const char *account_name);

static int resolve_binary_and_self(const char *argv0) {
    const char *bin = getenv("GITSWITCH_BIN");

    if (!bin || !*bin) bin = "build/bin/gitswitch";
    if (!realpath(bin, g_bin) || access(g_bin, X_OK) != 0) {
        fprintf(stderr, "test_ar04_lifecycle: executable not found at %s\n", bin);
        return -1;
    }
    if (!argv0 || !realpath(argv0, g_self) || access(g_self, X_OK) != 0) {
        fprintf(stderr, "test_ar04_lifecycle: cannot resolve self helper\n");
        return -1;
    }
    return 0;
}

static int make_temp_dir(char *buf, size_t size) {
    char canonical[PATH_MAX];
    size_t length;

    if (snprintf(buf, size, "/tmp/gitswitch-ar04-life-XXXXXX") < 0 ||
        !ts_mkdtemp(buf)) {
        return -1;
    }

    /* Darwin exposes /tmp through the /private/tmp filesystem alias.  Keep
     * fixture paths in the same physical namespace used by the production
     * runtime safety walk so socket ownership and symlink targets compare
     * consistently across platforms. */
    if (!realpath(buf, canonical)) return -1;
    length = strlen(canonical);
    if (length >= size) return -1;
    memcpy(buf, canonical, length + 1U);
    return 0;
}

static void remove_tree(const char *path) {
    char cmd[2048];
    int status;

    if (!path || !*path || strchr(path, '\'')) return;
    if (snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path) < 0) return;
    status = system(cmd);
    (void)status;
}

static int mkdir_private(const char *path) {
    if (mkdir(path, 0700) != 0 && errno != EEXIST) return -1;
    return chmod(path, 0700);
}

static int life_join_path(char *dest, size_t size, const char *base,
                          const char *suffix) {
    size_t base_len = strlen(base);
    size_t suffix_len = strlen(suffix);

    if (base_len >= size || suffix_len > size - base_len - 1) {
        return -1;
    }
    memcpy(dest, base, base_len);
    memcpy(dest + base_len, suffix, suffix_len + 1);
    return 0;
}

static int directory_has_entry_prefix(const char *path, const char *prefix) {
    DIR *directory;
    struct dirent *entry;
    size_t prefix_length;
    int result = 0;

    if (!path || !prefix) return -1;
    directory = opendir(path);
    if (!directory) return -1;
    prefix_length = strlen(prefix);
    for (;;) {
        errno = 0;
        entry = readdir(directory);
        if (!entry) {
            if (errno != 0) result = -1;
            break;
        }
        if (strncmp(entry->d_name, prefix, prefix_length) == 0) {
            result = 1;
            break;
        }
    }
    if (closedir(directory) != 0) result = -1;
    return result;
}

static int write_text(const char *path, const char *text, mode_t mode) {
    FILE *f = fopen(path, "w");

    if (!f) return -1;
    if (fputs(text, f) == EOF || fclose(f) != 0) return -1;
    return chmod(path, mode);
}

static int write_live_agent_record(const char *runtime, const char *name,
                                   pid_t pid) {
    char dir[PATH_MAX];
    ssh_agent_record_t record = {.pid = pid};
    int dir_fd;
    int rc;

    if ((size_t)snprintf(dir, sizeof(dir), "%s/gitswitch-ssh", runtime) >=
            sizeof(dir) ||
        ssh_manager_test_capture_process_generation(
            pid, &record.generation) != 0) {
        return -1;
    }
    dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0) return -1;
    rc = ssh_manager_test_write_pid_sidecar(dir_fd, name, &record);
    if (close(dir_fd) != 0) rc = -1;
    return rc;
}

static void stop_external_process(pid_t pid) {
    const struct timespec delay = {.tv_sec = 0, .tv_nsec = 10000000L};
    int attempt;

    if (pid <= 1) return;
    errno = 0;
    if (kill(pid, 0) != 0 && errno == ESRCH) return;

    (void)kill(pid, SIGTERM);
    for (attempt = 0; attempt < 50; ++attempt) {
        errno = 0;
        if (kill(pid, 0) != 0 && errno == ESRCH) return;
        (void)nanosleep(&delay, NULL);
    }

    (void)kill(pid, SIGKILL);
    for (attempt = 0; attempt < 50; ++attempt) {
        errno = 0;
        if (kill(pid, 0) != 0 && errno == ESRCH) return;
        (void)nanosleep(&delay, NULL);
    }
}

static int write_all(int fd, const void *data, size_t length) {
    const unsigned char *cursor = data;
    size_t written = 0U;

    while (written < length) {
        ssize_t result = write(fd, cursor + written, length - written);

        if (result > 0) {
            written += (size_t)result;
        } else if (result < 0 && errno == EINTR) {
            continue;
        } else {
            return -1;
        }
    }
    return 0;
}

static int life_git_config_set(const char *path, const char *key,
                               const char *value) {
    const char *argv[] = {
        "git", "config", "--file", path, "--no-includes",
        "--replace-all", key, value, NULL
    };
    run_result_t run;

    memset(&run, 0, sizeof(run));
    return run_argv_real(argv, NULL, &run);
}

/* M17 fixtures that reach Git retirement carry the same durable authority as
 * a real completed switch: a persisted incarnation plus one exact PUBLISHED
 * destination/generation. Credentialless cases retain only that destination;
 * an SSH-bearing case also stores the exact core.sshCommand and executable
 * generation that a completed switch would have sealed. */
static int seed_global_publication(const char *home, uint32_t account_id,
                                   const char *incarnation,
                                   const char *runtime_needs,
                                   const char *active_account,
                                   const char *ssh_key) {
    static const char git_body[] =
        "[fixture]\n"
        "\tgeneration = lifecycle\n";
    char git_path[1024], state_path[1024], header[512];
    char ssh_command[PUBLICATION_SSH_COMMAND_MAX] = "";
    char ssh_program[MAX_PATH_LEN] = "";
    account_t account;
    publication_record_t record;
    publication_ledger_t ledger;
    unsigned char *tail = NULL;
    size_t tail_length = 0U;
    struct stat st;
    int fd = -1;
    int result = -1;
    int written;

    if (!home || !incarnation || !runtime_needs || !active_account ||
        snprintf(git_path, sizeof(git_path), "%s/.gitconfig", home) < 0 ||
        snprintf(state_path, sizeof(state_path),
                 "%s/.config/gitswitch/.resume-hint", home) < 0) {
        return -1;
    }
    written = snprintf(header, sizeof(header), "%s\nactive=%s\n",
                       runtime_needs, active_account);
    if (written < 0 || (size_t)written >= sizeof(header) ||
        write_text(git_path, git_body, 0600) != 0) {
        return -1;
    }
    if (ssh_key) {
        memset(&account, 0, sizeof(account));
        account.ssh_enabled = true;
        if (safe_strncpy(account.ssh_key_path, ssh_key,
                         sizeof(account.ssh_key_path)) != 0 ||
            git_expected_ssh_command(&account, ssh_command,
                                     sizeof(ssh_command)) != 0 ||
            publication_extract_ssh_program(
                ssh_command, ssh_program, sizeof(ssh_program)) != 0 ||
            life_git_config_set(git_path, GIT_CONFIG_CORE_SSHCOMMAND,
                                ssh_command) != 0) {
            return -1;
        }
    }

    publication_record_init(&record);
    record.account_id = account_id;
    record.scope = PUBLICATION_SCOPE_GLOBAL;
    record.state = PUBLICATION_STATE_PUBLISHED;
    record.capabilities = PUBLICATION_CAP_DESTINATION |
                          PUBLICATION_CAP_POST_GENERATION;
    if (safe_strncpy(record.account_incarnation, incarnation,
                     sizeof(record.account_incarnation)) != 0 ||
        safe_strncpy(record.config_path, git_path,
                     sizeof(record.config_path)) != 0 ||
        stat(home, &st) != 0) {
        return -1;
    }
    publication_identity_from_stat(&record.config_parent, &st);
    if (stat(git_path, &st) != 0) return -1;
    publication_identity_from_stat(&record.post_config, &st);
    if (ssh_key) {
        record.capabilities |= PUBLICATION_CAP_SSH_COMMAND |
                               PUBLICATION_CAP_SSH_PROGRAM;
        if (safe_strncpy(record.ssh_command, ssh_command,
                         sizeof(record.ssh_command)) != 0 ||
            safe_strncpy(record.ssh_program, ssh_program,
                         sizeof(record.ssh_program)) != 0 ||
            stat(ssh_program, &st) != 0) {
            return -1;
        }
        publication_identity_from_stat(&record.ssh_program_identity, &st);
    }
    if (publication_record_validate(&record) != 0) return -1;

    publication_ledger_init(&ledger);
    if (publication_ledger_upsert(&ledger, &record) != 0 ||
        publication_ledger_serialize(&ledger, &tail, &tail_length) != 0) {
        goto cleanup;
    }
    fd = open(state_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0 || write_all(fd, header, (size_t)written) != 0 ||
        write_all(fd, tail, tail_length) != 0 || fsync(fd) != 0 ||
        close(fd) != 0) {
        if (fd >= 0) (void)close(fd);
        fd = -1;
        goto cleanup;
    }
    fd = -1;
    result = 0;

cleanup:
    if (fd >= 0) (void)close(fd);
    if (tail) {
        secure_zero_memory(tail, tail_length);
        free(tail);
    }
    publication_ledger_clear(&ledger);
    return result;
}

static const char *slurp(const char *path, char *buf, size_t size) {
    FILE *f;
    size_t n;

    buf[0] = '\0';
    f = fopen(path, "r");
    if (!f) return buf;
    n = fread(buf, 1, size - 1, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

/* AR-06 F33: -(1000+signal) for a crash/signal-kill, -1 for a system()
 * failure, so abnormal termination never passes as an ordinary nonzero exit. */
static int run_shell(const char *cmd) {
    int status = system(cmd);

    if (status == -1) return -1;
    if (!WIFEXITED(status))
        return WIFSIGNALED(status) ? -(1000 + WTERMSIG(status)) : -1;
    return WEXITSTATUS(status);
}

static int prepare_home(const char *home, const char *config_body) {
    char path[1024];

    snprintf(path, sizeof(path), "%s/.config", home);
    if (mkdir_private(path) != 0) return -1;
    snprintf(path, sizeof(path), "%s/.config/gitswitch", home);
    if (mkdir_private(path) != 0) return -1;
    /* Child CLI invocations pin GNUPGHOME here so prompt validation never
     * depends on the operator's keyring or on whether GNUPGHOME is inherited. */
    snprintf(path, sizeof(path), "%s/.gnupg", home);
    if (mkdir_private(path) != 0) return -1;
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    /* Each seed is a new pre-command generation. Reusing the inode through
     * fopen("w") leaves FreeBSD UFS free to materialize the preceding ctime
     * update after the child has loaded it, which correctly trips the
     * production stale-generation guard. */
    if (unlink(path) != 0 && errno != ENOENT) return -1;
    if (write_text(path, config_body, 0600) != 0) return -1;

    /* Historical active-only files predate the consolidated artifact. Remove
     * state left by an earlier command in this reused HOME so this fixture
     * exercises migration from settings.active_account itself. */
    snprintf(path, sizeof(path), "%s/.config/gitswitch/.resume-hint", home);
    return unlink(path) == 0 || errno == ENOENT ? 0 : -1;
}

static const char *active_work_config(void) {
    return "[settings]\n"
           "default_scope = \"global\"\n"
           "active_account = \"work\"\n"
           "\n"
           "[accounts.1]\n"
           "incarnation = \"" LIFE_WORK_INCARNATION "\"\n"
           "name = \"work\"\n"
           "email = \"old@example.com\"\n"
           "description = \"old description\"\n"
           "preferred_scope = \"global\"\n";
}

/* Resolve and copy host tools only to construct deterministic native test
 * fixtures. Production still performs its complete trust walk on the private
 * copies before execution. This deliberately does not use find_command_path:
 * a package-manager prefix can be safe for the CI operator yet intentionally
 * fail the product's stricter ancestry policy. */
static int find_fixture_executable(const char *name, char *resolved,
                                   size_t resolved_size) {
    const char *path_env = getenv("PATH");
    const char *cursor;

    if (!name || !*name || !resolved || resolved_size == 0 ||
        !path_env || !*path_env || strchr(name, '/')) return -1;

    cursor = path_env;
    while (*cursor) {
        const char *colon = strchr(cursor, ':');
        size_t dir_len = colon ? (size_t)(colon - cursor) : strlen(cursor);
        size_t name_len = strlen(name);
        char candidate[PATH_MAX], canonical[PATH_MAX];
        struct stat st;

        if (dir_len > 0 && cursor[0] == '/' &&
            dir_len + 1 + name_len + 1 <= sizeof(candidate)) {
            memcpy(candidate, cursor, dir_len);
            candidate[dir_len] = '/';
            memcpy(candidate + dir_len + 1, name, name_len + 1);
            if (realpath(candidate, canonical) &&
                stat(canonical, &st) == 0 && S_ISREG(st.st_mode) &&
                access(canonical, R_OK | X_OK) == 0 &&
                strlen(canonical) < resolved_size) {
                memcpy(resolved, canonical, strlen(canonical) + 1);
                return 0;
            }
        }
        if (!colon) break;
        cursor = colon + 1;
    }
    return -1;
}

static int copy_executable(const char *source, const char *destination) {
    unsigned char buffer[16384];
    int source_fd = -1, destination_fd = -1;
    int result = -1;

    source_fd = open(source, O_RDONLY);
    if (source_fd < 0) goto done;
    destination_fd = open(destination, O_WRONLY | O_CREAT | O_EXCL, 0700);
    if (destination_fd < 0) goto done;

    for (;;) {
        ssize_t count = read(source_fd, buffer, sizeof(buffer));
        if (count == 0) break;
        if (count < 0) {
            if (errno == EINTR) continue;
            goto done;
        }
        ssize_t offset = 0;
        while (offset < count) {
            ssize_t written = write(destination_fd, buffer + offset,
                                    (size_t)(count - offset));
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) goto done;
            offset += written;
        }
    }
    if (fchmod(destination_fd, 0700) != 0) goto done;
    result = 0;

done:
    if (source_fd >= 0 && close(source_fd) != 0) result = -1;
    if (destination_fd >= 0 && close(destination_fd) != 0) result = -1;
    if (result != 0) (void)unlink(destination);
    return result;
}

static int generate_fixture_ssh_key(const char *path) {
    char ssh_keygen_path[PATH_MAX];
    const char *argv[] = {
        ssh_keygen_path, "-q", "-t", "ed25519", "-N", "", "-f", path, NULL
    };
    run_opts_t opts;
    run_result_t result;

    if (!path ||
        find_fixture_executable("ssh-keygen", ssh_keygen_path,
                                sizeof(ssh_keygen_path)) != 0) {
        return -1;
    }
    memset(&opts, 0, sizeof(opts));
    memset(&result, 0, sizeof(result));
    opts.stderr_to_devnull = true;
    return run_argv_real(argv, &opts, &result);
}

static int life_reap_attempts;

static ssh_process_outcome_t count_and_refuse_session_reap(
    const ssh_agent_record_t *record, const char *socket_arg,
    int runtime_dir_fd) {
    (void)record;
    (void)socket_arg;
    (void)runtime_dir_fd;
    life_reap_attempts++;
    return SSH_PROCESS_OWNED;
}

static char life_activation_key_path[PATH_MAX];
static char life_activation_replacement_path[PATH_MAX];
static int life_activation_replacement_attempts;
static int life_activation_replacement_result;
static int life_activation_agent_launches;

static int replace_key_after_admission_parse(
    const char *const argv[], const run_opts_t *opts,
    run_result_t *result) {
    const char *leaf = NULL;
    int rc;

    if (argv && argv[0]) {
        leaf = strrchr(argv[0], '/');
        leaf = leaf ? leaf + 1 : argv[0];
        if (strcmp(leaf, "ssh-agent") == 0) {
            life_activation_agent_launches++;
        }
    }
    rc = run_argv_real(argv, opts, result);
    /* The first ssh-keygen -lf in this instrumented switch is the account
     * admission parse. Replace the configured name only after OpenSSH has
     * accepted the original descriptor-backed generation. */
    if (rc == 0 && leaf && strcmp(leaf, "ssh-keygen") == 0 &&
        argv[1] && strcmp(argv[1], "-lf") == 0 &&
        life_activation_replacement_attempts == 0) {
        life_activation_replacement_attempts++;
        life_activation_replacement_result =
            rename(life_activation_replacement_path,
                   life_activation_key_path);
    }
    return rc;
}

static int prepare_shims(char *shim_dir, size_t size) {
    char path[1024], true_path[PATH_MAX], git_path[PATH_MAX];

    if (!ts_mkdtemp_trusted(shim_dir, size,
                            "gitswitch-ar04-life-shims")) return -1;
    /* This suite owns account lifecycle semantics. Interpreted executable
     * descriptor coverage belongs to test_ar07_exec_trust, so use native
     * copies here and avoid coupling these fixtures to /dev/fd availability.
     * Pin Git into the same private PATH as well: hosted arm64 macOS installs
     * it under /opt/homebrew, which the deliberately narrow child PATH omits. */
    if (find_fixture_executable("true", true_path, sizeof(true_path)) != 0 ||
        find_fixture_executable("git", git_path, sizeof(git_path)) != 0) {
        return -1;
    }
    /* Account edit now resolves a selector to one canonical primary
     * fingerprint. Exit-zero-with-no-output is deliberately a miss, so the
     * old copied `true` fixture no longer supplies valid key evidence. Copy
     * this test binary as a native helper; its helper mode below emits a
     * minimal, structurally valid secret-key inventory. */
    snprintf(path, sizeof(path), "%s/gpg", shim_dir);
    if (copy_executable(g_self, path) != 0) return -1;
    snprintf(path, sizeof(path), "%s/gpgconf", shim_dir);
    if (copy_executable(true_path, path) != 0) return -1;
    snprintf(path, sizeof(path), "%s/git", shim_dir);
    return copy_executable(git_path, path);
}

static int run_edit(const char *home, const char *runtime, const char *shim_dir,
                    const char *input, const char *output) {
    char stdin_path[1024];
    char cmd[8192];

    snprintf(stdin_path, sizeof(stdin_path), "%s/edit.in", runtime);
    if (write_text(stdin_path, input, 0600) != 0) return -1;
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' GNUPGHOME='%s/.gnupg' XDG_RUNTIME_DIR='%s' "
             "PATH='%s:/usr/bin:/bin' "
             "'%s' -C -y edit work <'%s' >'%s' 2>&1",
             home, home, runtime, shim_dir, g_bin, stdin_path, output);
    return run_shell(cmd);
}

TEST(active_live_field_edits_are_rejected_without_mutation) {
    char home[256], runtime[256], shims[512], key[1024];
    char config_path[1024], git_path[1024], output[1024];
    char before_config[8192], before_git[8192], after[8192], out[8192];
    char ssh_input[2048];
    const char *inputs[6];
    size_t i;

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(prepare_shims(shims, sizeof(shims)), 0);
    snprintf(key, sizeof(key), "%s/new-key", runtime);
    CHECK_EQ_INT(generate_fixture_ssh_key(key), 0);
    snprintf(ssh_input, sizeof(ssh_input), "\n\n\n%s\n\n\n\n", key);
    inputs[0] = "renamed\n\n\n\n\n\n";
    inputs[1] = "\nnew@example.com\n\n\n\n\n";
    inputs[2] = "renamed\nnew@example.com\n\n\n\nlocal\n";
    inputs[3] = "\n\n\n\n\nlocal\n";
    inputs[4] = ssh_input;
    inputs[5] = "\n\n\n\nABCDEF0123456789\n\n\n";

    snprintf(config_path, sizeof(config_path),
             "%s/.config/gitswitch/accounts.toml", home);
    snprintf(git_path, sizeof(git_path), "%s/.gitconfig", home);
    snprintf(output, sizeof(output), "%s/edit.out", runtime);

    for (i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
        CHECK_EQ_INT(prepare_home(home, active_work_config()), 0);
        CHECK_EQ_INT(write_text(git_path,
                                "[user]\n\tname = work\n\temail = old@example.com\n",
                                0600), 0);
        slurp(config_path, before_config, sizeof(before_config));
        slurp(git_path, before_git, sizeof(before_git));
        CHECK(run_edit(home, runtime, shims, inputs[i], output) != 0);
        slurp(config_path, after, sizeof(after));
        CHECK_STR_EQ(after, before_config);
        slurp(git_path, after, sizeof(after));
        CHECK_STR_EQ(after, before_git);
        slurp(output, out, sizeof(out));
        CHECK(strstr(out, "Cannot change live fields for active account 'work'") != NULL);
        CHECK(strstr(out, "switch away or reset it, then rerun edit") != NULL);
    }

    remove_tree(home);
    remove_tree(runtime);
}

TEST(active_description_edit_and_inactive_live_edits_still_work) {
    char home[256], runtime[256], shims[512], output[1024], path[1024];
    char key[1024], input[2048], contents[16384], before_git[4096];
    char ssh_target[1024], ssh_current[1024], gpg_target[1024], gpg_current[1024];
    char link_target[1024];
    struct stat ssh_before, ssh_after, gpg_before, gpg_after;
    ssize_t link_len;
    int edit_result;
    int listener = -1;
    static const char inactive_config[] =
        "[settings]\n"
        "default_scope = \"global\"\n"
        "active_account = \"other\"\n"
        "\n"
        "[accounts.1]\n"
        "name = \"work\"\n"
        "email = \"old@example.com\"\n"
        "description = \"old description\"\n"
        "preferred_scope = \"global\"\n"
        "\n"
        "[accounts.2]\n"
        "name = \"other\"\n"
        "email = \"other@example.com\"\n"
        "preferred_scope = \"global\"\n";
    static const char cleared_active_config[] =
        "[settings]\n"
        "default_scope = \"global\"\n"
        "active_account = \"\"\n"
        "\n"
        "[accounts.1]\n"
        "name = \"work\"\n"
        "email = \"old@example.com\"\n"
        "description = \"old description\"\n"
        "preferred_scope = \"global\"\n";

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(prepare_shims(shims, sizeof(shims)), 0);
    snprintf(output, sizeof(output), "%s/edit.out", runtime);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);

    CHECK_EQ_INT(prepare_home(home, active_work_config()), 0);
    snprintf(path, sizeof(path), "%s/.gitconfig", home);
    CHECK_EQ_INT(write_text(path,
                            "[user]\n\tname = work\n\temail = old@example.com\n",
                            0600), 0);
    slurp(path, before_git, sizeof(before_git));

    snprintf(ssh_target, sizeof(ssh_target),
             "%s/gitswitch-ssh/ssh-agent.work.sock", runtime);
    snprintf(ssh_current, sizeof(ssh_current),
             "%s/gitswitch-ssh/current.sock", runtime);
    listener = install_live_current_socket(runtime, "work");
    CHECK(listener >= 0);
    CHECK_EQ_INT(lstat(ssh_current, &ssh_before), 0);

    snprintf(path, sizeof(path), "%s/gitswitch-gpg", runtime);
    CHECK_EQ_INT(mkdir_private(path), 0);
    snprintf(gpg_target, sizeof(gpg_target), "%s/gitswitch-gpg/work", runtime);
    CHECK_EQ_INT(mkdir_private(gpg_target), 0);
    snprintf(gpg_current, sizeof(gpg_current), "%s/gitswitch-gpg/current", runtime);
    CHECK_EQ_INT(symlink(gpg_target, gpg_current), 0);
    CHECK_EQ_INT(lstat(gpg_current, &gpg_before), 0);

    CHECK_EQ_INT(run_edit(home, runtime, shims,
                          "\n\nmetadata only\n\n\n\n", output), 0);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "description = \"metadata only\"") != NULL);
    CHECK(strstr(contents, "email = \"old@example.com\"") != NULL);
    snprintf(path, sizeof(path), "%s/.gitconfig", home);
    slurp(path, contents, sizeof(contents));
    CHECK_STR_EQ(contents, before_git);
    CHECK_EQ_INT(lstat(ssh_current, &ssh_after), 0);
    CHECK_EQ_INT(lstat(gpg_current, &gpg_after), 0);
    CHECK(ssh_before.st_dev == ssh_after.st_dev &&
          ssh_before.st_ino == ssh_after.st_ino);
    CHECK(gpg_before.st_dev == gpg_after.st_dev &&
          gpg_before.st_ino == gpg_after.st_ino);
    link_len = readlink(ssh_current, link_target, sizeof(link_target) - 1);
    CHECK(link_len > 0);
    if (link_len > 0) {
        link_target[link_len] = '\0';
        CHECK_STR_EQ(link_target, ssh_target);
    }
    link_len = readlink(gpg_current, link_target, sizeof(link_target) - 1);
    CHECK(link_len > 0);
    if (link_len > 0) {
        link_target[link_len] = '\0';
        CHECK_STR_EQ(link_target, gpg_target);
    }

    /* The remainder of this test exercises edits to an inactive `work`
     * account. Remove the deliberately-live `work` runtime first so startup
     * detection does not correctly classify it as active. */
    if (listener >= 0) {
        close(listener);
        listener = -1;
    }
    CHECK_EQ_INT(unlink(ssh_current), 0);
    CHECK_EQ_INT(unlink(ssh_target), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-ssh/.lock", runtime);
    CHECK(unlink(path) == 0 || errno == ENOENT);
    snprintf(path, sizeof(path), "%s/gitswitch-ssh", runtime);
    CHECK_EQ_INT(rmdir(path), 0);
    CHECK_EQ_INT(unlink(gpg_current), 0);
    CHECK_EQ_INT(rmdir(gpg_target), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/.lock", runtime);
    CHECK(unlink(path) == 0 || errno == ENOENT);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg", runtime);
    CHECK_EQ_INT(rmdir(path), 0);

    /* The documented recovery workflow is not merely "make some other account
     * active": after clearing active_account entirely, the exact email change
     * rejected above must be accepted and persisted. */
    CHECK_EQ_INT(prepare_home(home, cleared_active_config), 0);
    CHECK_EQ_INT(run_edit(home, runtime, shims,
                          "\nnew@example.com\n\n\n\n\n", output), 0);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    /* Saving canonicalizes a cleared marker by omitting the empty setting; an
     * explicit empty value is equally valid, but no nonempty marker may return. */
    CHECK(strstr(contents, "active_account =") == NULL ||
          strstr(contents, "active_account = \"\"") != NULL);
    CHECK(strstr(contents, "name = \"work\"") != NULL);
    CHECK(strstr(contents, "email = \"new@example.com\"") != NULL);

    CHECK_EQ_INT(prepare_home(home, inactive_config), 0);
    edit_result = run_edit(home, runtime, shims,
                           "renamed\nnew@example.com\n\n\n\n\n", output);
    if (edit_result != 0) {
        slurp(output, contents, sizeof(contents));
        fprintf(stderr, "  inactive edit output:\n%s\n", contents);
    }
    CHECK_EQ_INT(edit_result, 0);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "name = \"renamed\"") != NULL);
    CHECK(strstr(contents, "email = \"new@example.com\"") != NULL);
    CHECK(strstr(contents, "active_account") == NULL);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/.resume-hint", home);
    slurp(path, contents, sizeof(contents));
    CHECK_STR_EQ(contents, "none\nactive=other\n");

    CHECK_EQ_INT(prepare_home(home, inactive_config), 0);
    snprintf(key, sizeof(key), "%s/inactive-key", runtime);
    CHECK_EQ_INT(generate_fixture_ssh_key(key), 0);
    snprintf(input, sizeof(input),
             "\n\n\n%s\ngithub.com-work\ngithub.com\nABCDEF0123456789\ny\n\n",
             key);
    CHECK_EQ_INT(run_edit(home, runtime, shims, input, output), 0);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "ssh_key = ") != NULL);
    CHECK(strstr(contents, "ssh_host = \"github.com-work\"") != NULL);
    CHECK(strstr(contents, "ssh_hostname = \"github.com\"") != NULL);
    CHECK(strstr(contents, "gpg_key = \"ABCDEF0123456789\"") != NULL);

    remove_tree(home);
    remove_tree(runtime);
}

static int run_remove(const char *home, const char *runtime,
                      const char *shim_dir, const char *account,
                      const char *output) {
    char cmd[8192];

    snprintf(cmd, sizeof(cmd),
             "HOME='%s' GNUPGHOME='%s/.gnupg' XDG_RUNTIME_DIR='%s' "
             "GIT_CONFIG_GLOBAL='%s/.gitconfig' GIT_CONFIG_NOSYSTEM=1 "
             "PATH='%s:/usr/bin:/bin' "
             "'%s' -C -y remove '%s' </dev/null >'%s' 2>&1",
             home, home, runtime, home, shim_dir, g_bin, account, output);
    return run_shell(cmd);
}

static size_t life_config_faults_remaining;

static bool life_config_fault_once(config_io_boundary_t boundary) {
    if (boundary != CONFIG_IO_STATE_BEFORE_RENAME ||
        life_config_faults_remaining == 0U) {
        return false;
    }
    life_config_faults_remaining--;
    return true;
}

/* Drive the real CLI entry in an isolated child so the lifecycle suite can
 * inject one precise PREINSTALL state-save failure. The callback is exhausted
 * before rollback reconciliation writes the refreshed publication generation,
 * proving the blocker is cleared only after that second write succeeds. */
static int run_remove_with_one_shot_save_fault(
    const char *home, const char *runtime, const char *shim_dir,
    const char *account, const char *output) {
    char trusted_path[2U * PATH_MAX];
    char gnupg_home[PATH_MAX];
    char git_config[PATH_MAX];
    pid_t child;
    int status = 0;

    if (!home || !runtime || !shim_dir || !account || !output ||
        safe_snprintf(trusted_path, sizeof(trusted_path),
                      "%s:/usr/local/bin:/usr/bin:/bin", shim_dir) != 0 ||
        safe_snprintf(gnupg_home, sizeof(gnupg_home),
                      "%s/.gnupg", home) != 0 ||
        safe_snprintf(git_config, sizeof(git_config),
                      "%s/.gitconfig", home) != 0) {
        return -1;
    }
    (void)fflush(NULL);
    child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        char program[] = "gitswitch";
        char no_color[] = "-C";
        char assume_yes[] = "-y";
        char remove[] = "remove";
        char *argv[] = {
            program, no_color, assume_yes, remove, (char *)account, NULL
        };
        int output_fd = open(output,
                             O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                             0600);
        int rc;

        if (output_fd < 0 || dup2(output_fd, STDOUT_FILENO) < 0 ||
            dup2(output_fd, STDERR_FILENO) < 0 ||
            setenv("HOME", home, 1) != 0 ||
            setenv("GNUPGHOME", gnupg_home, 1) != 0 ||
            setenv("XDG_RUNTIME_DIR", runtime, 1) != 0 ||
            setenv("GIT_CONFIG_GLOBAL", git_config, 1) != 0 ||
            setenv("GIT_CONFIG_NOSYSTEM", "1", 1) != 0 ||
            setenv("PATH", trusted_path, 1) != 0 ||
            unsetenv("GIT_CONFIG_COUNT") != 0) {
            if (output_fd >= 0) (void)close(output_fd);
            _exit(120);
        }
        if (output_fd > STDERR_FILENO) (void)close(output_fd);
        life_config_faults_remaining = 1U;
        (void)config_set_io_fault_fn(life_config_fault_once);
        optind = 1;
        rc = gitswitch_cli_main(5, argv);
        (void)fflush(NULL);
        _exit(rc);
    }
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    if (!WIFEXITED(status)) {
        return WIFSIGNALED(status) ? -(1000 + WTERMSIG(status)) : -1;
    }
    return WEXITSTATUS(status);
}

static void exercise_remove_runtime_teardown(const char *ssh_agent_path) {
    char home[256], runtime[256], shims[512], path[1024], target[1024];
    char output[1024], contents[8192], cmd[PATH_MAX + 4096];
    pid_t agent_pid = -1;
    bool agent_started = false;

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(prepare_shims(shims, sizeof(shims)), 0);
    CHECK_EQ_INT(prepare_home(home, active_work_config()), 0);
    CHECK_EQ_INT(seed_global_publication(home, 1U, LIFE_WORK_INCARNATION,
                                         "none", "work", NULL), 0);

    snprintf(path, sizeof(path), "%s/gitswitch-ssh", runtime);
    CHECK_EQ_INT(mkdir_private(path), 0);
    snprintf(target, sizeof(target), "%s/gitswitch-ssh/ssh-agent.work.sock", runtime);
    if (ssh_agent_path) {
        char *pid_marker;

        snprintf(output, sizeof(output), "%s/ssh-agent.out", runtime);
        snprintf(cmd, sizeof(cmd),
                 "PATH='/usr/bin:/bin:/usr/local/bin' '%s' -s -a '%s' "
                 ">'%s' 2>/dev/null",
                 ssh_agent_path, target, output);
        CHECK_EQ_INT(run_shell(cmd), 0);
        slurp(output, contents, sizeof(contents));
        pid_marker = strstr(contents, "SSH_AGENT_PID=");
        CHECK(pid_marker != NULL);
        if (pid_marker) {
            agent_pid = (pid_t)strtol(pid_marker + strlen("SSH_AGENT_PID="),
                                      NULL, 10);
        }
        CHECK(agent_pid > 1);
        if (agent_pid > 1) {
            CHECK_EQ_INT(write_live_agent_record(
                             runtime, "ssh-agent.work.pid", agent_pid),
                         0);
            agent_started = true;
        }
    } else {
        CHECK_EQ_INT(write_text(target, "socket fixture\n", 0600), 0);
    }
    snprintf(path, sizeof(path), "%s/gitswitch-ssh/current.sock", runtime);
    CHECK_EQ_INT(symlink(target, path), 0);

    snprintf(path, sizeof(path), "%s/gitswitch-gpg", runtime);
    CHECK_EQ_INT(mkdir_private(path), 0);
    snprintf(target, sizeof(target), "%s/gitswitch-gpg/work", runtime);
    CHECK_EQ_INT(mkdir_private(target), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/current", runtime);
    CHECK_EQ_INT(symlink(target, path), 0);

    snprintf(output, sizeof(output), "%s/remove.out", runtime);
    CHECK_EQ_INT(run_remove(home, runtime, shims, "work", output), 0);
    if (agent_started) {
        errno = 0;
        CHECK(kill(agent_pid, 0) != 0);
        CHECK_EQ_INT(errno, ESRCH);
        snprintf(path, sizeof(path),
                 "%s/gitswitch-ssh/ssh-agent.work.pid", runtime);
        CHECK(access(path, F_OK) != 0);
    }
    snprintf(path, sizeof(path), "%s/gitswitch-ssh/ssh-agent.work.sock", runtime);
    CHECK(access(path, F_OK) != 0);
    snprintf(path, sizeof(path), "%s/gitswitch-ssh/current.sock", runtime);
    CHECK(access(path, F_OK) != 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/work", runtime);
    CHECK(access(path, F_OK) != 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/current", runtime);
    CHECK(access(path, F_OK) != 0);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "name = \"work\"") == NULL);
    CHECK(strstr(contents, "active_account = \"work\"") == NULL);

    stop_external_process(agent_pid);

    remove_tree(home);
    remove_tree(runtime);
}

/* AR-14 M22: OpenSSH usability is read-only switch admission. A repeated
 * switch must parse the new target before it attempts to reap the process-
 * local agent owned by the preceding successful switch. Otherwise malformed
 * private-key armor can needlessly stop a working session and replace the
 * useful parse diagnostic with a cleanup/rollback error. */
TEST(malformed_private_key_fails_before_prior_session_teardown) {
    char home[256], runtime[256], valid_key[1024], invalid_key[1024];
    char config_path[1024], git_config[1024], config_body[4096];
    char current_socket[1024], target_before[1024], target_after[1024];
    char saved_home[PATH_MAX] = "";
    char saved_runtime[PATH_MAX] = "";
    char saved_git_config[PATH_MAX] = "";
    char saved_git_nosystem[64] = "";
    char saved_git_count[64] = "";
    const char *environment_value;
    bool had_home;
    bool had_runtime;
    bool had_git_config;
    bool had_git_nosystem;
    bool had_git_count;
    gitswitch_ctx_t ctx;
    error_context_t observed_error;
    ssh_reap_fn previous_reap;
    ssize_t before_length;
    ssize_t after_length;
    int switch_result;
    int cleanup_result;
    int observed_reaps;

    if (!command_exists("ssh-agent") || !command_exists("ssh-add") ||
        !command_exists("ssh-keygen")) {
        TS_SKIP("openssh",
                "ssh-agent, ssh-add, and ssh-keygen are required");
    }

    environment_value = getenv("HOME");
    had_home = environment_value != NULL;
    if (had_home) {
        CHECK_EQ_INT(safe_strncpy(saved_home, environment_value,
                                  sizeof(saved_home)),
                     0);
    }
    environment_value = getenv("XDG_RUNTIME_DIR");
    had_runtime = environment_value != NULL;
    if (had_runtime) {
        CHECK_EQ_INT(safe_strncpy(saved_runtime, environment_value,
                                  sizeof(saved_runtime)),
                     0);
    }
    environment_value = getenv("GIT_CONFIG_GLOBAL");
    had_git_config = environment_value != NULL;
    if (had_git_config) {
        CHECK_EQ_INT(safe_strncpy(saved_git_config, environment_value,
                                  sizeof(saved_git_config)),
                     0);
    }
    environment_value = getenv("GIT_CONFIG_NOSYSTEM");
    had_git_nosystem = environment_value != NULL;
    if (had_git_nosystem) {
        CHECK_EQ_INT(safe_strncpy(saved_git_nosystem, environment_value,
                                  sizeof(saved_git_nosystem)),
                     0);
    }
    environment_value = getenv("GIT_CONFIG_COUNT");
    had_git_count = environment_value != NULL;
    if (had_git_count) {
        CHECK_EQ_INT(safe_strncpy(saved_git_count, environment_value,
                                  sizeof(saved_git_count)),
                     0);
    }

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    snprintf(valid_key, sizeof(valid_key), "%s/valid-key", runtime);
    snprintf(invalid_key, sizeof(invalid_key), "%s/invalid-key", runtime);
    CHECK_EQ_INT(generate_fixture_ssh_key(valid_key), 0);
    CHECK_EQ_INT(write_text(
                     invalid_key,
                     "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                     "not-a-valid-openssh-private-key\n"
                     "-----END OPENSSH PRIVATE KEY-----\n",
                     0600),
                 0);
    snprintf(config_body, sizeof(config_body),
             "[settings]\n"
             "default_scope = \"global\"\n"
             "\n"
             "[accounts.1]\n"
             "incarnation = \"" LIFE_WORK_INCARNATION "\"\n"
             "name = \"work\"\n"
             "email = \"work@example.com\"\n"
             "preferred_scope = \"global\"\n"
             "ssh_key = \"%s\"\n"
             "\n"
             "[accounts.2]\n"
             "incarnation = \"" LIFE_OTHER_INCARNATION "\"\n"
             "name = \"broken\"\n"
             "email = \"broken@example.com\"\n"
             "preferred_scope = \"global\"\n"
             "ssh_key = \"%s\"\n",
             valid_key, valid_key);
    CHECK_EQ_INT(prepare_home(home, config_body), 0);
    snprintf(config_path, sizeof(config_path),
             "%s/.config/gitswitch/accounts.toml", home);
    snprintf(git_config, sizeof(git_config), "%s/.gitconfig", home);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", runtime, 1), 0);
    CHECK_EQ_INT(setenv("GIT_CONFIG_GLOBAL", git_config, 1), 0);
    CHECK_EQ_INT(setenv("GIT_CONFIG_NOSYSTEM", "1", 1), 0);
    CHECK_EQ_INT(unsetenv("GIT_CONFIG_COUNT"), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, config_path), 0);
    ctx.config.force_global = true;
    ctx.config.assume_yes = true;
    CHECK_EQ_INT(accounts_switch(&ctx, "work"), 0);
    CHECK(ctx.current_account == &ctx.accounts[0]);

    snprintf(current_socket, sizeof(current_socket),
             "%s/gitswitch-ssh/current.sock", runtime);
    before_length =
        readlink(current_socket, target_before, sizeof(target_before) - 1U);
    CHECK(before_length > 0);
    if (before_length > 0) target_before[before_length] = '\0';

    CHECK_EQ_INT(safe_strncpy(ctx.accounts[1].ssh_key_path, invalid_key,
                              sizeof(ctx.accounts[1].ssh_key_path)),
                 0);
    life_reap_attempts = 0;
    previous_reap =
        ssh_manager_set_reap_fn(count_and_refuse_session_reap);
    clear_error();
    switch_result = accounts_switch(&ctx, "broken");
    observed_error = *get_last_error();
    observed_reaps = life_reap_attempts;
    ssh_manager_set_reap_fn(previous_reap);

    after_length =
        readlink(current_socket, target_after, sizeof(target_after) - 1U);
    if (after_length > 0) target_after[after_length] = '\0';
    cleanup_result = accounts_session_cleanup();

    CHECK_EQ_INT(switch_result, -1);
    CHECK_EQ_INT(observed_reaps, 0);
    CHECK_EQ_INT(observed_error.code, ERR_SSH_KEY_INVALID);
    CHECK(strstr(observed_error.message, "OpenSSH") != NULL ||
          strstr(observed_error.message, "private key") != NULL);
    CHECK(ctx.current_account == &ctx.accounts[0]);
    CHECK_STR_EQ(ctx.config.active_account, "work");
    CHECK(after_length > 0);
    if (before_length > 0 && after_length > 0) {
        CHECK_STR_EQ(target_after, target_before);
    }
    CHECK_EQ_INT(cleanup_result, 0);

    CHECK_EQ_INT(had_git_count
                     ? setenv("GIT_CONFIG_COUNT", saved_git_count, 1)
                     : unsetenv("GIT_CONFIG_COUNT"),
                 0);
    CHECK_EQ_INT(had_git_nosystem
                     ? setenv("GIT_CONFIG_NOSYSTEM", saved_git_nosystem, 1)
                     : unsetenv("GIT_CONFIG_NOSYSTEM"),
                 0);
    CHECK_EQ_INT(had_git_config
                     ? setenv("GIT_CONFIG_GLOBAL", saved_git_config, 1)
                     : unsetenv("GIT_CONFIG_GLOBAL"),
                 0);
    CHECK_EQ_INT(had_runtime
                     ? setenv("XDG_RUNTIME_DIR", saved_runtime, 1)
                     : unsetenv("XDG_RUNTIME_DIR"),
                 0);
    CHECK_EQ_INT(had_home ? setenv("HOME", saved_home, 1)
                          : unsetenv("HOME"),
                 0);
    remove_tree(home);
    remove_tree(runtime);
}

/* AR-14 M22: replace a target immediately after OpenSSH accepts the
 * descriptor-backed admission generation. The final pathname proof must
 * reject that generation change before the prior healthy session is reaped
 * or a replacement agent is launched. Exercise both another valid key and
 * malformed private-key armor: identity continuity, not reparsing the new
 * pathname, owns the rejection. */
static void exercise_activation_generation_replacement(
    bool valid_replacement) {
    char home[256], runtime[256], prior_key[1024], target_key[1024];
    char staged_replacement_key[1024], config_path[1024], git_config[1024];
    char config_body[4096], current_socket[1024];
    char target_socket[1024], target_pid[1024];
    char target_before[1024], target_after[1024];
    char saved_home[PATH_MAX] = "";
    char saved_runtime[PATH_MAX] = "";
    char saved_git_config[PATH_MAX] = "";
    char saved_git_nosystem[64] = "";
    char saved_git_count[64] = "";
    const char *environment_value;
    bool had_home;
    bool had_runtime;
    bool had_git_config;
    bool had_git_nosystem;
    bool had_git_count;
    gitswitch_ctx_t ctx;
    command_runner_fn previous_runner;
    error_context_t observed_error;
    ssh_reap_fn previous_reap;
    ssize_t before_length;
    ssize_t after_length;
    int switch_result;
    int cleanup_result;
    int observed_agent_launches;
    int observed_reaps;

    if (!command_exists("ssh-agent") || !command_exists("ssh-add") ||
        !command_exists("ssh-keygen")) {
        TS_SKIP("openssh",
                "ssh-agent, ssh-add, and ssh-keygen are required");
    }

    environment_value = getenv("HOME");
    had_home = environment_value != NULL;
    if (had_home) {
        CHECK_EQ_INT(safe_strncpy(saved_home, environment_value,
                                  sizeof(saved_home)),
                     0);
    }
    environment_value = getenv("XDG_RUNTIME_DIR");
    had_runtime = environment_value != NULL;
    if (had_runtime) {
        CHECK_EQ_INT(safe_strncpy(saved_runtime, environment_value,
                                  sizeof(saved_runtime)),
                     0);
    }
    environment_value = getenv("GIT_CONFIG_GLOBAL");
    had_git_config = environment_value != NULL;
    if (had_git_config) {
        CHECK_EQ_INT(safe_strncpy(saved_git_config, environment_value,
                                  sizeof(saved_git_config)),
                     0);
    }
    environment_value = getenv("GIT_CONFIG_NOSYSTEM");
    had_git_nosystem = environment_value != NULL;
    if (had_git_nosystem) {
        CHECK_EQ_INT(safe_strncpy(saved_git_nosystem, environment_value,
                                  sizeof(saved_git_nosystem)),
                     0);
    }
    environment_value = getenv("GIT_CONFIG_COUNT");
    had_git_count = environment_value != NULL;
    if (had_git_count) {
        CHECK_EQ_INT(safe_strncpy(saved_git_count, environment_value,
                                  sizeof(saved_git_count)),
                     0);
    }

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(accounts_session_cleanup(), 0);
    snprintf(prior_key, sizeof(prior_key), "%s/prior-key", runtime);
    snprintf(target_key, sizeof(target_key), "%s/target-key", runtime);
    snprintf(staged_replacement_key, sizeof(staged_replacement_key),
             "%s/target-key.replacement", runtime);
    CHECK_EQ_INT(generate_fixture_ssh_key(prior_key), 0);
    CHECK_EQ_INT(generate_fixture_ssh_key(target_key), 0);
    if (valid_replacement) {
        CHECK_EQ_INT(generate_fixture_ssh_key(staged_replacement_key), 0);
    } else {
        CHECK_EQ_INT(write_text(
                         staged_replacement_key,
                         "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                         "shape-valid-but-not-an-openssh-private-key\n"
                         "-----END OPENSSH PRIVATE KEY-----\n",
                         0600),
                     0);
    }
    snprintf(config_body, sizeof(config_body),
             "[settings]\n"
             "default_scope = \"global\"\n"
             "\n"
             "[accounts.1]\n"
             "incarnation = \"" LIFE_WORK_INCARNATION "\"\n"
             "name = \"work\"\n"
             "email = \"work@example.com\"\n"
             "preferred_scope = \"global\"\n"
             "ssh_key = \"%s\"\n"
             "\n"
             "[accounts.2]\n"
             "incarnation = \"" LIFE_OTHER_INCARNATION "\"\n"
             "name = \"replacement\"\n"
             "email = \"replacement@example.com\"\n"
             "preferred_scope = \"global\"\n"
             "ssh_key = \"%s\"\n",
             prior_key, target_key);
    CHECK_EQ_INT(prepare_home(home, config_body), 0);
    snprintf(config_path, sizeof(config_path),
             "%s/.config/gitswitch/accounts.toml", home);
    snprintf(git_config, sizeof(git_config), "%s/.gitconfig", home);
    CHECK_EQ_INT(setenv("HOME", home, 1), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", runtime, 1), 0);
    CHECK_EQ_INT(setenv("GIT_CONFIG_GLOBAL", git_config, 1), 0);
    CHECK_EQ_INT(setenv("GIT_CONFIG_NOSYSTEM", "1", 1), 0);
    CHECK_EQ_INT(unsetenv("GIT_CONFIG_COUNT"), 0);

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(config_load(&ctx, config_path), 0);
    ctx.config.force_global = true;
    ctx.config.assume_yes = true;
    CHECK_EQ_INT(accounts_switch(&ctx, "work"), 0);
    CHECK(ctx.current_account == &ctx.accounts[0]);

    snprintf(current_socket, sizeof(current_socket),
             "%s/gitswitch-ssh/current.sock", runtime);
    snprintf(target_socket, sizeof(target_socket),
             "%s/gitswitch-ssh/ssh-agent.replacement.sock", runtime);
    snprintf(target_pid, sizeof(target_pid),
             "%s/gitswitch-ssh/ssh-agent.replacement.pid", runtime);
    before_length =
        readlink(current_socket, target_before, sizeof(target_before) - 1U);
    CHECK(before_length > 0);
    if (before_length > 0) target_before[before_length] = '\0';

    CHECK_EQ_INT(safe_strncpy(life_activation_key_path, target_key,
                              sizeof(life_activation_key_path)),
                 0);
    CHECK_EQ_INT(safe_strncpy(life_activation_replacement_path,
                              staged_replacement_key,
                              sizeof(life_activation_replacement_path)),
                 0);
    life_activation_replacement_attempts = 0;
    life_activation_replacement_result = -1;
    life_activation_agent_launches = 0;
    life_reap_attempts = 0;
    previous_reap =
        ssh_manager_set_reap_fn(count_and_refuse_session_reap);
    previous_runner =
        run_set_runner(replace_key_after_admission_parse);
    clear_error();
    switch_result = accounts_switch(&ctx, "replacement");
    observed_error = *get_last_error();
    observed_reaps = life_reap_attempts;
    observed_agent_launches = life_activation_agent_launches;
    run_set_runner(previous_runner);
    ssh_manager_set_reap_fn(previous_reap);

    after_length =
        readlink(current_socket, target_after, sizeof(target_after) - 1U);
    if (after_length > 0) target_after[after_length] = '\0';
    cleanup_result = accounts_session_cleanup();

    CHECK_EQ_INT(life_activation_replacement_result, 0);
    CHECK_EQ_INT(life_activation_replacement_attempts, 1);
    CHECK_EQ_INT(switch_result, -1);
    CHECK_EQ_INT(observed_reaps, 0);
    CHECK_EQ_INT(observed_agent_launches, 0);
    CHECK_EQ_INT(observed_error.code, ERR_SSH_KEY_INVALID);
    CHECK(strstr(observed_error.message,
                 "changed after OpenSSH validation") != NULL);
    CHECK(ctx.current_account == &ctx.accounts[0]);
    CHECK_STR_EQ(ctx.config.active_account, "work");
    CHECK(after_length > 0);
    if (before_length > 0 && after_length > 0) {
        CHECK_STR_EQ(target_after, target_before);
    }
    CHECK(access(target_socket, F_OK) != 0);
    CHECK(access(target_pid, F_OK) != 0);
    CHECK_EQ_INT(cleanup_result, 0);

    CHECK_EQ_INT(had_git_count
                     ? setenv("GIT_CONFIG_COUNT", saved_git_count, 1)
                     : unsetenv("GIT_CONFIG_COUNT"),
                 0);
    CHECK_EQ_INT(had_git_nosystem
                     ? setenv("GIT_CONFIG_NOSYSTEM", saved_git_nosystem, 1)
                     : unsetenv("GIT_CONFIG_NOSYSTEM"),
                 0);
    CHECK_EQ_INT(had_git_config
                     ? setenv("GIT_CONFIG_GLOBAL", saved_git_config, 1)
                     : unsetenv("GIT_CONFIG_GLOBAL"),
                 0);
    CHECK_EQ_INT(had_runtime
                     ? setenv("XDG_RUNTIME_DIR", saved_runtime, 1)
                     : unsetenv("XDG_RUNTIME_DIR"),
                 0);
    CHECK_EQ_INT(had_home ? setenv("HOME", saved_home, 1)
                          : unsetenv("HOME"),
                 0);
    remove_tree(home);
    remove_tree(runtime);
}

TEST(valid_activation_generation_replacement_preserves_prior_session) {
    exercise_activation_generation_replacement(true);
}

TEST(malformed_activation_generation_replacement_preserves_prior_session) {
    exercise_activation_generation_replacement(false);
}

TEST(remove_tears_down_runtime_before_deleting_account) {
    exercise_remove_runtime_teardown(NULL);
}

#if defined(__linux__)
TEST(remove_reaps_real_agent_before_deleting_account) {
    char ssh_agent_path[PATH_MAX];

    if (find_fixture_executable("ssh-agent", ssh_agent_path,
                                sizeof(ssh_agent_path)) != 0) {
        TS_SKIP("openssh", "ssh-agent unavailable in PATH");
    }
    exercise_remove_runtime_teardown(ssh_agent_path);
}
#endif

TEST(remove_save_failure_keeps_retry_handle_after_runtime_teardown) {
    char home[256], runtime[256], shims[512];
    char path[1024], target[1024], output[1024], cmd[8192], contents[8192];
    char key_path[1024], config_body[4096], current_path[1024];
    char socket_path[1024], pid_path[1024], link_target[1024];
    struct stat st;
    ssize_t link_len;
    pid_t retry_pid = -1;

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(prepare_shims(shims, sizeof(shims)), 0);
    CHECK_EQ_INT(life_join_path(key_path, sizeof(key_path), runtime,
                                "/retry-key"), 0);
    snprintf(cmd, sizeof(cmd),
             "PATH='/usr/bin:/bin:/usr/local/bin' ssh-keygen -q -t ed25519 "
             "-N '' -f '%s' >/dev/null 2>&1",
             key_path);
    CHECK_EQ_INT(run_shell(cmd), 0);
    snprintf(config_body, sizeof(config_body),
             "[settings]\n"
             "default_scope = \"global\"\n"
             "active_account = \"work\"\n"
             "\n"
             "[accounts.1]\n"
             "incarnation = \"%s\"\n"
             "name = \"work\"\n"
             "email = \"old@example.com\"\n"
             "description = \"old description\"\n"
             "preferred_scope = \"global\"\n"
             "ssh_key = \"%s\"\n",
             LIFE_WORK_INCARNATION, key_path);
    CHECK_EQ_INT(prepare_home(home, config_body), 0);
    CHECK_EQ_INT(seed_global_publication(home, 1U, LIFE_WORK_INCARNATION,
                                         "ssh", "work", key_path), 0);

    /* Give teardown a real owned GPG home to remove before persistence is
     * forced to fail. The on-disk account must remain as the retry handle. */
    snprintf(path, sizeof(path), "%s/gitswitch-gpg", runtime);
    CHECK_EQ_INT(mkdir_private(path), 0);
    snprintf(target, sizeof(target), "%s/gitswitch-gpg/work", runtime);
    CHECK_EQ_INT(mkdir_private(target), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/current", runtime);
    CHECK_EQ_INT(symlink(target, path), 0);

    /* M18 publishes its durable blocker before runtime teardown, so inject a
     * one-shot state-save fault only after the runtime and Git retirement
     * phases. The rollback refresh gets a clean second write and must clear
     * the blocker while retaining the durable account retry handle. */
    snprintf(output, sizeof(output), "%s/remove-save-failure.out", runtime);
    CHECK(run_remove_with_one_shot_save_fault(
              home, runtime, shims, "work", output) != 0);
    slurp(output, contents, sizeof(contents));
    CHECK(strstr(contents, "Failed to save configuration changes") != NULL);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/work", runtime);
    CHECK(access(path, F_OK) != 0);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "name = \"work\"") != NULL);
    CHECK(strstr(contents, "active_account = \"work\"") != NULL);

    /* Reload by switching again after the persistence fault is removed. This
     * proves the retained account is not merely listable: its SSH runtime can
     * be recreated cleanly after the earlier teardown. */
    snprintf(cmd, sizeof(cmd),
             "HOME='%s' GNUPGHOME='%s/.gnupg' XDG_RUNTIME_DIR='%s' "
             "GIT_CONFIG_GLOBAL='%s/.gitconfig' GIT_CONFIG_NOSYSTEM=1 "
             "PATH='%s:/usr/local/bin:/usr/bin:/bin' "
             "'%s' -C -y work >'%s' 2>&1",
             home, home, runtime, home, shims, g_bin, output);
    int switch_rc = run_shell(cmd);
    slurp(output, contents, sizeof(contents));
    if (switch_rc != 0) {
        fprintf(stderr, "  retry switch output:\n%s\n", contents);
    }
    CHECK_EQ_INT(switch_rc, 0);
    CHECK(strstr(contents, "SSH key loaded") != NULL);

    CHECK_EQ_INT(life_join_path(socket_path, sizeof(socket_path), runtime,
                                "/gitswitch-ssh/ssh-agent.work.sock"), 0);
    CHECK_EQ_INT(life_join_path(current_path, sizeof(current_path), runtime,
                                "/gitswitch-ssh/current.sock"), 0);
    CHECK_EQ_INT(life_join_path(pid_path, sizeof(pid_path), runtime,
                                "/gitswitch-ssh/ssh-agent.work.pid"), 0);
    CHECK_EQ_INT(lstat(current_path, &st), 0);
    CHECK(S_ISLNK(st.st_mode));
    link_len = readlink(current_path, link_target, sizeof(link_target) - 1);
    CHECK(link_len > 0);
    if (link_len > 0) {
        link_target[link_len] = '\0';
        CHECK_STR_EQ(link_target, socket_path);
    }
    CHECK_EQ_INT(stat(current_path, &st), 0);
    CHECK(S_ISSOCK(st.st_mode));
    CHECK_EQ_INT(life_join_path(path, sizeof(path), runtime,
                                "/gitswitch-ssh"), 0);
    CHECK_EQ_INT(directory_has_entry_prefix(path, ".key-fingerprint."), 0);
    slurp(pid_path, contents, sizeof(contents));
    {
        char *pid_end = NULL;
        const char *pid_text = contents;
        long parsed_pid;

        if (strncmp(contents, "v1 ", 3) == 0 ||
            strncmp(contents, "v2 ", 3) == 0) {
            pid_text += 3;
        }
        errno = 0;
        parsed_pid = strtol(pid_text, &pid_end, 10);
        if (errno == 0 && pid_end &&
            (*pid_end == ' ' || *pid_end == '\n' || *pid_end == '\0') &&
            parsed_pid > 1 && (long)(pid_t)parsed_pid == parsed_pid) {
            retry_pid = (pid_t)parsed_pid;
        }
    }
    CHECK(retry_pid > 1);

    CHECK_EQ_INT(run_remove(home, runtime, shims, "work", output), 0);
#if defined(__linux__)
    if (retry_pid > 1) {
        errno = 0;
        CHECK(kill(retry_pid, 0) != 0);
        CHECK_EQ_INT(errno, ESRCH);
    }
#endif
    errno = 0;
    CHECK(lstat(pid_path, &st) != 0);
    CHECK_EQ_INT(errno, ENOENT);
    errno = 0;
    CHECK(lstat(socket_path, &st) != 0);
    CHECK_EQ_INT(errno, ENOENT);
    errno = 0;
    CHECK(lstat(current_path, &st) != 0);
    CHECK_EQ_INT(errno, ENOENT);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "name = \"work\"") == NULL);

    stop_external_process(retry_pid);

    remove_tree(home);
    remove_tree(runtime);
}

TEST(remove_failure_retains_account_and_attempts_other_manager) {
    char home[256], runtime[256], shims[512], path[1024], target[1024];
    char output[1024], contents[8192];
    struct stat link_st;
    int listener = -1;

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(prepare_shims(shims, sizeof(shims)), 0);
    CHECK_EQ_INT(prepare_home(home, active_work_config()), 0);
    CHECK_EQ_INT(seed_global_publication(home, 1U, LIFE_WORK_INCARNATION,
                                         "none", "work", NULL), 0);
    snprintf(target, sizeof(target), "%s/foreign-ssh", runtime);
    CHECK_EQ_INT(mkdir_private(target), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-ssh", runtime);
    CHECK_EQ_INT(symlink(target, path), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg", runtime);
    CHECK_EQ_INT(mkdir_private(path), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/current", runtime);
    CHECK_EQ_INT(symlink("missing", path), 0);
    CHECK_EQ_INT(lstat(path, &link_st), 0);
    CHECK(S_ISLNK(link_st.st_mode));

    snprintf(output, sizeof(output), "%s/remove.out", runtime);
    CHECK(run_remove(home, runtime, shims, "work", output) != 0);
    /* GPG reset still attempted: gpg_manager_reset unlinks the dangling
     * `current` link, so the LINK must be gone. access() follows symlinks
     * and returned -1 either way — a tautological witness (AR-05 M6). */
    errno = 0;
    CHECK(lstat(path, &link_st) != 0 && errno == ENOENT);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "name = \"work\"") != NULL);
    CHECK(strstr(contents, "active_account = \"work\"") != NULL);
    slurp(output, contents, sizeof(contents));
    CHECK(strstr(contents, "account retained for retry") != NULL);

    /* The inverse partial failure: SSH cleanup succeeds, GPG lock fails, and
     * the account remains so the next remove/reset can retry. */
    remove_tree(runtime);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(prepare_shims(shims, sizeof(shims)), 0);
    CHECK_EQ_INT(prepare_home(home, active_work_config()), 0);
    CHECK_EQ_INT(seed_global_publication(home, 1U, LIFE_WORK_INCARNATION,
                                         "none", "work", NULL), 0);
    listener = install_live_current_socket(runtime, "work");
    CHECK(listener >= 0);
    if (listener >= 0) {
        CHECK_EQ_INT(close(listener), 0);
        listener = -1;
    }
    snprintf(path, sizeof(path), "%s/gitswitch-gpg", runtime);
    CHECK_EQ_INT(mkdir_private(path), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg/.lock", runtime);
    CHECK_EQ_INT(mkdir_private(path), 0);
    snprintf(output, sizeof(output), "%s/remove.out", runtime);
    CHECK(run_remove(home, runtime, shims, "work", output) != 0);
    snprintf(path, sizeof(path), "%s/gitswitch-ssh/ssh-agent.work.sock", runtime);
    if (access(path, F_OK) == 0) {
        slurp(output, contents, sizeof(contents));
        fprintf(stderr, "  partial cleanup output:\n%s\n", contents);
    }
    CHECK(access(path, F_OK) != 0);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "name = \"work\"") != NULL);
    CHECK(strstr(contents, "active_account = \"work\"") != NULL);

    remove_tree(home);
    remove_tree(runtime);
}

TEST(remove_inactive_account_with_no_runtime_preserves_active_account) {
    char home[256], runtime[256], shims[512], output[1024], path[1024];
    char contents[8192], ssh_target[1024], ssh_current[1024];
    char gpg_target[1024], gpg_current[1024], link_target[1024];
    ssize_t link_len;
    static const char body[] =
        "[settings]\n"
        "default_scope = \"global\"\n"
        "active_account = \"other\"\n"
        "\n"
        "[accounts.1]\n"
        "incarnation = \"" LIFE_WORK_INCARNATION "\"\n"
        "name = \"work\"\n"
        "email = \"work@example.com\"\n"
        "preferred_scope = \"global\"\n"
        "\n"
        "[accounts.2]\n"
        "incarnation = \"" LIFE_OTHER_INCARNATION "\"\n"
        "name = \"other\"\n"
        "email = \"other@example.com\"\n"
        "preferred_scope = \"global\"\n";

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(prepare_shims(shims, sizeof(shims)), 0);
    CHECK_EQ_INT(prepare_home(home, body), 0);
    CHECK_EQ_INT(seed_global_publication(home, 1U, LIFE_WORK_INCARNATION,
                                         "none", "other", NULL), 0);

    /* Give the active account real stable entry points. Removing the inactive
     * account must not tear either one down. */
    snprintf(path, sizeof(path), "%s/gitswitch-ssh", runtime);
    CHECK_EQ_INT(mkdir_private(path), 0);
    snprintf(ssh_target, sizeof(ssh_target),
             "%s/gitswitch-ssh/ssh-agent.other.sock", runtime);
    CHECK_EQ_INT(write_text(ssh_target, "active ssh runtime\n", 0600), 0);
    snprintf(ssh_current, sizeof(ssh_current),
             "%s/gitswitch-ssh/current.sock", runtime);
    CHECK_EQ_INT(symlink(ssh_target, ssh_current), 0);
    snprintf(path, sizeof(path), "%s/gitswitch-gpg", runtime);
    CHECK_EQ_INT(mkdir_private(path), 0);
    snprintf(gpg_target, sizeof(gpg_target), "%s/gitswitch-gpg/other", runtime);
    CHECK_EQ_INT(mkdir_private(gpg_target), 0);
    snprintf(gpg_current, sizeof(gpg_current), "%s/gitswitch-gpg/current", runtime);
    CHECK_EQ_INT(symlink(gpg_target, gpg_current), 0);

    snprintf(output, sizeof(output), "%s/remove.out", runtime);
    CHECK_EQ_INT(run_remove(home, runtime, shims, "work", output), 0);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "name = \"work\"") == NULL);
    CHECK(strstr(contents, "active_account") == NULL);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/.resume-hint", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strncmp(contents, "none\nactive=other\n",
                  strlen("none\nactive=other\n")) == 0);
    link_len = readlink(ssh_current, link_target, sizeof(link_target) - 1);
    CHECK(link_len > 0);
    if (link_len > 0) {
        link_target[link_len] = '\0';
        CHECK_STR_EQ(link_target, ssh_target);
    }
    CHECK(access(ssh_target, F_OK) == 0);
    link_len = readlink(gpg_current, link_target, sizeof(link_target) - 1);
    CHECK(link_len > 0);
    if (link_len > 0) {
        link_target[link_len] = '\0';
        CHECK_STR_EQ(link_target, gpg_target);
    }
    CHECK(access(gpg_target, F_OK) == 0);

    remove_tree(home);
    remove_tree(runtime);
}

TEST(remove_rebinds_current_pointer_after_array_compaction) {
    gitswitch_ctx_t ctx;
    char home[256], runtime[256], config_path[1024];

    memset(&ctx, 0, sizeof(ctx));
    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(prepare_home(home, active_work_config()), 0);
    CHECK_EQ_INT(seed_global_publication(home, 1U, LIFE_WORK_INCARNATION,
                                         "none", "work", NULL), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", runtime, 1), 0);
    snprintf(config_path, sizeof(config_path),
             "%s/.config/gitswitch/accounts.toml", home);
    CHECK_EQ_INT(safe_strncpy(ctx.config.config_path, config_path,
                              sizeof(ctx.config.config_path)), 0);

    ctx.account_count = 3;
    ctx.config.assume_yes = true;
    ctx.accounts[0].id = 1;
    ctx.accounts[0].incarnation_persisted = true;
    CHECK_EQ_INT(safe_strncpy(ctx.accounts[0].incarnation,
                              LIFE_WORK_INCARNATION,
                              sizeof(ctx.accounts[0].incarnation)), 0);
    snprintf(ctx.accounts[0].name, sizeof(ctx.accounts[0].name), "remove-me");
    ctx.accounts[1].id = 2;
    snprintf(ctx.accounts[1].name, sizeof(ctx.accounts[1].name), "current");
    ctx.accounts[2].id = 3;
    snprintf(ctx.accounts[2].name, sizeof(ctx.accounts[2].name), "later");
    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account), "current");
    ctx.current_account = &ctx.accounts[1];

    CHECK_EQ_INT(accounts_remove(&ctx, "remove-me"), 0);
    CHECK_EQ_INT((int)ctx.account_count, 2);
    CHECK(ctx.current_account == &ctx.accounts[0]);
    CHECK_STR_EQ(ctx.current_account->name, "current");
    CHECK_STR_EQ(ctx.config.active_account, "current");

    unsetenv("XDG_RUNTIME_DIR");
    remove_tree(home);
    remove_tree(runtime);
}

/* AR-12 H1: an account with no publication-ledger records (never switched,
 * or loaded from a pre-ledger config) has nothing durable to retire. Its
 * removal must succeed vacuously instead of demanding a switch-first round
 * trip that would publish the identity being deleted. */
TEST(remove_without_publication_provenance_succeeds_vacuously) {
    char home[256], runtime[256], shims[512], output[1024], path[1024];
    char contents[8192];

    CHECK_EQ_INT(make_temp_dir(home, sizeof(home)), 0);
    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(prepare_shims(shims, sizeof(shims)), 0);
    CHECK_EQ_INT(prepare_home(home, active_work_config()), 0);

    snprintf(output, sizeof(output), "%s/remove-no-provenance.out", runtime);
    CHECK_EQ_INT(run_remove(home, runtime, shims, "work", output), 0);
    snprintf(path, sizeof(path), "%s/.config/gitswitch/accounts.toml", home);
    slurp(path, contents, sizeof(contents));
    CHECK(strstr(contents, "name = \"work\"") == NULL);
    CHECK(strstr(contents, "active_account") == NULL);
    slurp(output, contents, sizeof(contents));
    CHECK(strstr(contents, "Failed to remove account") == NULL);
    CHECK(strstr(contents, "No canonical publication provenance exists") == NULL);

    remove_tree(home);
    remove_tree(runtime);
}

static void add_account(gitswitch_ctx_t *ctx, size_t index, const char *name) {
    account_t *account = &ctx->accounts[index];

    memset(account, 0, sizeof(*account));
    account->id = (uint32_t)index + 1;
    snprintf(account->name, sizeof(account->name), "%s", name);
    snprintf(account->email, sizeof(account->email), "%s@example.com", name);
    ctx->account_count = index + 1;
}

static int install_current_link(const char *runtime, const char *target) {
    char path[1024];

    snprintf(path, sizeof(path), "%s/gitswitch-ssh", runtime);
    if (mkdir_private(path) != 0) return -1;
    snprintf(path, sizeof(path), "%s/gitswitch-ssh/current.sock", runtime);
    unlink(path);
    return symlink(target, path);
}

static int install_live_current_socket(const char *runtime,
                                       const char *account_name) {
    char dir[1024];
    char current[1024];
    char lock_path[1024];
    char socket_path[1024];
    struct sockaddr_un addr;
    int fd;
    int lock_fd;

    if ((size_t)snprintf(dir, sizeof(dir), "%s/gitswitch-ssh", runtime) >=
        sizeof(dir)) {
        return -1;
    }
    if (mkdir_private(dir) != 0) return -1;
    if ((size_t)snprintf(lock_path, sizeof(lock_path), "%s/.lock", dir) >=
        sizeof(lock_path)) {
        return -1;
    }
    lock_fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (lock_fd < 0) return -1;
    if (fchmod(lock_fd, 0600) != 0) {
        int saved_errno = errno;
        close(lock_fd);
        errno = saved_errno;
        return -1;
    }
    if (close(lock_fd) != 0) return -1;
    if ((size_t)snprintf(socket_path, sizeof(socket_path),
                         "%s/ssh-agent.%s.sock", dir, account_name) >=
        sizeof(socket_path)) {
        return -1;
    }
    if (strlen(socket_path) >= sizeof(addr.sun_path)) return -1;

    unlink(socket_path);
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, socket_path, strlen(socket_path) + 1);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        chmod(socket_path, 0600) != 0 || listen(fd, 4) != 0) {
        close(fd);
        unlink(socket_path);
        return -1;
    }

    if ((size_t)snprintf(current, sizeof(current), "%s/current.sock", dir) >=
        sizeof(current)) {
        close(fd);
        unlink(socket_path);
        return -1;
    }
    unlink(current);
    if (symlink(socket_path, current) != 0) {
        close(fd);
        unlink(socket_path);
        return -1;
    }
    return fd;
}

TEST(sock_substrings_round_trip_and_malformed_links_fall_back) {
    char runtime[256];
    gitswitch_ctx_t ctx;
    int listener;

    CHECK_EQ_INT(make_temp_dir(runtime, sizeof(runtime)), 0);
    CHECK_EQ_INT(setenv("XDG_RUNTIME_DIR", runtime, 1), 0);
    memset(&ctx, 0, sizeof(ctx));
    add_account(&ctx, 0, "alice.sock.work");
    add_account(&ctx, 1, "a.sock.b.sock.c");
    add_account(&ctx, 2, "saved");
    snprintf(ctx.config.active_account, sizeof(ctx.config.active_account), "%s", "saved");

    listener = install_live_current_socket(runtime, "alice.sock.work");
    CHECK(listener >= 0);
    CHECK_EQ_INT(accounts_detect_current(&ctx), 0);
    CHECK(ctx.current_account == &ctx.accounts[0]);
    if (listener >= 0) close(listener);

    ctx.current_account = NULL;
    listener = install_live_current_socket(runtime, "a.sock.b.sock.c");
    CHECK(listener >= 0);
    CHECK_EQ_INT(accounts_detect_current(&ctx), 0);
    CHECK(ctx.current_account == &ctx.accounts[1]);
    if (listener >= 0) close(listener);

    ctx.current_account = NULL;
    CHECK_EQ_INT(install_current_link(runtime,
                 "/tmp/ssh-agent.alice.sock.work.sock.extra"), 0);
    CHECK_EQ_INT(accounts_detect_current(&ctx), 0);
    CHECK(ctx.current_account == &ctx.accounts[2]);

    ctx.current_account = NULL;
    CHECK_EQ_INT(install_current_link(runtime,
                 "/tmp/ssh-agent.deleted.sock"), 0);
    CHECK_EQ_INT(accounts_detect_current(&ctx), 0);
    CHECK(ctx.current_account == &ctx.accounts[2]);

    ctx.current_account = NULL;
    {
        char path[1024];
        snprintf(path, sizeof(path), "%s/gitswitch-ssh/current.sock", runtime);
        unlink(path);
    }
    CHECK_EQ_INT(accounts_detect_current(&ctx), 0);
    CHECK(ctx.current_account == &ctx.accounts[2]);

    remove_tree(runtime);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--batch") == 0) {
        puts("sec:u:4096:1:ABCDEF0123456789:1700000000:::-:::scESC:::+:::23::0:");
        puts("fpr:::::::::0123456789ABCDEF01234567ABCDEF0123456789:");
        return 0;
    }
    error_init(LOG_LEVEL_WARNING, NULL);
    if (resolve_binary_and_self(argc > 0 ? argv[0] : NULL) != 0) return 1;
    RUN_TEST(active_live_field_edits_are_rejected_without_mutation);
    RUN_TEST(active_description_edit_and_inactive_live_edits_still_work);
    RUN_TEST(remove_tears_down_runtime_before_deleting_account);
#if defined(__linux__)
    RUN_TEST(remove_reaps_real_agent_before_deleting_account);
#endif
    RUN_TEST(remove_save_failure_keeps_retry_handle_after_runtime_teardown);
    RUN_TEST(remove_failure_retains_account_and_attempts_other_manager);
    RUN_TEST(remove_inactive_account_with_no_runtime_preserves_active_account);
    RUN_TEST(remove_rebinds_current_pointer_after_array_compaction);
    RUN_TEST(remove_without_publication_provenance_succeeds_vacuously);
    RUN_TEST(sock_substrings_round_trip_and_malformed_links_fall_back);
    RUN_TEST(malformed_private_key_fails_before_prior_session_teardown);
    RUN_TEST(valid_activation_generation_replacement_preserves_prior_session);
    RUN_TEST(malformed_activation_generation_replacement_preserves_prior_session);
    error_cleanup();
    return ts_test_finish();
}
