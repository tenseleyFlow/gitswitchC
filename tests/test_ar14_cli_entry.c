#include "test.h"

#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#include "gitswitch.h"

int gitswitch_cli_main(int argc, char **argv);
int gitswitch_test_context_allocations(void);
int gitswitch_test_context_allocation_total(void);

typedef void (*reset_test_hook_fn)(int stage);
typedef void (*remove_test_hook_fn)(int stage);
typedef void (*switch_abort_test_hook_fn)(gitswitch_ctx_t *ctx);
typedef void (*switch_prepare_failure_test_hook_fn)(void);
typedef void (*switch_rollback_publish_test_hook_fn)(void);

reset_test_hook_fn gitswitch_test_set_reset_hook(reset_test_hook_fn hook);
remove_test_hook_fn gitswitch_test_set_remove_hook(remove_test_hook_fn hook);
switch_abort_test_hook_fn gitswitch_test_set_switch_abort_hook(
    switch_abort_test_hook_fn hook);
switch_prepare_failure_test_hook_fn
gitswitch_test_set_switch_prepare_failure_hook(
    switch_prepare_failure_test_hook_fn hook);
switch_rollback_publish_test_hook_fn
gitswitch_test_set_switch_rollback_publish_hook(
    switch_rollback_publish_test_hook_fn hook);

typedef struct {
    char root[PATH_MAX];
    char home[PATH_MAX];
    char config[PATH_MAX];
    char runtime[PATH_MAX];
    char stdout_path[PATH_MAX];
    char stderr_path[PATH_MAX];
} cli_fixture_t;

typedef struct {
    int status;
    int allocation_delta;
    int active_allocations;
    bool hooks_unchanged;
    mode_t cli_umask;
    char stdout_text[32768];
    char stderr_text[8192];
} cli_result_t;

typedef struct {
    const char *name;
    char *value;
    bool was_set;
    bool captured;
} saved_env_t;

static const char *const g_fixture_env_names[] = {
    "HOME", "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR", "SHELL", "NO_COLOR"
};

static int save_environment(saved_env_t *saved, size_t count) {
    for (size_t index = 0; index < count; index++) {
        saved[index].name = g_fixture_env_names[index];
    }
    for (size_t index = 0; index < count; index++) {
        const char *value = getenv(g_fixture_env_names[index]);

        saved[index].was_set = value != NULL;
        saved[index].value = value ? strdup(value) : NULL;
        if (value && !saved[index].value) return -1;
        saved[index].captured = true;
    }
    return 0;
}

static void restore_environment(saved_env_t *saved, size_t count) {
    for (size_t index = 0; index < count; index++) {
        if (!saved[index].captured) {
            free(saved[index].value);
            saved[index].value = NULL;
            continue;
        }
        if (saved[index].was_set) {
            (void)setenv(saved[index].name, saved[index].value, 1);
        } else {
            (void)unsetenv(saved[index].name);
        }
        free(saved[index].value);
        saved[index].value = NULL;
        saved[index].captured = false;
    }
}

static int path_join(char *out, size_t out_size, const char *left,
                     const char *right) {
    int written = snprintf(out, out_size, "%s/%s", left, right);

    return written >= 0 && (size_t)written < out_size ? 0 : -1;
}

static int make_dir(const char *path) {
    return mkdir(path, 0700) == 0 || errno == EEXIST ? 0 : -1;
}

static int fixture_setup(cli_fixture_t *fixture) {
    char template_path[] = "/tmp/gitswitch-ar14-cli-XXXXXX";

    memset(fixture, 0, sizeof(*fixture));
    if (!ts_mkdtemp(template_path)) return -1;
    if (snprintf(fixture->root, sizeof(fixture->root), "%s",
                 template_path) >= (int)sizeof(fixture->root) ||
        path_join(fixture->home, sizeof(fixture->home), fixture->root,
                  "home") != 0 ||
        path_join(fixture->config, sizeof(fixture->config), fixture->root,
                  "config") != 0 ||
        path_join(fixture->runtime, sizeof(fixture->runtime), fixture->root,
                  "runtime") != 0 ||
        path_join(fixture->stdout_path, sizeof(fixture->stdout_path),
                  fixture->root, "stdout") != 0 ||
        path_join(fixture->stderr_path, sizeof(fixture->stderr_path),
                  fixture->root, "stderr") != 0) {
        return -1;
    }
    if (make_dir(fixture->home) != 0 ||
        make_dir(fixture->config) != 0 ||
        make_dir(fixture->runtime) != 0) {
        return -1;
    }
    if (setenv("HOME", fixture->home, 1) != 0 ||
        setenv("XDG_CONFIG_HOME", fixture->config, 1) != 0 ||
        setenv("XDG_RUNTIME_DIR", fixture->runtime, 1) != 0 ||
        setenv("SHELL", "/bin/bash", 1) != 0 ||
        setenv("NO_COLOR", "1", 1) != 0) {
        return -1;
    }
    return 0;
}

static size_t read_capture(const char *path, char *buffer,
                           size_t buffer_size) {
    int fd;
    size_t used = 0;

    if (buffer_size == 0) return 0;
    buffer[0] = '\0';
    fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    while (used + 1 < buffer_size) {
        ssize_t count = read(fd, buffer + used, buffer_size - used - 1);

        if (count > 0) {
            used += (size_t)count;
        } else if (count < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
    buffer[used] = '\0';
    close(fd);
    return used;
}

static cli_result_t invoke_cli(const cli_fixture_t *fixture, int argc,
                               char **argv) {
    cli_result_t result;
    int stdout_fd = -1;
    int stderr_fd = -1;
    int saved_stdout = -1;
    int saved_stderr = -1;
    int allocation_before;
    mode_t original_umask;
    reset_test_hook_fn reset_hook;
    remove_test_hook_fn remove_hook;
    switch_abort_test_hook_fn abort_hook;
    switch_prepare_failure_test_hook_fn prepare_hook;
    switch_rollback_publish_test_hook_fn publish_hook;

    memset(&result, 0, sizeof(result));
    result.status = EXIT_FAILURE;
    result.allocation_delta = INT_MIN;
    result.active_allocations = INT_MIN;
    result.cli_umask = (mode_t)-1;

    reset_hook = gitswitch_test_set_reset_hook(NULL);
    remove_hook = gitswitch_test_set_remove_hook(NULL);
    abort_hook = gitswitch_test_set_switch_abort_hook(NULL);
    prepare_hook = gitswitch_test_set_switch_prepare_failure_hook(NULL);
    publish_hook = gitswitch_test_set_switch_rollback_publish_hook(NULL);
    (void)gitswitch_test_set_reset_hook(reset_hook);
    (void)gitswitch_test_set_remove_hook(remove_hook);
    (void)gitswitch_test_set_switch_abort_hook(abort_hook);
    (void)gitswitch_test_set_switch_prepare_failure_hook(prepare_hook);
    (void)gitswitch_test_set_switch_rollback_publish_hook(publish_hook);

    stdout_fd = open(fixture->stdout_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    stderr_fd = open(fixture->stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (stdout_fd < 0 || stderr_fd < 0) goto restore_fds;
    if (fflush(NULL) != 0) goto restore_fds;
    saved_stdout = dup(STDOUT_FILENO);
    saved_stderr = dup(STDERR_FILENO);
    if (saved_stdout < 0 || saved_stderr < 0) goto restore_fds;
    if (dup2(stdout_fd, STDOUT_FILENO) < 0 ||
        dup2(stderr_fd, STDERR_FILENO) < 0) {
        goto restore_fds;
    }
    close(stdout_fd);
    stdout_fd = -1;
    close(stderr_fd);
    stderr_fd = -1;
    clearerr(stdout);
    clearerr(stderr);

#if defined(__APPLE__) || defined(__FreeBSD__)
    optind = 1;
    optreset = 1;
#else
    /* GNU and musl getopt use zero to reinitialize their hidden parser
     * state, including the next-character cursor left by a prior call. */
    optind = 0;
#endif
    opterr = 0;
    optopt = 0;
    allocation_before = gitswitch_test_context_allocation_total();
    original_umask = umask(022);
    (void)umask(original_umask);
    result.status = gitswitch_cli_main(argc, argv);
    result.allocation_delta =
        gitswitch_test_context_allocation_total() - allocation_before;
    result.active_allocations = gitswitch_test_context_allocations();
    result.cli_umask = umask(original_umask);
    (void)fflush(stdout);
    (void)fflush(stderr);

restore_fds:
    if (saved_stdout >= 0) {
        (void)dup2(saved_stdout, STDOUT_FILENO);
        close(saved_stdout);
    }
    if (saved_stderr >= 0) {
        (void)dup2(saved_stderr, STDERR_FILENO);
        close(saved_stderr);
    }
    if (stdout_fd >= 0) close(stdout_fd);
    if (stderr_fd >= 0) close(stderr_fd);
    clearerr(stdout);
    clearerr(stderr);
    (void)read_capture(fixture->stdout_path, result.stdout_text,
                       sizeof(result.stdout_text));
    (void)read_capture(fixture->stderr_path, result.stderr_text,
                       sizeof(result.stderr_text));

    result.hooks_unchanged = true;
    if (gitswitch_test_set_reset_hook(reset_hook) != reset_hook) {
        result.hooks_unchanged = false;
    }
    if (gitswitch_test_set_remove_hook(remove_hook) != remove_hook) {
        result.hooks_unchanged = false;
    }
    if (gitswitch_test_set_switch_abort_hook(abort_hook) != abort_hook) {
        result.hooks_unchanged = false;
    }
    if (gitswitch_test_set_switch_prepare_failure_hook(prepare_hook) !=
        prepare_hook) {
        result.hooks_unchanged = false;
    }
    if (gitswitch_test_set_switch_rollback_publish_hook(publish_hook) !=
        publish_hook) {
        result.hooks_unchanged = false;
    }
    return result;
}

static void check_clean_return(const cli_result_t *result,
                               int expected_allocations) {
    CHECK_EQ_INT(result->allocation_delta, expected_allocations);
    CHECK_EQ_INT(result->active_allocations, 0);
    CHECK(result->hooks_unchanged);
    CHECK_EQ_INT(result->cli_umask, 077);
}

TEST(informational_options_return_normally_across_repeated_entries) {
    cli_fixture_t fixture;
    char program[] = "gitswitch";
    char help[] = "--help";
    char version[] = "--version";
    char *help_argv[] = { program, help, NULL };
    char *version_argv[] = { program, version, NULL };
    cli_result_t first;
    cli_result_t second;
    cli_result_t third;

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    first = invoke_cli(&fixture, 2, help_argv);
    second = invoke_cli(&fixture, 2, version_argv);
    third = invoke_cli(&fixture, 2, help_argv);

    CHECK_EQ_INT(first.status, EXIT_SUCCESS);
    CHECK(strstr(first.stdout_text, "Usage: gitswitch") != NULL);
    check_clean_return(&first, 0);
    CHECK_EQ_INT(second.status, EXIT_SUCCESS);
    CHECK(strstr(second.stdout_text, "gitswitch") != NULL);
    check_clean_return(&second, 0);
    CHECK_EQ_INT(third.status, EXIT_SUCCESS);
    CHECK(strstr(third.stdout_text, "Usage: gitswitch") != NULL);
    check_clean_return(&third, 0);
}

TEST(every_safe_short_option_parses_before_help_dispatch) {
    cli_fixture_t fixture;
    char program[] = "gitswitch";
    char options[] = "-cCVdny";
    char names[] = "--names";
    char help[] = "-h";
    char *argv[] = { program, options, names, help, NULL };
    cli_result_t result;

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    result = invoke_cli(&fixture, 4, argv);
    CHECK_EQ_INT(result.status, EXIT_SUCCESS);
    CHECK(strstr(result.stdout_text, "Complete Git Identity Management") != NULL);
    check_clean_return(&result, 0);
}

TEST(scope_options_are_individually_valid_and_jointly_rejected) {
    cli_fixture_t fixture;
    char program[] = "gitswitch";
    char global[] = "-g";
    char local[] = "-l";
    char version[] = "-v";
    char *global_argv[] = { program, global, version, NULL };
    char *local_argv[] = { program, local, version, NULL };
    char *conflict_argv[] = { program, global, local, version, NULL };
    cli_result_t global_result;
    cli_result_t local_result;
    cli_result_t conflict_result;

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    global_result = invoke_cli(&fixture, 3, global_argv);
    local_result = invoke_cli(&fixture, 3, local_argv);
    conflict_result = invoke_cli(&fixture, 4, conflict_argv);
    CHECK_EQ_INT(global_result.status, EXIT_SUCCESS);
    check_clean_return(&global_result, 0);
    CHECK_EQ_INT(local_result.status, EXIT_SUCCESS);
    check_clean_return(&local_result, 0);
    CHECK_EQ_INT(conflict_result.status, EXIT_FAILURE);
    CHECK(strstr(conflict_result.stderr_text, "mutually exclusive") != NULL);
    check_clean_return(&conflict_result, 0);
}

TEST(unknown_and_malformed_options_fail_before_context_allocation) {
    cli_fixture_t fixture;
    char program[] = "gitswitch";
    char unknown[] = "--not-an-option";
    char malformed[] = "--global=value";
    char *unknown_argv[] = { program, unknown, NULL };
    char *malformed_argv[] = { program, malformed, NULL };
    cli_result_t unknown_result;
    cli_result_t malformed_result;

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    unknown_result = invoke_cli(&fixture, 2, unknown_argv);
    malformed_result = invoke_cli(&fixture, 2, malformed_argv);
    CHECK_EQ_INT(unknown_result.status, EXIT_FAILURE);
    CHECK(strstr(unknown_result.stdout_text, "Usage: gitswitch") != NULL);
    check_clean_return(&unknown_result, 0);
    CHECK_EQ_INT(malformed_result.status, EXIT_FAILURE);
    CHECK(strstr(malformed_result.stdout_text, "Usage: gitswitch") != NULL);
    check_clean_return(&malformed_result, 0);
}

TEST(each_command_family_rejects_invalid_arity_before_context_allocation) {
    static const char *const commands[] = {
        "edit", "remove", "rm", "delete", "switch", "reset", "init",
        "add", "list", "ls", "status", "doctor", "health", "config",
        "resume", "bare-account"
    };
    cli_fixture_t fixture;

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    for (size_t index = 0;
         index < sizeof(commands) / sizeof(commands[0]); index++) {
        char program[] = "gitswitch";
        char first[] = "one";
        char second[] = "two";
        char *argv[5] = { program, (char *)commands[index], NULL, NULL, NULL };
        int argc = 2;
        cli_result_t result;

        if (index <= 4) {
            /* These command families require one operand. */
        } else {
            argv[2] = first;
            argv[3] = second;
            argc = 4;
        }
        result = invoke_cli(&fixture, argc, argv);
        CHECK_EQ_INT(result.status, EXIT_FAILURE);
        CHECK(strstr(result.stderr_text, "invalid number of operands") != NULL);
        check_clean_return(&result, 0);
    }
}

TEST(internal_probes_reject_operands_and_mutual_exclusion) {
    cli_fixture_t fixture;
    char program[] = "gitswitch";
    char agent[] = "--ssh-agent-info";
    char resume[] = "--resume-check";
    char hint[] = "--resume-hint-probe";
    char operand[] = "status";
    char *agent_operand[] = { program, agent, operand, NULL };
    char *resume_operand[] = { program, resume, operand, NULL };
    char *hint_operand[] = { program, hint, operand, NULL };
    char *mutual[] = { program, agent, resume, hint, NULL };
    char **cases[] = { agent_operand, resume_operand, hint_operand, mutual };
    const int argcs[] = { 3, 3, 3, 4 };

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]);
         index++) {
        cli_result_t result = invoke_cli(&fixture, argcs[index], cases[index]);

        CHECK_EQ_INT(result.status, EXIT_FAILURE);
        CHECK(strstr(result.stderr_text,
                     index < 3 ? "does not accept operands"
                               : "mutually exclusive") != NULL);
        check_clean_return(&result, 0);
    }
}

TEST(informational_modes_take_precedence_without_running_internal_probes) {
    cli_fixture_t fixture;
    char program[] = "gitswitch";
    char version[] = "--version";
    char help[] = "--help";
    char resume[] = "--resume-check";
    char hint[] = "--resume-hint-probe";
    char operand[] = "status";
    char *version_argv[] = {
        program, resume, hint, operand, version, NULL
    };
    char *help_argv[] = { program, hint, operand, help, NULL };
    cli_result_t version_result;
    cli_result_t help_result;

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    version_result = invoke_cli(&fixture, 5, version_argv);
    help_result = invoke_cli(&fixture, 4, help_argv);
    CHECK_EQ_INT(version_result.status, EXIT_SUCCESS);
    CHECK(strstr(version_result.stdout_text, "gitswitch") != NULL);
    CHECK(strstr(version_result.stderr_text, "mutually exclusive") == NULL);
    check_clean_return(&version_result, 0);
    CHECK_EQ_INT(help_result.status, EXIT_SUCCESS);
    CHECK(strstr(help_result.stdout_text, "Usage: gitswitch") != NULL);
    CHECK(strstr(help_result.stderr_text, "does not accept operands") == NULL);
    check_clean_return(&help_result, 0);
}

TEST(option_reordering_and_delimiter_have_stable_portable_semantics) {
    cli_fixture_t fixture;
    char program[] = "gitswitch";
    char init[] = "init";
    char bash[] = "bash";
    char dry_run[] = "-n";
    char delimiter[] = "--";
    char *reordered[] = { program, init, bash, dry_run, NULL };
    char *delimited[] = {
        program, init, bash, delimiter, dry_run, NULL
    };
    cli_result_t reordered_result;
    cli_result_t delimited_result;

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    reordered_result = invoke_cli(&fixture, 4, reordered);
    delimited_result = invoke_cli(&fixture, 5, delimited);
    CHECK_EQ_INT(reordered_result.status, EXIT_SUCCESS);
    CHECK(reordered_result.stdout_text[0] != '\0');
    check_clean_return(&reordered_result, 0);
    CHECK_EQ_INT(delimited_result.status, EXIT_FAILURE);
    CHECK(strstr(delimited_result.stderr_text,
                 "invalid number of operands") != NULL);
    check_clean_return(&delimited_result, 0);
}

TEST(init_accepts_supported_shells_and_rejects_an_unknown_shell) {
    static const char *const shells[] = {
        "bash", "zsh", "fish", "sh", "dash", "ksh"
    };
    cli_fixture_t fixture;

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    for (size_t index = 0; index < sizeof(shells) / sizeof(shells[0]);
         index++) {
        char program[] = "gitswitch";
        char init[] = "init";
        char *argv[] = { program, init, (char *)shells[index], NULL };
        cli_result_t result = invoke_cli(&fixture, 3, argv);

        CHECK_EQ_INT(result.status, EXIT_SUCCESS);
        CHECK(result.stdout_text[0] != '\0');
        check_clean_return(&result, 0);
    }
    {
        char program[] = "gitswitch";
        char init[] = "init";
        char unknown[] = "powershell";
        char *argv[] = { program, init, unknown, NULL };
        cli_result_t result = invoke_cli(&fixture, 3, argv);

        CHECK_EQ_INT(result.status, EXIT_FAILURE);
        CHECK(strstr(result.stderr_text, "unsupported shell") != NULL);
        check_clean_return(&result, 0);
    }
}

TEST(legacy_init_alias_uses_the_private_shell_environment) {
    cli_fixture_t fixture;
    char program[] = "gitswitch";
    char alias[] = "--ssh-agent-info";
    char *argv[] = { program, alias, NULL };
    cli_result_t result;

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    result = invoke_cli(&fixture, 2, argv);
    CHECK_EQ_INT(result.status, EXIT_SUCCESS);
    CHECK(result.stdout_text[0] != '\0');
    check_clean_return(&result, 0);
}

TEST(no_command_uses_private_read_only_fixture_and_releases_context) {
    cli_fixture_t fixture;
    char program[] = "gitswitch";
    char *argv[] = { program, NULL };
    char config_dir[PATH_MAX];
    char config_lock[PATH_MAX];
    cli_result_t result;

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    CHECK_EQ_INT(path_join(config_dir, sizeof(config_dir), fixture.config,
                           "gitswitch"), 0);
    CHECK_EQ_INT(path_join(config_lock, sizeof(config_lock), config_dir,
                           ".config.lock"), 0);
    result = invoke_cli(&fixture, 1, argv);
    CHECK_EQ_INT(result.status, EXIT_SUCCESS);
    CHECK(strstr(result.stdout_text, "No accounts configured yet") != NULL);
    CHECK(access(config_lock, F_OK) != 0 && errno == ENOENT);
    check_clean_return(&result, 1);
}

TEST(empty_configuration_read_only_commands_release_each_parent_context) {
    static const char *const commands[] = {
        "list", "ls", "status"
    };
    cli_fixture_t fixture;

    CHECK_EQ_INT(fixture_setup(&fixture), 0);
    for (size_t index = 0;
         index < sizeof(commands) / sizeof(commands[0]); index++) {
        char program[] = "gitswitch";
        char *argv[] = { program, (char *)commands[index], NULL };
        cli_result_t result = invoke_cli(&fixture, 2, argv);

        CHECK_EQ_INT(result.status, EXIT_SUCCESS);
        CHECK(result.stdout_text[0] != '\0');
        check_clean_return(&result, 1);
    }
    {
        char program[] = "gitswitch";
        char list[] = "list";
        char names[] = "--names";
        char *argv[] = { program, list, names, NULL };
        cli_result_t result = invoke_cli(&fixture, 3, argv);

        CHECK_EQ_INT(result.status, EXIT_SUCCESS);
        check_clean_return(&result, 1);
    }
    {
        char program[] = "gitswitch";
        char config[] = "config";
        char dry_run[] = "--dry-run";
        char *argv[] = { program, config, dry_run, NULL };
        cli_result_t result = invoke_cli(&fixture, 3, argv);

        CHECK_EQ_INT(result.status, EXIT_SUCCESS);
        CHECK(strstr(result.stdout_text, "Would offer to create") != NULL);
        check_clean_return(&result, 1);
    }
}

int main(void) {
    saved_env_t saved_env[
        sizeof(g_fixture_env_names) / sizeof(g_fixture_env_names[0])
    ] = {{0}};
    int result;

    if (save_environment(saved_env,
                         sizeof(saved_env) / sizeof(saved_env[0])) != 0) {
        restore_environment(saved_env,
                            sizeof(saved_env) / sizeof(saved_env[0]));
        fprintf(stderr, "failed to preserve CLI-entry test environment\n");
        return EXIT_FAILURE;
    }
    RUN_TEST(informational_options_return_normally_across_repeated_entries);
    RUN_TEST(every_safe_short_option_parses_before_help_dispatch);
    RUN_TEST(scope_options_are_individually_valid_and_jointly_rejected);
    RUN_TEST(unknown_and_malformed_options_fail_before_context_allocation);
    RUN_TEST(each_command_family_rejects_invalid_arity_before_context_allocation);
    RUN_TEST(internal_probes_reject_operands_and_mutual_exclusion);
    RUN_TEST(informational_modes_take_precedence_without_running_internal_probes);
    RUN_TEST(option_reordering_and_delimiter_have_stable_portable_semantics);
    RUN_TEST(init_accepts_supported_shells_and_rejects_an_unknown_shell);
    RUN_TEST(legacy_init_alias_uses_the_private_shell_environment);
    RUN_TEST(no_command_uses_private_read_only_fixture_and_releases_context);
    RUN_TEST(empty_configuration_read_only_commands_release_each_parent_context);
    restore_environment(saved_env, sizeof(saved_env) / sizeof(saved_env[0]));
    result = ts_test_finish();
    return result;
}
