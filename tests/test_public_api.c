/* AR-08 L27: compile and link every function exported by a project header.
 *
 * __typeof__ binds each reference to the declaration's exact function-pointer
 * type.  The volatile local keeps a real relocation in optimized builds, so a
 * declaration without a definition cannot be hidden by dead-code removal. */
#include "test.h"

#include "accounts.h"
#include "config.h"
#include "display.h"
#include "error.h"
#include "git_ops.h"
#include "gitswitch.h"
#include "gpg_manager.h"
#include "prompt.h"
#include "signals.h"
#include "ssh_manager.h"
#include "toml_parser.h"
#include "utils.h"

#define REQUIRE_PUBLIC_API(name)                 \
    do {                                         \
        __typeof__(&(name)) volatile typed_api = &(name); \
        CHECK(typed_api != NULL);                \
    } while (0)

#define REQUIRE_PUBLIC_OBJECT(name)              \
    do {                                         \
        __typeof__(&(name)) volatile typed_object = &(name); \
        CHECK(typed_object != NULL);             \
    } while (0)

TEST(all_retained_public_apis_compile_and_link) {
    REQUIRE_PUBLIC_API(accounts_add_interactive);
    REQUIRE_PUBLIC_API(accounts_detect_current);
    REQUIRE_PUBLIC_API(accounts_edit_abort);
    REQUIRE_PUBLIC_API(accounts_edit_candidate_prepare);
    REQUIRE_PUBLIC_API(accounts_edit_commit);
    REQUIRE_PUBLIC_API(accounts_edit_interactive);
    REQUIRE_PUBLIC_API(accounts_edit_interactive_prepare);
    REQUIRE_PUBLIC_API(accounts_health_check);
    REQUIRE_PUBLIC_API(accounts_init);
    REQUIRE_PUBLIC_API(accounts_list);
    REQUIRE_PUBLIC_API(accounts_remove);
    REQUIRE_PUBLIC_API(accounts_session_cleanup);
    REQUIRE_PUBLIC_API(accounts_show_status);
    REQUIRE_PUBLIC_API(accounts_switch);
    REQUIRE_PUBLIC_API(accounts_switch_abort);
    REQUIRE_PUBLIC_API(accounts_switch_commit);
    REQUIRE_PUBLIC_API(accounts_switch_prepare);
    REQUIRE_PUBLIC_API(accounts_validate);
    REQUIRE_PUBLIC_API(atomic_symlink);
    REQUIRE_PUBLIC_API(atomic_symlink_at);
    REQUIRE_PUBLIC_API(backup_file);
    REQUIRE_PUBLIC_API(check_file_permissions_safe);
    REQUIRE_PUBLIC_API(clear_error);
    REQUIRE_PUBLIC_API(command_exists);
    REQUIRE_PUBLIC_API(compare_accounts_by_id);
    REQUIRE_PUBLIC_API(compare_accounts_by_name);
    REQUIRE_PUBLIC_API(compare_strings);
    REQUIRE_PUBLIC_API(config_add_account);
    REQUIRE_PUBLIC_API(config_backup);
    REQUIRE_PUBLIC_API(config_check_rewritable);
    REQUIRE_PUBLIC_API(config_create_default);
    REQUIRE_PUBLIC_API(config_find_account);
    REQUIRE_PUBLIC_API(config_find_account_destructive);
    REQUIRE_PUBLIC_API(config_find_account_exact);
    REQUIRE_PUBLIC_API(config_get_path);
    REQUIRE_PUBLIC_API(config_init);
    REQUIRE_PUBLIC_API(config_init_names);
    REQUIRE_PUBLIC_API(config_init_readonly);
    REQUIRE_PUBLIC_API(config_load);
    REQUIRE_PUBLIC_API(config_parse_scope);
    REQUIRE_PUBLIC_API(config_remove_account);
    REQUIRE_PUBLIC_API(config_restore_active_account);
    REQUIRE_PUBLIC_API(config_resume_hint_path);
    REQUIRE_PUBLIC_API(config_resume_hint_probe);
    REQUIRE_PUBLIC_API(config_resume_hint_snapshot_capture);
    REQUIRE_PUBLIC_API(config_resume_hint_snapshot_clear);
    REQUIRE_PUBLIC_API(config_resume_hint_snapshot_restore);
    REQUIRE_PUBLIC_API(config_save);
    REQUIRE_PUBLIC_API(config_save_active_account);
    REQUIRE_PUBLIC_API(config_save_active_account_transactional);
    REQUIRE_PUBLIC_API(config_save_transactional);
    REQUIRE_PUBLIC_API(config_scope_to_string);
    REQUIRE_PUBLIC_API(config_set_backup_clock_fn);
    REQUIRE_PUBLIC_API(config_set_document_malloc_fn);
    REQUIRE_PUBLIC_API(config_set_io_fault_fn);
    REQUIRE_PUBLIC_API(config_update_account);
    REQUIRE_PUBLIC_API(config_validate);
    REQUIRE_PUBLIC_API(config_write_lock);
    REQUIRE_PUBLIC_API(config_write_unlock);
    REQUIRE_PUBLIC_API(copy_file);
    REQUIRE_PUBLIC_API(create_directory_recursive);
    REQUIRE_PUBLIC_API(disable_echo);
    REQUIRE_PUBLIC_API(display_colorize);
    REQUIRE_PUBLIC_API(display_config_info);
    REQUIRE_PUBLIC_API(display_error);
    REQUIRE_PUBLIC_API(display_header);
    REQUIRE_PUBLIC_API(display_info);
    REQUIRE_PUBLIC_API(display_init);
    REQUIRE_PUBLIC_API(display_status);
    REQUIRE_PUBLIC_API(display_success);
    REQUIRE_PUBLIC_API(display_supports_color);
    REQUIRE_PUBLIC_API(display_warning);
    REQUIRE_PUBLIC_API(dump_account);
    REQUIRE_PUBLIC_API(dump_config);
    REQUIRE_PUBLIC_API(dump_context);
    REQUIRE_PUBLIC_API(enable_echo);
    REQUIRE_PUBLIC_API(ensure_config_directory_exists);
    REQUIRE_PUBLIC_API(ensure_private_dir);
    REQUIRE_PUBLIC_API(error_cleanup);
    REQUIRE_PUBLIC_API(error_code_to_string);
    REQUIRE_PUBLIC_API(error_init);
    REQUIRE_PUBLIC_API(expand_path);
    REQUIRE_PUBLIC_API(file_is_readable);
    REQUIRE_PUBLIC_API(file_is_writable);
    REQUIRE_PUBLIC_API(find_account_in_array);
    REQUIRE_PUBLIC_API(find_command_path);
    REQUIRE_PUBLIC_API(format_error_message);
    REQUIRE_PUBLIC_API(generate_random_string);
    REQUIRE_PUBLIC_API(get_config_directory);
    REQUIRE_PUBLIC_API(get_current_time_string);
    REQUIRE_PUBLIC_API(get_env_var);
    REQUIRE_PUBLIC_API(get_file_mtime);
    REQUIRE_PUBLIC_API(get_file_permissions);
    REQUIRE_PUBLIC_API(get_file_size);
    REQUIRE_PUBLIC_API(get_home_directory);
    REQUIRE_PUBLIC_API(get_last_error);
    REQUIRE_PUBLIC_API(get_terminal_size);
    REQUIRE_PUBLIC_API(get_timestamp);
    REQUIRE_PUBLIC_API(get_timestamp_string);
    REQUIRE_PUBLIC_API(git_clear_config);
    REQUIRE_PUBLIC_API(git_config_origin_scope_to_string);
    REQUIRE_PUBLIC_API(git_config_restore);
    REQUIRE_PUBLIC_API(git_config_snapshot);
    REQUIRE_PUBLIC_API(git_configure_gpg);
    REQUIRE_PUBLIC_API(git_configure_ssh);
    REQUIRE_PUBLIC_API(git_expected_ssh_command);
    REQUIRE_PUBLIC_API(git_get_config_value);
    REQUIRE_PUBLIC_API(git_get_current_config);
    REQUIRE_PUBLIC_API(git_get_repo_root);
    REQUIRE_PUBLIC_API(git_is_repository);
    REQUIRE_PUBLIC_API(git_list_config);
    REQUIRE_PUBLIC_API(git_ops_init);
    REQUIRE_PUBLIC_API(git_scope_to_flag);
    REQUIRE_PUBLIC_API(git_set_config);
    REQUIRE_PUBLIC_API(git_set_config_value);
    REQUIRE_PUBLIC_API(git_test_config);
    REQUIRE_PUBLIC_API(git_unset_config_value);
    REQUIRE_PUBLIC_API(gpg_colons_have_sign_capability);
    REQUIRE_PUBLIC_API(gpg_configure_git_signing);
    REQUIRE_PUBLIC_API(gpg_create_isolated_home);
    REQUIRE_PUBLIC_API(gpg_manager_cleanup);
    REQUIRE_PUBLIC_API(gpg_manager_current_is_live_for_account);
    REQUIRE_PUBLIC_API(gpg_manager_drop_current);
    REQUIRE_PUBLIC_API(gpg_manager_get_home_path);
    REQUIRE_PUBLIC_API(gpg_manager_get_home_path_quiet);
    REQUIRE_PUBLIC_API(gpg_manager_init);
    REQUIRE_PUBLIC_API(gpg_manager_isolated_home_present);
    REQUIRE_PUBLIC_API(gpg_manager_key_available_cached);
    REQUIRE_PUBLIC_API(gpg_manager_note_key_available);
    REQUIRE_PUBLIC_API(gpg_manager_reset);
    REQUIRE_PUBLIC_API(gpg_manager_resolve_secret_key_listing);
    REQUIRE_PUBLIC_API(gpg_manager_restore_current_if);
    REQUIRE_PUBLIC_API(gpg_manager_retarget_current);
    REQUIRE_PUBLIC_API(gpg_manager_runtime_restore_pending);
    REQUIRE_PUBLIC_API(gpg_manager_set_agent_conf_precommit_fn);
    REQUIRE_PUBLIC_API(gpg_manager_set_agent_conf_preopen_fn);
    REQUIRE_PUBLIC_API(gpg_manager_set_agent_conf_sync_fn);
    REQUIRE_PUBLIC_API(gpg_manager_set_cleanup_predelete_fn);
    REQUIRE_PUBLIC_API(gpg_manager_set_mount_identity_probe_fn);
    REQUIRE_PUBLIC_API(gpg_manager_set_readdir_fn);
    REQUIRE_PUBLIC_API(gpg_manager_set_rename_noreplace_fn);
    REQUIRE_PUBLIC_API(gpg_manager_set_reset_final_hook_fn);
    REQUIRE_PUBLIC_API(gpg_manager_set_retarget_commit_hook_fn);
    REQUIRE_PUBLIC_API(gpg_manager_set_retarget_restore_hook_fn);
    REQUIRE_PUBLIC_API(gpg_manager_set_rollback_hook_fn);
    REQUIRE_PUBLIC_API(gpg_manager_set_setenv_fn);
    REQUIRE_PUBLIC_API(gpg_manager_set_sync_base_fn);
    REQUIRE_PUBLIC_API(gpg_manager_set_unsetenv_fn);
    REQUIRE_PUBLIC_API(gpg_manager_setup_agent_config_for_test);
    REQUIRE_PUBLIC_API(gpg_manager_snapshot_current);
    REQUIRE_PUBLIC_API(gpg_manager_system_keyring_home);
    REQUIRE_PUBLIC_API(gpg_set_environment);
    REQUIRE_PUBLIC_API(gpg_switch_account);
    REQUIRE_PUBLIC_API(gpg_test_signing);
    REQUIRE_PUBLIC_API(gpg_validate_key);
    REQUIRE_PUBLIC_API(is_directory);
    REQUIRE_PUBLIC_API(is_regular_file);
    REQUIRE_PUBLIC_API(is_safe_ssh_key_path);
    REQUIRE_PUBLIC_API(is_terminal);
    REQUIRE_PUBLIC_API(is_timestamp_expired);
    REQUIRE_PUBLIC_API(join_path);
    REQUIRE_PUBLIC_API(lock_private_file_at);
    REQUIRE_PUBLIC_API(log_message);
    REQUIRE_PUBLIC_API(name_is_reserved_for_commands);
    REQUIRE_PUBLIC_API(open_private_subdir_at);
    REQUIRE_PUBLIC_API(open_runtime_parent);
    REQUIRE_PUBLIC_API(path_exists);
    REQUIRE_PUBLIC_API(print_error);
    REQUIRE_PUBLIC_API(process_is_running);
    REQUIRE_PUBLIC_API(prompt_line);
    REQUIRE_PUBLIC_API(read_file_to_string);
    REQUIRE_PUBLIC_API(run_argv);
    REQUIRE_PUBLIC_API(run_argv_real);
    REQUIRE_PUBLIC_API(run_set_runner);
    REQUIRE_PUBLIC_API(run_test_fd_close_bulk_supported);
    REQUIRE_PUBLIC_API(run_test_get_fd_close_observation);
    REQUIRE_PUBLIC_API(run_test_set_auto_bulk_close_unavailable);
    REQUIRE_PUBLIC_API(run_test_set_bulk_close_failure);
    REQUIRE_PUBLIC_API(run_test_set_exec_resolved_hook);
    REQUIRE_PUBLIC_API(run_test_set_fd_close_observation);
    REQUIRE_PUBLIC_API(run_test_set_fd_close_strategy);
    REQUIRE_PUBLIC_API(run_test_set_fork_failure);
    REQUIRE_PUBLIC_API(run_test_set_post_fork_pre_publish_hook);
    REQUIRE_PUBLIC_API(runtime_lock_test_fail_release_stat);
    REQUIRE_PUBLIC_API(runtime_state_lock_acquire);
    REQUIRE_PUBLIC_API(runtime_state_lock_release);
    REQUIRE_PUBLIC_API(safe_calloc);
    REQUIRE_PUBLIC_API(safe_malloc);
    REQUIRE_PUBLIC_API(safe_memcpy);
    REQUIRE_PUBLIC_API(safe_memset);
    REQUIRE_PUBLIC_API(safe_mlock);
    REQUIRE_PUBLIC_API(safe_munlock);
    REQUIRE_PUBLIC_API(safe_realloc);
    REQUIRE_PUBLIC_API(safe_snprintf);
    REQUIRE_PUBLIC_API(safe_strncat);
    REQUIRE_PUBLIC_API(safe_strncpy);
    REQUIRE_PUBLIC_API(secure_zero_memory);
    REQUIRE_PUBLIC_API(set_env_var);
    REQUIRE_PUBLIC_API(set_error_context);
    REQUIRE_PUBLIC_API(set_log_file);
    REQUIRE_PUBLIC_API(set_log_level);
    REQUIRE_PUBLIC_API(set_log_to_stderr);
    REQUIRE_PUBLIC_API(set_system_error_context);
    REQUIRE_PUBLIC_API(should_log);
    REQUIRE_PUBLIC_API(signals_block_for_child_spawn);
    REQUIRE_PUBLIC_API(signals_child_reaped);
    REQUIRE_PUBLIC_API(signals_child_spawned);
    REQUIRE_PUBLIC_API(signals_dispatch_pending);
    REQUIRE_PUBLIC_API(signals_guard_begin);
    REQUIRE_PUBLIC_API(signals_guard_end);
    REQUIRE_PUBLIC_API(signals_pending);
    REQUIRE_PUBLIC_API(signals_pending_signal);
    REQUIRE_PUBLIC_API(signals_reset_for_child);
    REQUIRE_PUBLIC_API(signals_restore_after_child_spawn);
    REQUIRE_PUBLIC_API(signals_rollback_begin);
    REQUIRE_PUBLIC_API(signals_rollback_end);
    REQUIRE_PUBLIC_API(signals_scratch_cleanup);
    REQUIRE_PUBLIC_API(signals_scratch_register);
    REQUIRE_PUBLIC_API(signals_scratch_unregister);
    REQUIRE_PUBLIC_API(signals_test_fail_sigaction);
    REQUIRE_PUBLIC_API(sort_accounts);
    REQUIRE_PUBLIC_API(ssh_add_key);
    REQUIRE_PUBLIC_API(ssh_clear_agent_keys);
    REQUIRE_PUBLIC_API(ssh_configure_host_alias);
    REQUIRE_PUBLIC_API(ssh_inspect_key_file);
    REQUIRE_PUBLIC_API(ssh_list_keys);
    REQUIRE_PUBLIC_API(ssh_manager_cleanup);
    REQUIRE_PUBLIC_API(ssh_manager_current_is_live_for_account);
    REQUIRE_PUBLIC_API(ssh_manager_get_auth_sock_path);
    REQUIRE_PUBLIC_API(ssh_manager_get_current_account);
    REQUIRE_PUBLIC_API(ssh_manager_init);
    REQUIRE_PUBLIC_API(ssh_manager_reset);
    REQUIRE_PUBLIC_API(ssh_manager_set_config_commit_hook_fn);
    REQUIRE_PUBLIC_API(ssh_manager_set_current_cleanup_hook_fn);
    REQUIRE_PUBLIC_API(ssh_manager_set_current_precleanup_hook_fn);
    REQUIRE_PUBLIC_API(ssh_manager_set_current_publish_hook_fn);
    REQUIRE_PUBLIC_API(ssh_manager_set_dirsync_fn);
    REQUIRE_PUBLIC_API(ssh_manager_set_force_portable_quarantine);
    REQUIRE_PUBLIC_API(ssh_manager_set_key_open_fn);
    REQUIRE_PUBLIC_API(ssh_manager_set_namespace_commit_hook_fn);
    REQUIRE_PUBLIC_API(ssh_manager_set_pid_commit_hook_fn);
    REQUIRE_PUBLIC_API(ssh_manager_set_pid_postrename_hook_fn);
    REQUIRE_PUBLIC_API(ssh_manager_set_probe_clock_fn);
    REQUIRE_PUBLIC_API(ssh_manager_set_probe_poll_fn);
    REQUIRE_PUBLIC_API(ssh_manager_set_quarantine_capture_hook_fn);
    REQUIRE_PUBLIC_API(ssh_manager_set_quarantine_hook_fn);
    REQUIRE_PUBLIC_API(ssh_manager_set_reap_fn);
    REQUIRE_PUBLIC_API(ssh_manager_set_setenv_fn);
    REQUIRE_PUBLIC_API(ssh_manager_test_cleanup_current_link);
    REQUIRE_PUBLIC_API(ssh_manager_test_probe_deadline);
    REQUIRE_PUBLIC_API(ssh_manager_test_probe_socket);
    REQUIRE_PUBLIC_API(ssh_manager_test_publish_current_link);
    REQUIRE_PUBLIC_API(ssh_manager_test_socket_has_key);
    REQUIRE_PUBLIC_API(ssh_manager_test_write_pid_sidecar);
    REQUIRE_PUBLIC_API(ssh_remove_host_alias);
    REQUIRE_PUBLIC_API(ssh_start_isolated_agent);
    REQUIRE_PUBLIC_API(ssh_stop_agent);
    REQUIRE_PUBLIC_API(ssh_switch_account);
    REQUIRE_PUBLIC_API(ssh_test_connection);
    REQUIRE_PUBLIC_API(ssh_validate_key_file);
    REQUIRE_PUBLIC_API(string_ascii_case_equal);
    REQUIRE_PUBLIC_API(string_empty);
    REQUIRE_PUBLIC_API(string_ends_with);
    REQUIRE_PUBLIC_API(string_equals);
    REQUIRE_PUBLIC_API(string_replace);
    REQUIRE_PUBLIC_API(string_starts_with);
    REQUIRE_PUBLIC_API(toml_check_injection_patterns);
    REQUIRE_PUBLIC_API(toml_cleanup_document);
    REQUIRE_PUBLIC_API(toml_get_boolean);
    REQUIRE_PUBLIC_API(toml_get_integer);
    REQUIRE_PUBLIC_API(toml_get_sections);
    REQUIRE_PUBLIC_API(toml_get_string);
    REQUIRE_PUBLIC_API(toml_init_document);
    REQUIRE_PUBLIC_API(toml_parse_file);
    REQUIRE_PUBLIC_API(toml_parse_string);
    REQUIRE_PUBLIC_API(toml_sanitize_string);
    REQUIRE_PUBLIC_API(toml_set_boolean);
    REQUIRE_PUBLIC_API(toml_set_document_init_hook_fn);
    REQUIRE_PUBLIC_API(toml_set_string);
    REQUIRE_PUBLIC_API(toml_set_writer_test_hook_fn);
    REQUIRE_PUBLIC_API(toml_validate_file_path);
    REQUIRE_PUBLIC_API(toml_validate_gitswitch_schema);
    REQUIRE_PUBLIC_API(toml_validate_safe_characters);
    REQUIRE_PUBLIC_API(toml_validate_ssh_host_alias);
    REQUIRE_PUBLIC_API(toml_validate_ssh_hostname);
    REQUIRE_PUBLIC_API(toml_write_file);
    REQUIRE_PUBLIC_API(toml_write_fd);
    REQUIRE_PUBLIC_API(text_is_tty_safe);
    REQUIRE_PUBLIC_API(trim_whitespace);
    REQUIRE_PUBLIC_API(try_lock_private_file_at);
    REQUIRE_PUBLIC_API(tty_safe_codepoint);
    REQUIRE_PUBLIC_API(unlock_private_file);
    REQUIRE_PUBLIC_API(unset_env_var);
    REQUIRE_PUBLIC_API(utf8_decode);
    REQUIRE_PUBLIC_API(validate_email);
    REQUIRE_PUBLIC_API(validate_file_path);
    REQUIRE_PUBLIC_API(validate_key_id);
    REQUIRE_PUBLIC_API(validate_name);
    REQUIRE_PUBLIC_API(write_string_to_file);

    REQUIRE_PUBLIC_OBJECT(default_config_template);
    REQUIRE_PUBLIC_OBJECT(g_last_error);
    REQUIRE_PUBLIC_OBJECT(g_log_file);
    REQUIRE_PUBLIC_OBJECT(g_log_level);
    REQUIRE_PUBLIC_OBJECT(g_log_to_stderr);
}

TEST_MAIN_BEGIN()
    RUN_TEST(all_retained_public_apis_compile_and_link);
TEST_MAIN_END()
