/* SSH key and agent management with comprehensive isolation and security
 * Implements per-account SSH agents to prevent key leakage between accounts
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include "ssh_manager.h"
#include "error.h"
#include "utils.h"
#include "display.h"

/* Internal helper functions */
static int execute_ssh_command(const char *command, char *output, size_t output_size);
static int setup_ssh_environment(ssh_config_t *ssh_config);
static int create_isolated_agent_socket_dir(char *socket_dir, size_t socket_dir_size);
static bool is_ssh_agent_running(pid_t pid);
static int kill_ssh_agent_gracefully(pid_t pid);
static int validate_ssh_agent_socket(const char *socket_path);
static int parse_ssh_agent_output(const char *output, ssh_config_t *ssh_config);

/* Global SSH configuration for cleanup */
static ssh_config_t *g_active_ssh_config = NULL;

/* Initialize SSH manager */
int ssh_manager_init(ssh_config_t *ssh_config, ssh_agent_mode_t mode) {
    if (!ssh_config) {
        set_error(ERR_INVALID_ARGS, "NULL ssh_config to ssh_manager_init");
        return -1;
    }
    
    log_debug("Initializing SSH manager with mode: %d", mode);
    
    /* Initialize structure */
    memset(ssh_config, 0, sizeof(ssh_config_t));
    ssh_config->mode = mode;
    ssh_config->agent_pid = -1;
    ssh_config->agent_owned = false;
    
    /* Validate SSH is available */
    if (!command_exists("ssh")) {
        set_error(ERR_SSH_NOT_FOUND, "SSH command not found in PATH");
        return -1;
    }
    
    if (!command_exists("ssh-agent")) {
        set_error(ERR_SSH_AGENT_NOT_FOUND, "ssh-agent command not found in PATH");
        return -1;
    }
    
    if (!command_exists("ssh-add")) {
        set_error(ERR_SSH_AGENT_NOT_FOUND, "ssh-add command not found in PATH");
        return -1;
    }
    
    /* Set up based on mode */
    switch (mode) {
        case SSH_AGENT_SYSTEM:
            /* Use existing SSH_AUTH_SOCK */
            if (getenv("SSH_AUTH_SOCK")) {
                safe_strncpy(ssh_config->agent_socket_path, getenv("SSH_AUTH_SOCK"),
                           sizeof(ssh_config->agent_socket_path));
                log_info("Using system SSH agent at: %s", ssh_config->agent_socket_path);
            } else {
                log_warning("No system SSH agent found (SSH_AUTH_SOCK not set)");
            }
            break;
            
        case SSH_AGENT_ISOLATED:
            /* Will create isolated agents on demand */
            log_info("Initialized for isolated SSH agent mode");
            break;
            
        case SSH_AGENT_NONE:
            log_info("SSH agent management disabled");
            break;
            
        default:
            set_error(ERR_INVALID_ARGS, "Invalid SSH agent mode: %d", mode);
            return -1;
    }
    
    /* Register for cleanup */
    g_active_ssh_config = ssh_config;
    
    log_info("SSH manager initialized successfully");
    return 0;
}

/* Cleanup SSH manager */
void ssh_manager_cleanup(ssh_config_t *ssh_config) {
    if (!ssh_config) {
        return;
    }
    
    log_debug("Cleaning up SSH manager");
    
    /* Stop agent if we own it */
    if (ssh_config->agent_owned && ssh_config->agent_pid > 0) {
        log_info("Stopping owned SSH agent (PID: %d)", ssh_config->agent_pid);
        ssh_stop_agent(ssh_config);
    }
    
    /* Clear global reference */
    if (g_active_ssh_config == ssh_config) {
        g_active_ssh_config = NULL;
    }
    
    /* Clear sensitive data */
    secure_zero_memory(ssh_config, sizeof(ssh_config_t));
    
    log_debug("SSH manager cleanup complete");
}

/* Switch to account's SSH configuration */
int ssh_switch_account(ssh_config_t *ssh_config, const account_t *account) {
    char expanded_key_path[MAX_PATH_LEN];
    
    if (!ssh_config || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to ssh_switch_account");
        return -1;
    }
    
    /* Skip if SSH not enabled for this account */
    if (!account->ssh_enabled || strlen(account->ssh_key_path) == 0) {
        log_debug("SSH not enabled for account: %s", account->name);
        return 0;
    }
    
    log_info("Switching SSH configuration for account: %s", account->name);
    
    /* Validate and expand key path */
    if (expand_path(account->ssh_key_path, expanded_key_path, sizeof(expanded_key_path)) != 0) {
        set_error(ERR_INVALID_PATH, "Failed to expand SSH key path: %s", account->ssh_key_path);
        return -1;
    }
    
    /* Validate key file */
    if (ssh_validate_key_file(expanded_key_path) != 0) {
        return -1; /* Error already set */
    }
    
    /* Handle based on mode */
    switch (ssh_config->mode) {
        case SSH_AGENT_SYSTEM:
            /* Clear existing keys and add new one to system agent */
            if (strlen(ssh_config->agent_socket_path) > 0) {
                log_debug("Clearing system SSH agent keys");
                ssh_clear_agent_keys(ssh_config);
                
                log_debug("Adding key to system SSH agent: %s", expanded_key_path);
                if (ssh_add_key(ssh_config, expanded_key_path) != 0) {
                    set_error(ERR_SSH_KEY_LOAD_FAILED, "Failed to load key into system SSH agent");
                    return -1;
                }
            } else {
                log_warning("No system SSH agent available");
            }
            break;
            
        case SSH_AGENT_ISOLATED:
            /* Start isolated agent for this account */
            if (ssh_start_isolated_agent(ssh_config, account) != 0) {
                return -1; /* Error already set */
            }
            
            /* Add key to isolated agent */
            if (ssh_add_key(ssh_config, expanded_key_path) != 0) {
                set_error(ERR_SSH_KEY_LOAD_FAILED, "Failed to load key into isolated SSH agent");
                return -1;
            }
            break;
            
        case SSH_AGENT_NONE:
            /* No agent management - just validate key */
            log_info("SSH agent management disabled - key validated but not loaded");
            break;
            
        default:
            set_error(ERR_INVALID_ARGS, "Invalid SSH agent mode");
            return -1;
    }
    
    /* Configure host alias if specified */
    if (strlen(account->ssh_host_alias) > 0) {
        if (ssh_configure_host_alias(account) != 0) {
            log_warning("Failed to configure SSH host alias: %s", account->ssh_host_alias);
            /* Don't fail completely for host alias issues */
        }
    }
    
    log_info("SSH configuration switched successfully for account: %s", account->name);
    return 0;
}

/* Start isolated SSH agent */
int ssh_start_isolated_agent(ssh_config_t *ssh_config, const account_t *account) {
    char command[512];
    char output[1024];
    char socket_dir[MAX_PATH_LEN];
    
    if (!ssh_config || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to ssh_start_isolated_agent");
        return -1;
    }
    
    log_info("Starting isolated SSH agent for account: %s", account->name);
    
    /* Stop any existing agent we own */
    if (ssh_config->agent_owned && ssh_config->agent_pid > 0) {
        log_debug("Stopping existing SSH agent");
        ssh_stop_agent(ssh_config);
    }
    
    /* Create secure socket directory */
    if (create_isolated_agent_socket_dir(socket_dir, sizeof(socket_dir)) != 0) {
        return -1;
    }
    
    /* Build ssh-agent command with socket path */
    if (snprintf(command, sizeof(command), 
                 "ssh-agent -a '%s/ssh-agent.%s.sock'", 
                 socket_dir, account->name) >= sizeof(command)) {
        set_error(ERR_INVALID_ARGS, "SSH agent command too long");
        return -1;
    }
    
    log_debug("Starting SSH agent: %s", command);
    
    /* Execute ssh-agent */
    if (execute_ssh_command(command, output, sizeof(output)) != 0) {
        set_error(ERR_SSH_AGENT_START_FAILED, "Failed to start SSH agent");
        return -1;
    }
    
    /* Parse ssh-agent output to get socket and PID */
    if (parse_ssh_agent_output(output, ssh_config) != 0) {
        set_error(ERR_SSH_AGENT_START_FAILED, "Failed to parse ssh-agent output");
        return -1;
    }
    
    /* Validate the agent is working */
    if (validate_ssh_agent_socket(ssh_config->agent_socket_path) != 0) {
        set_error(ERR_SSH_AGENT_START_FAILED, "SSH agent socket validation failed");
        return -1;
    }
    
    /* Mark as owned */
    ssh_config->agent_owned = true;
    
    /* Set up environment */
    if (setup_ssh_environment(ssh_config) != 0) {
        set_error(ERR_SSH_AGENT_START_FAILED, "Failed to set up SSH environment");
        return -1;
    }
    
    log_info("Isolated SSH agent started successfully (PID: %d, Socket: %s)", 
             ssh_config->agent_pid, ssh_config->agent_socket_path);
    return 0;
}

/* Stop SSH agent */
int ssh_stop_agent(ssh_config_t *ssh_config) {
    if (!ssh_config || ssh_config->agent_pid <= 0) {
        return 0; /* Nothing to stop */
    }
    
    if (!ssh_config->agent_owned) {
        log_debug("Not stopping SSH agent - we don't own it");
        return 0;
    }
    
    log_info("Stopping SSH agent (PID: %d)", ssh_config->agent_pid);
    
    /* Try graceful shutdown first */
    if (kill_ssh_agent_gracefully(ssh_config->agent_pid) == 0) {
        log_debug("SSH agent stopped gracefully");
    } else {
        log_warning("Failed to stop SSH agent gracefully");
    }
    
    /* Clean up socket file */
    if (strlen(ssh_config->agent_socket_path) > 0) {
        if (unlink(ssh_config->agent_socket_path) == 0) {
            log_debug("Removed SSH agent socket: %s", ssh_config->agent_socket_path);
        } else {
            log_debug("Could not remove SSH agent socket (may already be gone)");
        }
    }
    
    /* Reset state */
    ssh_config->agent_pid = -1;
    ssh_config->agent_owned = false;
    ssh_config->agent_socket_path[0] = '\0';
    
    /* Clear environment */
    unsetenv("SSH_AUTH_SOCK");
    unsetenv("SSH_AGENT_PID");
    
    return 0;
}

/* Clear all keys from SSH agent */
int ssh_clear_agent_keys(ssh_config_t *ssh_config) {
    char output[512];
    
    if (!ssh_config || strlen(ssh_config->agent_socket_path) == 0) {
        log_debug("No SSH agent available to clear keys");
        return 0;
    }
    
    log_debug("Clearing all keys from SSH agent");
    
    /* Set up environment for ssh-add */
    if (setup_ssh_environment(ssh_config) != 0) {
        return -1;
    }
    
    /* Execute ssh-add -D to delete all keys */
    if (execute_ssh_command("ssh-add -D", output, sizeof(output)) != 0) {
        log_warning("Failed to clear SSH agent keys (agent may be empty)");
        /* This is not necessarily an error - agent might be empty */
    } else {
        log_debug("SSH agent keys cleared successfully");
    }
    
    return 0;
}

/* Add key to SSH agent */
int ssh_add_key(ssh_config_t *ssh_config, const char *key_path) {
    char command[MAX_PATH_LEN + 32];
    char output[512];
    
    if (!ssh_config || !key_path) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to ssh_add_key");
        return -1;
    }
    
    if (strlen(ssh_config->agent_socket_path) == 0) {
        set_error(ERR_SSH_AGENT_NOT_FOUND, "No SSH agent available");
        return -1;
    }
    
    log_debug("Adding SSH key to agent: %s", key_path);
    
    /* Set up environment */
    if (setup_ssh_environment(ssh_config) != 0) {
        return -1;
    }
    
    /* Build ssh-add command */
    if (snprintf(command, sizeof(command), "ssh-add '%s'", key_path) >= sizeof(command)) {
        set_error(ERR_INVALID_ARGS, "SSH add command too long");
        return -1;
    }
    
    /* Execute ssh-add */
    if (execute_ssh_command(command, output, sizeof(output)) != 0) {
        set_error(ERR_SSH_KEY_LOAD_FAILED, "Failed to add SSH key: %s", output);
        return -1;
    }
    
    log_info("SSH key added successfully: %s", key_path);
    return 0;
}

/* List loaded SSH keys */
int ssh_list_keys(ssh_config_t *ssh_config, char *output, size_t output_size) {
    if (!ssh_config || !output || output_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to ssh_list_keys");
        return -1;
    }
    
    if (strlen(ssh_config->agent_socket_path) == 0) {
        safe_strncpy(output, "No SSH agent available", output_size);
        return -1;
    }
    
    /* Set up environment */
    if (setup_ssh_environment(ssh_config) != 0) {
        return -1;
    }
    
    /* Execute ssh-add -l */
    if (execute_ssh_command("ssh-add -l", output, output_size) != 0) {
        safe_strncpy(output, "No keys loaded in SSH agent", output_size);
        return -1;
    }
    
    return 0;
}

/* Validate SSH key file */
int ssh_validate_key_file(const char *key_path) {
    struct stat key_stat;
    mode_t key_mode;
    
    if (!key_path) {
        set_error(ERR_INVALID_ARGS, "NULL key_path to ssh_validate_key_file");
        return -1;
    }
    
    /* Check if file exists */
    if (stat(key_path, &key_stat) != 0) {
        set_system_error(ERR_SSH_KEY_NOT_FOUND, "SSH key file not found: %s", key_path);
        return -1;
    }
    
    /* Check if it's a regular file */
    if (!S_ISREG(key_stat.st_mode)) {
        set_error(ERR_SSH_KEY_INVALID, "SSH key path is not a regular file: %s", key_path);
        return -1;
    }
    
    /* Check permissions - should be 600 (readable only by owner) */
    key_mode = key_stat.st_mode & 0777;
    if (key_mode != 0600) {
        set_error(ERR_SSH_KEY_PERMISSIONS, 
                  "SSH key file has unsafe permissions: %o (should be 600): %s",
                  key_mode, key_path);
        return -1;
    }
    
    /* Check ownership - should be owned by current user */
    if (key_stat.st_uid != getuid()) {
        set_error(ERR_SSH_KEY_OWNERSHIP, "SSH key file not owned by current user: %s", key_path);
        return -1;
    }
    
    /* Basic content validation - check it looks like a private key */
    FILE *key_file = fopen(key_path, "r");
    if (!key_file) {
        set_system_error(ERR_SSH_KEY_INVALID, "Cannot read SSH key file: %s", key_path);
        return -1;
    }
    
    char first_line[256];
    bool valid_key = false;
    
    if (fgets(first_line, sizeof(first_line), key_file)) {
        /* Check for common private key headers */
        if (strstr(first_line, "-----BEGIN") && 
            (strstr(first_line, "PRIVATE KEY") || 
             strstr(first_line, "RSA PRIVATE KEY") ||
             strstr(first_line, "OPENSSH PRIVATE KEY") ||
             strstr(first_line, "EC PRIVATE KEY"))) {
            valid_key = true;
        }
    }
    
    fclose(key_file);
    
    if (!valid_key) {
        set_error(ERR_SSH_KEY_INVALID, "File does not appear to be a valid SSH private key: %s", key_path);
        return -1;
    }
    
    log_debug("SSH key validation passed: %s", key_path);
    return 0;
}

/* Configure SSH host alias */
int ssh_configure_host_alias(const account_t *account) {
    char ssh_config_path[MAX_PATH_LEN];
    char ssh_config_dir[MAX_PATH_LEN];
    FILE *ssh_config_file;
    char expanded_key_path[MAX_PATH_LEN];
    
    if (!account || strlen(account->ssh_host_alias) == 0) {
        return 0; /* Nothing to configure */
    }
    
    log_debug("Configuring SSH host alias: %s", account->ssh_host_alias);
    
    /* Get SSH config directory */
    if (snprintf(ssh_config_dir, sizeof(ssh_config_dir), "%s/.ssh", getenv("HOME")) >= sizeof(ssh_config_dir)) {
        set_error(ERR_INVALID_PATH, "SSH config directory path too long");
        return -1;
    }
    
    /* Create .ssh directory if it doesn't exist */
    if (!path_exists(ssh_config_dir)) {
        if (create_directory_recursive(ssh_config_dir, 0700) != 0) {
            return -1;
        }
    }
    
    /* SSH config file path */
    if (snprintf(ssh_config_path, sizeof(ssh_config_path), "%s/config", ssh_config_dir) >= sizeof(ssh_config_path)) {
        set_error(ERR_INVALID_PATH, "SSH config file path too long");
        return -1;
    }
    
    /* Expand key path */
    if (expand_path(account->ssh_key_path, expanded_key_path, sizeof(expanded_key_path)) != 0) {
        return -1;
    }
    
    /* Append to SSH config file */
    ssh_config_file = fopen(ssh_config_path, "a");
    if (!ssh_config_file) {
        set_system_error(ERR_FILE_IO, "Failed to open SSH config file: %s", ssh_config_path);
        return -1;
    }
    
    /* Write host configuration */
    fprintf(ssh_config_file, "\n# gitswitch-c configuration for account: %s\n", account->name);
    fprintf(ssh_config_file, "Host %s\n", account->ssh_host_alias);
    fprintf(ssh_config_file, "  IdentityFile %s\n", expanded_key_path);
    fprintf(ssh_config_file, "  IdentitiesOnly yes\n");
    fprintf(ssh_config_file, "  StrictHostKeyChecking no\n");
    fprintf(ssh_config_file, "  UserKnownHostsFile /dev/null\n");
    
    fclose(ssh_config_file);
    
    /* Set proper permissions on SSH config file */
    if (chmod(ssh_config_path, 0600) != 0) {
        log_warning("Failed to set permissions on SSH config file");
    }
    
    log_info("SSH host alias configured: %s -> %s", account->ssh_host_alias, expanded_key_path);
    return 0;
}

/* Test SSH connection */
int ssh_test_connection(const account_t *account, const char *host) {
    char command[512];
    char output[1024];
    
    if (!account || !host) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to ssh_test_connection");
        return -1;
    }
    
    log_debug("Testing SSH connection to: %s", host);
    
    /* Build SSH test command */
    if (strlen(account->ssh_host_alias) > 0) {
        /* Use host alias */
        if (snprintf(command, sizeof(command), 
                     "ssh -o ConnectTimeout=5 -o BatchMode=yes %s echo 'SSH connection test successful'",
                     account->ssh_host_alias) >= sizeof(command)) {
            set_error(ERR_INVALID_ARGS, "SSH test command too long");
            return -1;
        }
    } else {
        /* Use direct host with identity file */
        char expanded_key_path[MAX_PATH_LEN];
        if (expand_path(account->ssh_key_path, expanded_key_path, sizeof(expanded_key_path)) != 0) {
            return -1;
        }
        
        if (snprintf(command, sizeof(command),
                     "ssh -o ConnectTimeout=5 -o BatchMode=yes -i '%s' %s echo 'SSH connection test successful'",
                     expanded_key_path, host) >= sizeof(command)) {
            set_error(ERR_INVALID_ARGS, "SSH test command too long");
            return -1;
        }
    }
    
    /* Execute SSH test */
    if (execute_ssh_command(command, output, sizeof(output)) != 0) {
        set_error(ERR_SSH_CONNECTION_FAILED, "SSH connection test failed to %s: %s", host, output);
        return -1;
    }
    
    if (!strstr(output, "SSH connection test successful")) {
        set_error(ERR_SSH_CONNECTION_FAILED, "SSH connection test did not return expected output");
        return -1;
    }
    
    log_info("SSH connection test successful to: %s", host);
    return 0;
}

/* Internal helper functions */

/* Execute SSH command */
static int execute_ssh_command(const char *command, char *output, size_t output_size) {
    FILE *pipe;
    
    if (!command) {
        return -1;
    }
    
    log_debug("Executing SSH command: %s", command);
    
    pipe = popen(command, "r");
    if (!pipe) {
        set_system_error(ERR_SYSTEM_COMMAND_FAILED, "Failed to execute SSH command");
        return -1;
    }
    
    /* Read output if buffer provided */
    if (output && output_size > 0) {
        size_t total_read = 0;
        char *pos = output;
        
        while (total_read < output_size - 1 && 
               fgets(pos, output_size - total_read, pipe)) {
            size_t line_len = strlen(pos);
            total_read += line_len;
            pos += line_len;
        }
        output[total_read] = '\0';
        
        /* Remove trailing newline */
        if (total_read > 0 && output[total_read - 1] == '\n') {
            output[total_read - 1] = '\0';
        }
    }
    
    int exit_code = pclose(pipe);
    if (exit_code != 0) {
        log_debug("SSH command failed with exit code: %d", exit_code);
        return -1;
    }
    
    return 0;
}

/* Set up SSH environment variables */
static int setup_ssh_environment(ssh_config_t *ssh_config) {
    if (!ssh_config || strlen(ssh_config->agent_socket_path) == 0) {
        return -1;
    }
    
    /* Set SSH_AUTH_SOCK */
    if (setenv("SSH_AUTH_SOCK", ssh_config->agent_socket_path, 1) != 0) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to set SSH_AUTH_SOCK");
        return -1;
    }
    
    /* Set SSH_AGENT_PID if we have it */
    if (ssh_config->agent_pid > 0) {
        char pid_str[32];
        snprintf(pid_str, sizeof(pid_str), "%d", ssh_config->agent_pid);
        if (setenv("SSH_AGENT_PID", pid_str, 1) != 0) {
            set_system_error(ERR_SYSTEM_CALL, "Failed to set SSH_AGENT_PID");
            return -1;
        }
    }
    
    log_debug("SSH environment configured: SSH_AUTH_SOCK=%s, SSH_AGENT_PID=%d",
              ssh_config->agent_socket_path, ssh_config->agent_pid);
    return 0;
}

/* Create isolated agent socket directory */
static int create_isolated_agent_socket_dir(char *socket_dir, size_t socket_dir_size) {
    const char *runtime_dir = getenv("XDG_RUNTIME_DIR");
    const char *tmp_dir = "/tmp";
    
    /* Prefer XDG_RUNTIME_DIR if available */
    if (runtime_dir && path_exists(runtime_dir)) {
        if (snprintf(socket_dir, socket_dir_size, "%s/gitswitch-ssh", runtime_dir) >= socket_dir_size) {
            set_error(ERR_INVALID_PATH, "Socket directory path too long");
            return -1;
        }
    } else {
        if (snprintf(socket_dir, socket_dir_size, "%s/gitswitch-ssh-%d", tmp_dir, getuid()) >= socket_dir_size) {
            set_error(ERR_INVALID_PATH, "Socket directory path too long");
            return -1;
        }
    }
    
    /* Create directory with secure permissions */
    if (!path_exists(socket_dir)) {
        if (create_directory_recursive(socket_dir, 0700) != 0) {
            return -1;
        }
        log_debug("Created SSH socket directory: %s", socket_dir);
    }
    
    /* Verify permissions */
    struct stat dir_stat;
    if (stat(socket_dir, &dir_stat) != 0) {
        set_system_error(ERR_FILE_IO, "Failed to stat socket directory");
        return -1;
    }
    
    if ((dir_stat.st_mode & 0777) != 0700) {
        set_error(ERR_PERMISSION_DENIED, "Socket directory has insecure permissions");
        return -1;
    }
    
    return 0;
}

/* Check if SSH agent is running */
static bool is_ssh_agent_running(pid_t pid) {
    if (pid <= 0) {
        return false;
    }
    
    /* Use kill(pid, 0) to test if process exists */
    return (kill(pid, 0) == 0);
}

/* Kill SSH agent gracefully */
static int kill_ssh_agent_gracefully(pid_t pid) {
    if (pid <= 0) {
        return -1;
    }
    
    if (!is_ssh_agent_running(pid)) {
        log_debug("SSH agent (PID: %d) not running", pid);
        return 0;
    }
    
    /* Send SIGTERM first */
    if (kill(pid, SIGTERM) != 0) {
        set_system_error(ERR_SYSTEM_CALL, "Failed to send SIGTERM to SSH agent");
        return -1;
    }
    
    /* Wait a bit for graceful shutdown */
    for (int i = 0; i < 10; i++) {
        if (!is_ssh_agent_running(pid)) {
            return 0;
        }
        usleep(100000); /* 100ms */
    }
    
    /* Force kill if still running */
    if (is_ssh_agent_running(pid)) {
        log_warning("SSH agent did not respond to SIGTERM, sending SIGKILL");
        if (kill(pid, SIGKILL) != 0) {
            set_system_error(ERR_SYSTEM_CALL, "Failed to send SIGKILL to SSH agent");
            return -1;
        }
    }
    
    return 0;
}

/* Validate SSH agent socket */
static int validate_ssh_agent_socket(const char *socket_path) {
    struct stat socket_stat;
    
    if (!socket_path) {
        return -1;
    }
    
    /* Check if socket exists */
    if (stat(socket_path, &socket_stat) != 0) {
        set_system_error(ERR_SSH_AGENT_SOCKET_INVALID, "SSH agent socket not found: %s", socket_path);
        return -1;
    }
    
    /* Check if it's a socket */
    if (!S_ISSOCK(socket_stat.st_mode)) {
        set_error(ERR_SSH_AGENT_SOCKET_INVALID, "Path is not a socket: %s", socket_path);
        return -1;
    }
    
    /* Check permissions */
    if ((socket_stat.st_mode & 0777) != 0600) {
        set_error(ERR_SSH_AGENT_SOCKET_INVALID, "SSH agent socket has wrong permissions: %s", socket_path);
        return -1;
    }
    
    return 0;
}

/* Parse ssh-agent output */
static int parse_ssh_agent_output(const char *output, ssh_config_t *ssh_config) {
    char *line;
    char *output_copy;
    char *saveptr;
    
    if (!output || !ssh_config) {
        return -1;
    }
    
    /* Make a copy of output for parsing */
    output_copy = strdup(output);
    if (!output_copy) {
        set_error(ERR_MEMORY_ALLOCATION, "Failed to allocate memory for parsing");
        return -1;
    }
    
    /* Parse line by line */
    line = strtok_r(output_copy, "\n", &saveptr);
    while (line) {
        /* Look for SSH_AUTH_SOCK */
        if (strstr(line, "SSH_AUTH_SOCK=")) {
            char *socket_start = strchr(line, '=') + 1;
            char *socket_end = strchr(socket_start, ';');
            if (socket_end) {
                *socket_end = '\0';
            }
            safe_strncpy(ssh_config->agent_socket_path, socket_start,
                        sizeof(ssh_config->agent_socket_path));
        }
        
        /* Look for SSH_AGENT_PID */
        if (strstr(line, "SSH_AGENT_PID=")) {
            char *pid_start = strchr(line, '=') + 1;
            char *pid_end = strchr(pid_start, ';');
            if (pid_end) {
                *pid_end = '\0';
            }
            ssh_config->agent_pid = (pid_t)strtol(pid_start, NULL, 10);
        }
        
        line = strtok_r(NULL, "\n", &saveptr);
    }
    
    free(output_copy);
    
    /* Validate we got the required information */
    if (strlen(ssh_config->agent_socket_path) == 0 || ssh_config->agent_pid <= 0) {
        set_error(ERR_SSH_AGENT_START_FAILED, "Failed to parse ssh-agent output");
        return -1;
    }
    
    return 0;
}