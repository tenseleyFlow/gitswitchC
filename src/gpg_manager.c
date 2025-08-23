/* GPG key and environment management with comprehensive isolation and security
 * Implements per-account GNUPGHOME environments to prevent GPG key mixing
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

#include "gpg_manager.h"
#include "error.h"
#include "utils.h"
#include "display.h"
#include "git_ops.h"

/* Internal helper functions */
static int create_isolated_gnupg_home_dir(const char *gnupg_home);
static int execute_gpg_command_in_env(const gpg_config_t *gpg_config, 
                                       const char *command, char *output, size_t output_size);
static int copy_key_from_system_keyring(const gpg_config_t *gpg_config, const char *key_id);
static int validate_gnupg_home_permissions(const char *gnupg_home);
static int setup_gpg_agent_config(const char *gnupg_home);

/* Initialize GPG manager with specified mode */
int gpg_manager_init(gpg_config_t *gpg_config, gpg_mode_t mode) {
    if (!gpg_config) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_manager_init");
        return -1;
    }
    
    log_debug("Initializing GPG manager with mode: %d", mode);
    
    /* Initialize GPG configuration */
    memset(gpg_config, 0, sizeof(gpg_config_t));
    gpg_config->mode = mode;
    gpg_config->signing_enabled = false;
    gpg_config->home_owned = false;
    
    /* Initialize based on mode */
    switch (mode) {
        case GPG_MODE_SYSTEM:
            /* Use system GNUPGHOME */
            log_debug("Using system GPG environment");
            break;
            
        case GPG_MODE_ISOLATED:
            /* Will create isolated GNUPGHOME per account */
            log_debug("GPG manager initialized for isolated environments");
            break;
            
        case GPG_MODE_SHARED:
            /* Shared GNUPGHOME with key switching */
            log_debug("GPG manager initialized for shared environment");
            break;
            
        default:
            set_error(ERR_INVALID_ARGS, "Invalid GPG mode: %d", mode);
            return -1;
    }
    
    /* Verify GPG is available */
    if (!command_exists("gpg")) {
        set_error(ERR_GPG_NOT_FOUND, "GPG command not found in PATH");
        return -1;
    }
    
    log_info("GPG manager initialized successfully");
    return 0;
}

/* Cleanup GPG manager */
void gpg_manager_cleanup(gpg_config_t *gpg_config) {
    if (!gpg_config) {
        return;
    }
    
    log_debug("Cleaning up GPG manager");
    
    /* Clean up owned GNUPGHOME directory if needed */
    if (gpg_config->home_owned && strlen(gpg_config->gnupg_home) > 0) {
        log_debug("Cleaning up owned GNUPGHOME: %s", gpg_config->gnupg_home);
        
        /* Only remove if it's clearly our isolated directory */
        if (strstr(gpg_config->gnupg_home, "gitswitch-gpg") != NULL) {
            char command[512];
            if (safe_snprintf(command, sizeof(command), "rm -rf '%s'", gpg_config->gnupg_home) == 0) {
                if (system(command) != 0) {
                    log_warning("Failed to remove GNUPGHOME directory: %s", gpg_config->gnupg_home);
                } else {
                    log_debug("Successfully removed GNUPGHOME: %s", gpg_config->gnupg_home);
                }
            }
        }
    }
    
    /* Clear configuration */
    memset(gpg_config, 0, sizeof(gpg_config_t));
    
    log_debug("GPG manager cleanup completed");
}

/* Switch to account's GPG configuration with complete isolation */
int gpg_switch_account(gpg_config_t *gpg_config, const account_t *account) {
    if (!gpg_config || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_switch_account");
        return -1;
    }
    
    /* Skip if GPG not enabled for account */
    if (!account->gpg_enabled || strlen(account->gpg_key_id) == 0) {
        log_debug("GPG not enabled for account: %s", account->name);
        return 0;
    }
    
    log_info("Switching to GPG configuration for account: %s", account->name);
    log_debug("Account GPG key ID: %s", account->gpg_key_id);
    
    /* Handle different GPG modes */
    switch (gpg_config->mode) {
        case GPG_MODE_SYSTEM:
            /* Just validate key exists in system keyring */
            if (gpg_validate_key(gpg_config, account->gpg_key_id) != 0) {
                set_error(ERR_GPG_KEY_NOT_FOUND, "GPG key not found in system keyring: %s", 
                         account->gpg_key_id);
                return -1;
            }
            break;
            
        case GPG_MODE_ISOLATED:
            /* Create isolated GNUPGHOME for account */
            if (gpg_create_isolated_home(gpg_config, account) != 0) {
                set_error(ERR_GPG_KEY_FAILED, "Failed to create isolated GPG environment: %s", 
                         get_last_error()->message);
                return -1;
            }
            
            /* Copy key from system keyring to isolated environment */
            if (copy_key_from_system_keyring(gpg_config, account->gpg_key_id) != 0) {
                log_warning("Failed to copy GPG key to isolated environment: %s", 
                           get_last_error()->message);
                /* Continue anyway - maybe key is already there */
            }
            
            /* Validate key is available in isolated environment */
            if (gpg_validate_key(gpg_config, account->gpg_key_id) != 0) {
                set_error(ERR_GPG_KEY_NOT_FOUND, "GPG key not available in isolated environment: %s", 
                         account->gpg_key_id);
                return -1;
            }
            break;
            
        case GPG_MODE_SHARED:
            /* Validate key exists and switch to it */
            if (gpg_validate_key(gpg_config, account->gpg_key_id) != 0) {
                set_error(ERR_GPG_KEY_NOT_FOUND, "GPG key not found: %s", account->gpg_key_id);
                return -1;
            }
            break;
            
        default:
            set_error(ERR_INVALID_ARGS, "Invalid GPG mode: %d", gpg_config->mode);
            return -1;
    }
    
    /* Update GPG configuration */
    safe_strncpy(gpg_config->current_key_id, account->gpg_key_id, sizeof(gpg_config->current_key_id));
    gpg_config->signing_enabled = account->gpg_signing_enabled;
    
    /* Set environment variable if using isolated mode */
    if (gpg_config->mode == GPG_MODE_ISOLATED) {
        if (gpg_set_environment(gpg_config) != 0) {
            log_warning("Failed to set GPG environment variable: %s", get_last_error()->message);
        }
    }
    
    /* Test GPG signing if enabled */
    if (account->gpg_signing_enabled) {
        if (gpg_test_signing(gpg_config, account->gpg_key_id) != 0) {
            log_warning("GPG signing test failed for key: %s", account->gpg_key_id);
            /* Don't fail completely, just warn */
        } else {
            log_info("GPG signing test passed for key: %s", account->gpg_key_id);
        }
    }
    
    log_info("Successfully switched to GPG configuration for account: %s", account->name);
    return 0;
}

/* Create isolated GNUPGHOME for account */
int gpg_create_isolated_home(gpg_config_t *gpg_config, const account_t *account) {
    char gnupg_base_dir[MAX_PATH_LEN];
    char gnupg_home[MAX_PATH_LEN];
    const char *home_dir;
    const char *runtime_dir;
    
    if (!gpg_config || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_create_isolated_home");
        return -1;
    }
    
    /* Determine base directory for isolated GNUPGHOME */
    runtime_dir = getenv("XDG_RUNTIME_DIR");
    home_dir = getenv("HOME");
    
    if (runtime_dir) {
        /* Use XDG runtime directory if available */
        if (safe_snprintf(gnupg_base_dir, sizeof(gnupg_base_dir), "%s/gitswitch-gpg", runtime_dir) != 0) {
            set_error(ERR_INVALID_PATH, "GNUPG base directory path too long");
            return -1;
        }
    } else if (home_dir) {
        /* Fall back to home directory */
        if (safe_snprintf(gnupg_base_dir, sizeof(gnupg_base_dir), "%s/.local/run/gitswitch-gpg", home_dir) != 0) {
            set_error(ERR_INVALID_PATH, "GNUPG base directory path too long");
            return -1;
        }
    } else {
        /* Last resort: use /tmp */
        if (safe_snprintf(gnupg_base_dir, sizeof(gnupg_base_dir), "/tmp/gitswitch-gpg-%d", getuid()) != 0) {
            set_error(ERR_INVALID_PATH, "GNUPG base directory path too long");
            return -1;
        }
    }
    
    /* Create base directory */
    if (create_directory_recursive(gnupg_base_dir, 0700) != 0) {
        set_error(ERR_FILE_IO, "Failed to create GPG base directory: %s", gnupg_base_dir);
        return -1;
    }
    
    /* Create account-specific GNUPGHOME */
    if (safe_snprintf(gnupg_home, sizeof(gnupg_home), "%s/%s", gnupg_base_dir, account->name) != 0) {
        set_error(ERR_INVALID_PATH, "GNUPGHOME path too long");
        return -1;
    }
    
    /* Create isolated GNUPGHOME directory */
    if (create_isolated_gnupg_home_dir(gnupg_home) != 0) {
        return -1;
    }
    
    /* Set up GPG agent configuration */
    if (setup_gpg_agent_config(gnupg_home) != 0) {
        log_warning("Failed to set up GPG agent config: %s", get_last_error()->message);
        /* Continue anyway */
    }
    
    /* Update GPG configuration */
    safe_strncpy(gpg_config->gnupg_home, gnupg_home, sizeof(gpg_config->gnupg_home));
    gpg_config->home_owned = true;
    
    log_info("Created isolated GNUPGHOME: %s", gnupg_home);
    return 0;
}

/* Import GPG key from file or keyserver */
int gpg_import_key(gpg_config_t *gpg_config, const char *key_source) {
    char command[512];
    char output[1024];
    int result;
    
    if (!gpg_config || !key_source) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_import_key");
        return -1;
    }
    
    log_debug("Importing GPG key from: %s", key_source);
    
    /* Check if key_source is a file or key ID */
    if (path_exists(key_source)) {
        /* Import from file */
        if (safe_snprintf(command, sizeof(command), "gpg --import '%s'", key_source) != 0) {
            set_error(ERR_INVALID_ARGS, "GPG import command too long");
            return -1;
        }
    } else {
        /* Import from keyserver */
        if (safe_snprintf(command, sizeof(command), "gpg --keyserver hkps://keys.openpgp.org --recv-keys %s", 
                         key_source) != 0) {
            set_error(ERR_INVALID_ARGS, "GPG keyserver command too long");
            return -1;
        }
    }
    
    /* Execute import command */
    result = execute_gpg_command_in_env(gpg_config, command, output, sizeof(output));
    if (result != 0) {
        set_error(ERR_GPG_KEY_FAILED, "Failed to import GPG key: %s", output);
        return -1;
    }
    
    log_info("Successfully imported GPG key from: %s", key_source);
    return 0;
}

/* Export GPG public key for backup/sharing */
int gpg_export_public_key(gpg_config_t *gpg_config, const char *key_id, 
                          char *output, size_t output_size) {
    char command[256];
    
    if (!gpg_config || !key_id || !output || output_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_export_public_key");
        return -1;
    }
    
    if (safe_snprintf(command, sizeof(command), "gpg --armor --export %s", key_id) != 0) {
        set_error(ERR_INVALID_ARGS, "GPG export command too long");
        return -1;
    }
    
    return execute_gpg_command_in_env(gpg_config, command, output, output_size);
}

/* List available GPG keys */
int gpg_list_keys(gpg_config_t *gpg_config, char *output, size_t output_size) {
    if (!gpg_config || !output || output_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_list_keys");
        return -1;
    }
    
    return execute_gpg_command_in_env(gpg_config, "gpg --list-keys --with-colons", output, output_size);
}

/* Validate GPG key exists and is usable */
int gpg_validate_key(gpg_config_t *gpg_config, const char *key_id) {
    char command[256];
    char output[512];
    int result;
    
    if (!gpg_config || !key_id) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_validate_key");
        return -1;
    }
    
    log_debug("Validating GPG key: %s", key_id);
    
    /* Check if key exists in keyring */
    if (safe_snprintf(command, sizeof(command), "gpg --list-secret-keys %s", key_id) != 0) {
        set_error(ERR_INVALID_ARGS, "GPG validation command too long");
        return -1;
    }
    
    result = execute_gpg_command_in_env(gpg_config, command, output, sizeof(output));
    if (result != 0) {
        set_error(ERR_GPG_KEY_NOT_FOUND, "GPG key not found: %s", key_id);
        return -1;
    }
    
    log_debug("GPG key validation passed: %s", key_id);
    return 0;
}

/* Configure git GPG signing */
int gpg_configure_git_signing(gpg_config_t *gpg_config, const account_t *account, git_scope_t scope) {
    if (!gpg_config || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_configure_git_signing");
        return -1;
    }
    
    /* Skip if GPG signing not enabled */
    if (!account->gpg_signing_enabled) {
        log_debug("GPG signing not enabled for account: %s", account->name);
        
        /* Disable git signing */
        if (git_set_config_value("commit.gpgsign", "false", scope) != 0) {
            log_warning("Failed to disable git GPG signing");
        }
        return 0;
    }
    
    log_info("Configuring git GPG signing for account: %s", account->name);
    
    /* Set signing key */
    if (git_set_config_value("user.signingkey", account->gpg_key_id, scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to set git signing key");
        return -1;
    }
    
    /* Enable GPG signing */
    if (git_set_config_value("commit.gpgsign", "true", scope) != 0) {
        set_error(ERR_GIT_CONFIG_FAILED, "Failed to enable git GPG signing");
        return -1;
    }
    
    /* Set GPG program if using isolated environment */
    if (gpg_config->mode == GPG_MODE_ISOLATED && strlen(gpg_config->gnupg_home) > 0) {
        char gpg_command[MAX_PATH_LEN + 50];
        if (safe_snprintf(gpg_command, sizeof(gpg_command), "gpg --homedir '%s'", gpg_config->gnupg_home) == 0) {
            if (git_set_config_value("gpg.program", gpg_command, scope) != 0) {
                log_warning("Failed to set git GPG program");
            }
        }
    }
    
    log_info("Git GPG signing configured successfully for account: %s", account->name);
    return 0;
}

/* Test GPG signing by creating a test signature */
int gpg_test_signing(gpg_config_t *gpg_config, const char *key_id) {
    char command[512];
    char output[1024];
    int result;
    
    if (!gpg_config || !key_id) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_test_signing");
        return -1;
    }
    
    log_debug("Testing GPG signing with key: %s", key_id);
    
    /* Create test signature */
    if (safe_snprintf(command, sizeof(command), 
                     "echo 'GPG signing test' | gpg --clearsign --local-user %s", key_id) != 0) {
        set_error(ERR_INVALID_ARGS, "GPG test command too long");
        return -1;
    }
    
    result = execute_gpg_command_in_env(gpg_config, command, output, sizeof(output));
    if (result != 0) {
        set_error(ERR_GPG_SIGNING_FAILED, "GPG signing test failed: %s", output);
        return -1;
    }
    
    /* Verify the signature contains expected content */
    if (strstr(output, "BEGIN PGP SIGNED MESSAGE") == NULL) {
        set_error(ERR_GPG_SIGNING_FAILED, "GPG signing test produced invalid output");
        return -1;
    }
    
    log_debug("GPG signing test passed for key: %s", key_id);
    return 0;
}

/* Generate new GPG key for account */
int gpg_generate_key(gpg_config_t *gpg_config, const account_t *account) {
    char command[1024];
    char key_params[512];
    char output[2048];
    int result;
    
    if (!gpg_config || !account) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_generate_key");
        return -1;
    }
    
    log_info("Generating new GPG key for account: %s", account->name);
    
    /* Create key generation parameters */
    if (safe_snprintf(key_params, sizeof(key_params),
                     "Key-Type: RSA\n"
                     "Key-Length: 4096\n"
                     "Subkey-Type: RSA\n"
                     "Subkey-Length: 4096\n"
                     "Name-Real: %s\n"
                     "Name-Email: %s\n"
                     "Expire-Date: 2y\n"
                     "%%commit\n"
                     "%%echo done\n",
                     account->name, account->email) != 0) {
        set_error(ERR_INVALID_ARGS, "GPG key parameters too long");
        return -1;
    }
    
    /* Generate key */
    if (safe_snprintf(command, sizeof(command), "echo '%s' | gpg --batch --generate-key", key_params) != 0) {
        set_error(ERR_INVALID_ARGS, "GPG generation command too long");
        return -1;
    }
    
    result = execute_gpg_command_in_env(gpg_config, command, output, sizeof(output));
    if (result != 0) {
        set_error(ERR_GPG_KEY_FAILED, "Failed to generate GPG key: %s", output);
        return -1;
    }
    
    log_info("Successfully generated GPG key for account: %s", account->name);
    return 0;
}

/* Set environment variables for GPG operation */
int gpg_set_environment(const gpg_config_t *gpg_config) {
    if (!gpg_config) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to gpg_set_environment");
        return -1;
    }
    
    /* Set GNUPGHOME if using isolated mode */
    if (gpg_config->mode == GPG_MODE_ISOLATED && strlen(gpg_config->gnupg_home) > 0) {
        if (setenv("GNUPGHOME", gpg_config->gnupg_home, 1) != 0) {
            set_system_error(ERR_SYSTEM_CALL, "Failed to set GNUPGHOME environment variable");
            return -1;
        }
        
        log_debug("Set GNUPGHOME environment variable: %s", gpg_config->gnupg_home);
    }
    
    return 0;
}

/* Internal helper functions */

/* Create isolated GNUPGHOME directory with proper permissions */
static int create_isolated_gnupg_home_dir(const char *gnupg_home) {
    if (!gnupg_home) {
        set_error(ERR_INVALID_ARGS, "NULL gnupg_home path");
        return -1;
    }
    
    /* Create directory with 700 permissions */
    if (create_directory_recursive(gnupg_home, 0700) != 0) {
        set_error(ERR_FILE_IO, "Failed to create GNUPGHOME directory: %s", gnupg_home);
        return -1;
    }
    
    /* Validate permissions */
    if (validate_gnupg_home_permissions(gnupg_home) != 0) {
        return -1;
    }
    
    log_debug("Created isolated GNUPGHOME directory: %s", gnupg_home);
    return 0;
}

/* Execute GPG command in specified environment */
static int execute_gpg_command_in_env(const gpg_config_t *gpg_config, 
                                       const char *command, char *output, size_t output_size) {
    char full_command[1024];
    FILE *fp;
    int status;
    size_t bytes_read;
    
    if (!gpg_config || !command || !output || output_size == 0) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to execute_gpg_command_in_env");
        return -1;
    }
    
    /* Prepare command with GNUPGHOME if needed */
    if (gpg_config->mode == GPG_MODE_ISOLATED && strlen(gpg_config->gnupg_home) > 0) {
        if (safe_snprintf(full_command, sizeof(full_command), 
                         "GNUPGHOME='%s' %s 2>&1", gpg_config->gnupg_home, command) != 0) {
            set_error(ERR_INVALID_ARGS, "GPG command too long");
            return -1;
        }
    } else {
        if (safe_snprintf(full_command, sizeof(full_command), "%s 2>&1", command) != 0) {
            set_error(ERR_INVALID_ARGS, "GPG command too long");
            return -1;
        }
    }
    
    log_debug("Executing GPG command: %s", full_command);
    
    /* Execute command */
    fp = popen(full_command, "r");
    if (!fp) {
        set_system_error(ERR_SYSTEM_COMMAND_FAILED, "Failed to execute GPG command");
        return -1;
    }
    
    /* Read output */
    bytes_read = fread(output, 1, output_size - 1, fp);
    output[bytes_read] = '\0';
    
    status = pclose(fp);
    if (status != 0) {
        log_debug("GPG command failed with status: %d, output: %s", status, output);
        return -1;
    }
    
    log_debug("GPG command completed successfully");
    return 0;
}

/* Copy GPG key from system keyring to isolated environment */
static int copy_key_from_system_keyring(const gpg_config_t *gpg_config, const char *key_id) {
    char export_command[256];
    char import_command[512];
    char key_data[8192];
    FILE *export_fp, *import_fp;
    int export_status, import_status;
    size_t bytes_read;
    
    if (!gpg_config || !key_id) {
        set_error(ERR_INVALID_ARGS, "Invalid arguments to copy_key_from_system_keyring");
        return -1;
    }
    
    log_debug("Copying GPG key from system keyring: %s", key_id);
    
    /* Export key from system keyring */
    if (safe_snprintf(export_command, sizeof(export_command), 
                     "gpg --armor --export-secret-keys %s 2>/dev/null", key_id) != 0) {
        set_error(ERR_INVALID_ARGS, "Export command too long");
        return -1;
    }
    
    export_fp = popen(export_command, "r");
    if (!export_fp) {
        set_system_error(ERR_SYSTEM_COMMAND_FAILED, "Failed to export GPG key");
        return -1;
    }
    
    bytes_read = fread(key_data, 1, sizeof(key_data) - 1, export_fp);
    key_data[bytes_read] = '\0';
    
    export_status = pclose(export_fp);
    if (export_status != 0 || bytes_read == 0) {
        set_error(ERR_GPG_KEY_NOT_FOUND, "Failed to export GPG key from system keyring");
        return -1;
    }
    
    /* Import key into isolated environment */
    if (safe_snprintf(import_command, sizeof(import_command), 
                     "GNUPGHOME='%s' gpg --batch --import 2>/dev/null", gpg_config->gnupg_home) != 0) {
        set_error(ERR_INVALID_ARGS, "Import command too long");
        return -1;
    }
    
    import_fp = popen(import_command, "w");
    if (!import_fp) {
        set_system_error(ERR_SYSTEM_COMMAND_FAILED, "Failed to start GPG import");
        return -1;
    }
    
    fwrite(key_data, 1, bytes_read, import_fp);
    import_status = pclose(import_fp);
    
    if (import_status != 0) {
        set_error(ERR_GPG_KEY_FAILED, "Failed to import GPG key into isolated environment");
        return -1;
    }
    
    log_info("Successfully copied GPG key to isolated environment: %s", key_id);
    return 0;
}

/* Validate GNUPGHOME directory permissions */
static int validate_gnupg_home_permissions(const char *gnupg_home) {
    mode_t dir_mode;
    
    if (!gnupg_home) {
        set_error(ERR_INVALID_ARGS, "NULL gnupg_home path");
        return -1;
    }
    
    if (get_file_permissions(gnupg_home, &dir_mode) != 0) {
        set_error(ERR_FILE_IO, "Failed to check GNUPGHOME permissions: %s", gnupg_home);
        return -1;
    }
    
    /* Check for 700 permissions */
    if ((dir_mode & 0777) != 0700) {
        set_error(ERR_PERMISSION_DENIED, "GNUPGHOME has insecure permissions: %o", dir_mode & 0777);
        return -1;
    }
    
    log_debug("GNUPGHOME permissions validated: %s", gnupg_home);
    return 0;
}

/* Set up GPG agent configuration for isolated environment */
static int setup_gpg_agent_config(const char *gnupg_home) {
    char gpg_agent_conf_path[MAX_PATH_LEN];
    FILE *conf_file;
    
    if (!gnupg_home) {
        set_error(ERR_INVALID_ARGS, "NULL gnupg_home path");
        return -1;
    }
    
    /* Create gpg-agent.conf path */
    if (safe_snprintf(gpg_agent_conf_path, sizeof(gpg_agent_conf_path), 
                     "%s/gpg-agent.conf", gnupg_home) != 0) {
        set_error(ERR_INVALID_PATH, "GPG agent config path too long");
        return -1;
    }
    
    /* Create basic gpg-agent.conf */
    conf_file = fopen(gpg_agent_conf_path, "w");
    if (!conf_file) {
        set_system_error(ERR_FILE_IO, "Failed to create gpg-agent.conf");
        return -1;
    }
    
    fprintf(conf_file, "# GPG Agent configuration for gitswitch isolated environment\n");
    fprintf(conf_file, "default-cache-ttl 3600\n");
    fprintf(conf_file, "max-cache-ttl 7200\n");
    fprintf(conf_file, "pinentry-program /usr/bin/pinentry-curses\n");
    
    fclose(conf_file);
    
    /* Set proper permissions */
    if (chmod(gpg_agent_conf_path, 0600) != 0) {
        set_system_error(ERR_PERMISSION_DENIED, "Failed to set gpg-agent.conf permissions");
        return -1;
    }
    
    log_debug("Created GPG agent configuration: %s", gpg_agent_conf_path);
    return 0;
}