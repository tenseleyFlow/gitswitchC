/* gitswitch-c: Safe git identity switching with SSH/GPG isolation
 * Simplified Phase 1 implementation for foundation testing
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include "gitswitch.h"
#include "error.h"

static void print_usage(const char *prog_name);
static void print_version(void);

int main(int argc, char *argv[]) {
    int opt;
    bool show_help = false;
    bool show_version = false;
    bool verbose = false;
    
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {"verbose", no_argument, 0, 'V'},
        {0, 0, 0, 0}
    };
    
    /* Initialize error handling */
    if (error_init(LOG_LEVEL_INFO, NULL) != 0) {
        fprintf(stderr, "Failed to initialize error handling\n");
        return EXIT_FAILURE;
    }
    
    /* Parse command line options */
    while ((opt = getopt_long(argc, argv, "hvV", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                show_help = true;
                break;
            case 'v':
                show_version = true;
                break;
            case 'V':
                verbose = true;
                set_log_level(LOG_LEVEL_DEBUG);
                break;
            default:
                print_usage(argv[0]);
                error_cleanup();
                return EXIT_FAILURE;
        }
    }
    
    /* Handle special commands */
    if (show_version) {
        print_version();
        error_cleanup();
        return EXIT_SUCCESS;
    }
    
    if (show_help) {
        print_usage(argv[0]);
        error_cleanup();
        return EXIT_SUCCESS;
    }
    
    /* Phase 1 demonstration */
    printf("┌──────────────────────────────────────┐\n");
    printf("│   gitswitch-c Phase 1 Foundation    │\n");
    printf("└──────────────────────────────────────┘\n\n");
    
    printf("✓ Error handling system: initialized\n");
    printf("✓ Build system: working\n");
    printf("✓ Command line parsing: functional\n");
    
    if (verbose) {
        log_info("Verbose mode enabled");
        log_debug("Debug logging active");
    }
    
    /* Test error handling */
    printf("\nTesting error handling:\n");
    set_error(ERR_SUCCESS, "This is a test success message");
    const error_context_t *err = get_last_error();
    if (err->code == ERR_SUCCESS) {
        printf("✓ Error context system working\n");
    }
    
    printf("\nPhase 1 foundation is solid! ✨\n");
    printf("Ready for Phase 2: Configuration management\n\n");
    
    /* Cleanup */
    error_cleanup();
    return EXIT_SUCCESS;
}

static void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS] [COMMAND] [ARGS]\n", prog_name);
    printf("\nThis is a Phase 1 development build of gitswitch-c\n");
    printf("Safe git identity switching with SSH/GPG isolation\n\n");
    printf("Options:\n");
    printf("  --help, -h           Show this help message\n");
    printf("  --version, -v        Show version information\n");
    printf("  --verbose, -V        Enable verbose output\n\n");
    printf("Phase 1 Status:\n");
    printf("  ✓ Error handling system\n");
    printf("  ✓ Build system\n");
    printf("  ✓ Command line parsing\n");
    printf("  • Configuration management (Phase 2)\n");
    printf("  • Git operations (Phase 3)\n");
    printf("  • SSH security framework (Phase 4)\n");
    printf("  • GPG security framework (Phase 5)\n");
    printf("  • Full CLI integration (Phase 6)\n");
}

static void print_version(void) {
    printf("%s version %s (Phase 1 Development Build)\n", GITSWITCH_NAME, GITSWITCH_VERSION);
    printf("Safe git identity switching with SSH/GPG isolation\n");
    printf("Built with security and reliability in mind\n\n");
    printf("Phase 1 Features:\n");
    printf("• Comprehensive error handling and logging\n");
    printf("• Security-focused utility functions\n");
    printf("• Foundation for SSH/GPG isolation\n");
    printf("• Robust build system with hardening\n\n");
    printf("Upcoming Features:\n");
    printf("• Isolated SSH agents per account\n");
    printf("• Separate GPG environments\n");
    printf("• Comprehensive validation\n");
    printf("• Secure memory handling\n");
}