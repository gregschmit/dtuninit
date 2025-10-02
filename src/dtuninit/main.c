/*
 * Dynamic Tunnel Initiator: Userspace Program
 *
 * This program's primary subcommand `start` loads/unload the BPF programs and monitors the clients
 * file to keep the BPF maps updated. It also provides subcommands for adding/removing clients, to
 * avoid requiring users of this software from having to manually parse and write to the clients
 * file.
 */

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../shared.h"
#include "log.h"
#include "watch.h"
#include "bpf_state.h"

#define DEFAULT_CLIENTS_FN "dtuninit_clients"
#define DEFAULT_CLIENTS_PATH "/var/run/" DEFAULT_CLIENTS_FN
#define DEFAULT_BPF_FN "dtuninit_bpf.o"
#define DEFAULT_BPF_PATH "/usr/bin/" DEFAULT_BPF_FN

#define VERSION_S "dtuninit " VERSION
#define USAGE_S \
    VERSION_S "\nThe Dynamic Tunnel Initiator\n\n" \
    "Usage: dtuninit [OPTIONS]\n\n" \
    "Options:\n" \
    "  -B <FILE>  Set BPF object file (default: `" DEFAULT_BPF_FN "` from current dir or\n" \
    "             `" DEFAULT_BPF_PATH "`).\n" \
    "  -C <FILE>  Set Clients file (default: `" DEFAULT_CLIENTS_FN "` from current dir or\n" \
    "             `" DEFAULT_CLIENTS_PATH "`).\n" \
    "  -d         Enable debug logging.\n" \
    "  -i <IF>    Bind to selected interface.\n" \
    "  -V         Show version.\n" \
    "  -h -?      Show usage.\n"

volatile bool INTERRUPT = false;

// Static storage to hold input interface data.
static unsigned N_IFS = 0;
static char IFS[MAX_IFS][MAX_IF_NAME_LEN] = {0};
static char *IFS_PTRS[MAX_IFS + 1] = {0};  // Must be NULL-terminated.

void interrupt_handler(int _signum) {
    INTERRUPT = true;
}

bool start(char *bpf_path, char *clients_path) {
    log_info("Registering signal handlers.");
    signal(SIGHUP, interrupt_handler);  // TODO: Consider reloading on SIGHUP.
    signal(SIGINT, interrupt_handler);
    signal(SIGTERM, interrupt_handler);
    signal(SIGQUIT, interrupt_handler);

    log_info("BPF object file: `%s`.", bpf_path);
    log_info("Clients file: `%s`.", clients_path);
    log_info("Loading BPF programs.");
    BPFState *state = bpf_state__open(bpf_path, clients_path, N_IFS ? IFS_PTRS : NULL);
    if (!state) {
        log_error("Failed to load BPF state.");
        return false;
    }

    // Watch and update state on changes.
    bool watch_success = watch(state);

    log_info("Unloading BPF programs.");
    bpf_state__close(state);

    return watch_success;
}

int main(int argc, char *argv[]) {
    char bpf_path[PATH_MAX] = "";
    char clients_path[PATH_MAX] = "";

    // Detect if we have a TTY that also supports color.
    if (isatty(fileno(stderr))) {
        if (getenv("COLORTERM")) {
            COLOR = true;
        }

        char *term = getenv("TERM");
        if (
            strstr(term, "color") ||
            strstr(term, "xterm") ||
            strstr(term, "screen") ||
            strstr(term, "linux") ||
            strstr(term, "rxvt") ||
            strstr(term, "vt100") ||
            strstr(term, "ansi")
        ) {
            COLOR = true;
        }
    }

    // Try to find BPF object file and Clients file in current directory.
    char cwd[PATH_MAX] = "";
    if (getcwd(cwd, sizeof(cwd))) {
        size_t cwd_len = strlen(cwd);

        if (cwd_len + 1 + sizeof(DEFAULT_BPF_FN) >= sizeof(bpf_path)) {
            log_error("Working directory is too long for BPF file.");
        } else {
            snprintf(bpf_path, sizeof(bpf_path), "%s/%s", cwd, DEFAULT_BPF_FN);
            FILE *fp = fopen(bpf_path, "r");
            if (fp) {
                fclose(fp);
            } else {
                log_error("Working directory BPF object file could not be opened.");
                bpf_path[0] = '\0';
            }
        }

        if (cwd_len + 1 + sizeof(DEFAULT_CLIENTS_FN) >= sizeof(clients_path)) {
            log_error("Working directory is too long for Clients file.");
        } else {
            snprintf(clients_path, sizeof(clients_path), "%s/%s", cwd, DEFAULT_CLIENTS_FN);
            FILE *fp = fopen(clients_path, "r");
            if (fp) {
                fclose(fp);
            } else {
                log_error("Working directory Clients file could not be opened.");
                clients_path[0] = '\0';
            }
        }
    } else {
        log_errno("getcwd");
        log_error("Failed to get working directory.");
    }

    int ch;
    while ((ch = getopt(argc, argv, "B:C:di:Vh?")) != -1) {
        switch (ch) {
            case 'B': {
                size_t bpf_length = strlen(optarg);
                if (bpf_length <= 0) {
                    log_error("Invalid BPF object file path.");
                    return 1;
                } else if (bpf_length >= PATH_MAX) {
                    log_error("BPF object file path is too long.");
                    return 1;
                } else {
                    snprintf(bpf_path, sizeof(bpf_path), "%s", optarg);
                }

                break;
            }
            case 'C': {
                size_t clients_length = strlen(optarg);
                if (clients_length <= 0) {
                    log_error("Invalid Clients file path.");
                    return 1;
                } else if (clients_length >= PATH_MAX) {
                    log_error("Clients file path is too long.");
                    return 1;
                } else {
                    snprintf(clients_path, sizeof(clients_path), "%s", optarg);
                }

                break;
            }
            case 'd': {
                DEBUG = true;
                break;
            }
            case 'i': {
                if (N_IFS >= MAX_IFS) {
                    log_error("Exceeded max interfaces (%d); ignoring %s", MAX_IFS, optarg);
                } else {
                    snprintf(IFS[N_IFS], sizeof(IFS[N_IFS]), "%s", optarg);
                    IFS_PTRS[N_IFS] = IFS[N_IFS];
                    N_IFS++;
                }
                break;
            }
            case 'V': {
                log_info("%s", VERSION_S);
                exit(0);
                break;
            }
            case 'h':
            case '?': {
                log_info("%s", USAGE_S);
                exit(0);
                break;
            }
            default: {
                log_error("%s", USAGE_S);
                exit(1);
                break;
            }
        }
    }

    // Set default BPF object path and Clients path if not set.
    if (!bpf_path[0]) {
        snprintf(bpf_path, sizeof(bpf_path), "%s", DEFAULT_BPF_PATH);
    }
    if (!clients_path[0]) {
        snprintf(clients_path, sizeof(clients_path), "%s", DEFAULT_CLIENTS_PATH);
    }

    // Check if BPF object file can be read.
    FILE *fp = fopen(bpf_path, "r");
    if (fp == NULL) {
        log_errno("fopen");
        log_error("BPF object file could not be opened.");
        return 1;
    } else {
        fclose(fp);
    }

    bool success = start(bpf_path, clients_path);

    return success ? 0 : 1;
}
