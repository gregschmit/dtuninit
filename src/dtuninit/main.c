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
#include "bpf_state.h"
#include "bpf_state/clients_file.h"
#include "bpf_state/watch.h"

#ifdef UBUS
#include "ubus.h"
#endif

#define DEFAULT_CLIENTS_FN "dtuninit_clients.json"
#define DEFAULT_CLIENTS_PATH "/var/run/" DEFAULT_CLIENTS_FN
#define DEFAULT_BPF_FN "dtuninit_bpf.o"
#define DEFAULT_BPF_PATH "/usr/bin/" DEFAULT_BPF_FN

#define VERSION_S "dtuninit " VERSION
#define USAGE_HEADER_S VERSION_S "\nThe Dynamic Tunnel Initiator\n\n"
#define GLOBAL_GETOPT_S "+dh"  // Leading `+` disables GNU argv mutation behavior.
#define GLOBAL_OPTIONS_S \
    "  -d  Enable debug logging.\n" \
    "  -h  Show usage."
#define GLOBAL_USAGE_S USAGE_HEADER_S \
    "Usage: dtuninit <SUBCOMMAND> <OPTIONS>\n" \
    "\n" \
    "Subcommands:\n" \
    "  start     Start the BPF loader.\n" \
    "  client    Manage the clients file.\n" \
    "  version   Show version.\n" \
    "  help      Show usage.\n" \
    "\n" \
    "Global Options:\n" GLOBAL_OPTIONS_S
#define START_GETOPT_S GLOBAL_GETOPT_S "+B:C:i:"  // Leading `+` disables GNU argv mutation.
#define START_OPTIONS_S \
    "  -B <FILE>  Set BPF object file (default: `" DEFAULT_BPF_FN "` from current dir or\n" \
    "             `" DEFAULT_BPF_PATH "`).\n" \
    "  -C <FILE>  Set clients JSON file (default: `" DEFAULT_CLIENTS_FN "` from\n" \
    "             current dir or `" DEFAULT_CLIENTS_PATH "`).\n" \
    "  -i <IF>    Bind to selected interface (can be specified multiple times).\n"
#define START_USAGE_S USAGE_HEADER_S \
    "Usage: dtuninit start <OPTIONS>\n" \
    "\n" \
    "Start Options:\n" START_OPTIONS_S \
    "\n" \
    "Global Options:\n" GLOBAL_OPTIONS_S
#define CLIENT_GETOPT_S GLOBAL_GETOPT_S "C:"
#define CLIENT_OPTIONS_S \
    "  -C <FILE>  Set clients JSON file (default: `" DEFAULT_CLIENTS_FN "` from\n" \
    "             current dir or `" DEFAULT_CLIENTS_PATH "`).\n"
#define CLIENT_USAGE_S USAGE_HEADER_S \
    "Usage: dtuninit client <SUBCOMMAND> <OPTIONS>\n" \
    "\n" \
    "Subcommands:\n" \
    "  insert <MAC>  Insert a client into the clients file.\n" \
    "  remove <MAC>  Remove a client from the clients file.\n" \
    "  help          Show usage.\n" \
    "\n" \
    "Client Options:\n" CLIENT_OPTIONS_S \
    "\n" \
    "Global Options:\n" GLOBAL_OPTIONS_S
#define CLIENT_INSERT_GETOPT_S CLIENT_GETOPT_S "p:P:v:"
#define CLIENT_INSERT_OPTIONS_S \
    "  -p <PROTOCOL>  Set the protocol (e.g., `gre`, `gre/udp`).\n" \
    "  -P <PEER_IP>   Set the Peer IPv4 address.\n" \
    "  -v <VLAN>      Set the VLAN ID (optional).\n"
#define CLIENT_INSERT_USAGE_S USAGE_HEADER_S \
    "Usage: dtuninit client insert <MAC> <OPTIONS>\n" \
    "\n" \
    "Client Insert Options:\n" CLIENT_INSERT_OPTIONS_S \
    "\n" \
    "Client Options:\n" CLIENT_OPTIONS_S \
    "\n" \
    "Global Options:\n" GLOBAL_OPTIONS_S

volatile bool INTERRUPT = false;

// Static storage to hold input interface data.
static unsigned N_IFS = 0;
static char IFS[MAX_IFS][MAX_IF_NAME_LEN] = {0};
static char *IFS_PTRS[MAX_IFS + 1] = {0};  // Must be NULL-terminated.

char BPF_PATH[PATH_MAX] = "";
char CLIENTS_PATH[PATH_MAX] = "";

static char *INSERT_REMOVE_MAC = NULL;
static char *INSERT_PROTOCOL = NULL;
static char *INSERT_PEER_IP = NULL;
static long INSERT_VLAN = 0;

void interrupt_handler(int _signum) {
    (void)_signum;
    INTERRUPT = true;
}

bool start() {
    log_info("Registering signal handlers.");
    signal(SIGHUP, interrupt_handler);  // TODO: Consider reloading on SIGHUP.
    signal(SIGINT, interrupt_handler);
    signal(SIGTERM, interrupt_handler);
    signal(SIGQUIT, interrupt_handler);

    log_info("BPF object file: `%s`", BPF_PATH);
    log_info("Clients file: `%s`", CLIENTS_PATH);
    log_info("Loading BPF programs.");
    BPFState *state = bpf_state__open(CLIENTS_PATH, N_IFS ? IFS_PTRS : NULL);
    if (!state) {
        log_error("Failed to open BPF state.");
        return false;
    }

    if (!bpf_state__load_bpf(state, BPF_PATH)) {
        bpf_state__close(state);
        return false;
    }

    if (!bpf_state__reload_interfaces(state)) {
        bpf_state__close(state);
        return false;
    }

    if (!bpf_state__reload_clients(state)) {
        bpf_state__close(state);
        return false;
    }

    // Watch and update state on changes.
    bool watch_success = bpf_state__watch(state);

    log_info("Unloading BPF programs.");
    bpf_state__close(state);

    return watch_success;
}

bool client_insert() {
    if (!INSERT_REMOVE_MAC) {
        log_error("No MAC address specified.");
        return false;
    }
    if (!INSERT_PROTOCOL) {
        log_error("No protocol specified.");
        return false;
    }
    if (!INSERT_PEER_IP) {
        log_error("No peer IP specified.");
        return false;
    }

    log_info("Clients file: `%s`", CLIENTS_PATH);
    BPFState *state = bpf_state__open(CLIENTS_PATH, N_IFS ? IFS_PTRS : NULL);
    if (!state) {
        log_error("Failed to open BPF state.");
        return false;
    }
    List *clients = list__new(
        sizeof(Client), sizeof(uint8_t) * ETH_ALEN, (list__key_eq_t)client__key_eq
    );
    if (!clients) {
        log_error("Failed to create client list.");
        bpf_state__close(state);
        return false;
    }

    Client client = {0};
    if (!client__parse(&client, INSERT_REMOVE_MAC, INSERT_PROTOCOL, INSERT_PEER_IP, INSERT_VLAN)) {
        bpf_state__close(state);
        list__free(clients);
        return false;
    }

    if (!list__add(clients, &client)) {
        bpf_state__close(state);
        list__free(clients);
        return false;
    }

    if (!bpf_state__clients_file__insert(state, clients)) {
        bpf_state__close(state);
        list__free(clients);
        return false;
    }

    log_info("Successfully inserted client: %s", INSERT_REMOVE_MAC);
    bpf_state__close(state);
    list__free(clients);
    return true;
}

bool client_remove() {
    if (!INSERT_REMOVE_MAC) {
        log_error("No MAC address specified.");
        return false;
    }

    log_info("Clients file: `%s`", CLIENTS_PATH);
    BPFState *state = bpf_state__open(CLIENTS_PATH, N_IFS ? IFS_PTRS : NULL);
    if (!state) {
        log_error("Failed to open BPF state.");
        return false;
    }

    if (!bpf_state__clients_file__remove_s(state, INSERT_REMOVE_MAC)) {
        bpf_state__close(state);
        return false;
    }

    log_info("Successfully removed client: %s", INSERT_REMOVE_MAC);
    bpf_state__close(state);
    return true;
}

void do_global_getopt(int argc, char **argv) {
    int ch;
    while ((ch = getopt(argc, argv, GLOBAL_GETOPT_S)) != -1) {
        switch (ch) {
            case 'd': {
                DEBUG = true;
                break;
            }
            case 'h': {
                log_info("%s", GLOBAL_USAGE_S);
                exit(0);
                break;
            }
            default: {
                log_error("Unknown option: %c", optopt);
                log_info("%s", GLOBAL_USAGE_S);
                exit(1);
                break;
            }
        }
    }
}

void do_start_getopt(int *rem_argc, char ***rem_argv) {
    // Subcommand parsers: reset `optind` to 1 since we only pass remaining args.
    optind = 1;

    int ch;
    // Subcommand parsers: modify `argv`/`argc` since `getopt` always skips the first argument.
    while ((ch = getopt(*rem_argc + 1, *rem_argv - 1, START_GETOPT_S)) != -1) {
        switch (ch) {
            case 'd': {
                DEBUG = true;
                break;
            }
            case 'h': {
                log_info("%s", START_USAGE_S);
                exit(0);
                break;
            }
            case 'B': {
                size_t bpf_length = strlen(optarg);
                if (bpf_length <= 0) {
                    log_error("BPF object file path cannot be blank.");
                    exit(1);
                } else if (bpf_length >= sizeof(BPF_PATH)) {
                    log_error("BPF object file path is too long.");
                    exit(1);
                } else {
                    snprintf(BPF_PATH, sizeof(BPF_PATH), "%s", optarg);
                }
                break;
            }
            case 'C': {
                size_t clients_length = strlen(optarg);
                if (clients_length <= 0) {
                    log_error("Clients file path cannot be blank.");
                    exit(1);
                } else if (clients_length >= sizeof(CLIENTS_PATH)) {
                    log_error("Clients file path is too long.");
                    exit(1);
                } else {
                    snprintf(CLIENTS_PATH, sizeof(CLIENTS_PATH), "%s", optarg);
                }
                break;
            }
            case 'i': {
                if (optarg[0] == '\0') {
                    log_error("Interface name cannot be blank.");
                    exit(1);
                }
                if (N_IFS >= MAX_IFS) {
                    log_error("Exceeded max interfaces (%d); ignoring %s", MAX_IFS, optarg);
                } else {
                    snprintf(IFS[N_IFS], sizeof(IFS[N_IFS]), "%s", optarg);
                    IFS_PTRS[N_IFS] = IFS[N_IFS];
                    N_IFS++;
                }
                break;
            }
            default: {
                log_error("Unknown option: %c", optopt);
                log_info("%s", START_USAGE_S);
                exit(1);
                break;
            }
        }
    }

    // Subcommand parsers: update remaining args.
    *rem_argc -= (optind - 1);
    *rem_argv += (optind - 1);
}

void do_client_getopt(int *rem_argc, char ***rem_argv) {
    // Subcommand parsers: reset `optind` to 1 since we only pass remaining args.
    optind = 1;

    int ch;
    // Subcommand parsers: modify `argv`/`argc` since `getopt` always skips the first argument.
    while ((ch = getopt(*rem_argc + 1, *rem_argv - 1, CLIENT_GETOPT_S)) != -1) {
        switch (ch) {
            case 'd': {
                DEBUG = true;
                break;
            }
            case 'h': {
                log_info("%s", CLIENT_USAGE_S);
                exit(0);
                break;
            }
            case 'C': {
                size_t clients_length = strlen(optarg);
                if (clients_length <= 0) {
                    log_error("Clients file path cannot be blank.");
                    exit(1);
                } else if (clients_length >= sizeof(CLIENTS_PATH)) {
                    log_error("Clients file path is too long.");
                    exit(1);
                } else {
                    snprintf(CLIENTS_PATH, sizeof(CLIENTS_PATH), "%s", optarg);
                }
                break;
            }
            default: {
                log_error("Unknown option: %c", optopt);
                log_info("%s", CLIENT_USAGE_S);
                exit(1);
                break;
            }
        }
    }

    // Subcommand parsers: update remaining args.
    *rem_argc -= (optind - 1);
    *rem_argv += (optind - 1);
}

void do_client_insert_getopt(int *rem_argc, char ***rem_argv) {
    // Subcommand parsers: reset `optind` to 1 since we only pass remaining args.
    optind = 1;

    int ch;
    while ((ch = getopt(*rem_argc + 1, *rem_argv - 1, CLIENT_INSERT_GETOPT_S)) != -1) {
        switch (ch) {
            case 'd': {
                DEBUG = true;
                break;
            }
            case 'h': {
                log_info("%s", CLIENT_INSERT_USAGE_S);
                exit(0);
                break;
            }
            case 'C': {
                size_t clients_length = strlen(optarg);
                if (clients_length <= 0) {
                    log_error("Clients file path cannot be blank.");
                    exit(1);
                } else if (clients_length >= sizeof(CLIENTS_PATH)) {
                    log_error("Clients file path is too long.");
                    exit(1);
                } else {
                    snprintf(CLIENTS_PATH, sizeof(CLIENTS_PATH), "%s", optarg);
                }
                break;
            }
            case 'p': {
                if (optarg[0] == '\0') {
                    log_error("Protocol cannot be blank.");
                    exit(1);
                }
                INSERT_PROTOCOL = optarg;
                break;
            }
            case 'P': {
                if (optarg[0] == '\0') {
                    log_error("Peer IP address cannot be blank.");
                    exit(1);
                }
                INSERT_PEER_IP = optarg;
                break;
            }
            case 'v': {
                if (optarg[0] == '\0') {
                    log_error("VLAN ID cannot be blank.");
                    exit(1);
                }
                char *endptr = NULL;
                INSERT_VLAN = strtol(optarg, &endptr, 10);
                if (!endptr || *endptr != '\0') {
                    log_error("Invalid VLAN ID: %s", optarg);
                    exit(1);
                }
                break;
            }
            default: {
                log_error("Unknown option: %c", optopt);
                log_info("%s", CLIENT_INSERT_USAGE_S);
                exit(1);
                break;
            }
        }
    }

    // Subcommand parsers: update remaining args.
    *rem_argc -= (optind - 1);
    *rem_argv += (optind - 1);
}

int main(int argc, char *argv[]) {
    // Detect if we have a TTY that also supports color.
    if (isatty(fileno(stderr))) {
        if (getenv("COLORTERM")) {
            COLOR = true;
        }

        char *term = getenv("TERM");
        if (
            term && (
                strstr(term, "color") ||
                strstr(term, "xterm") ||
                strstr(term, "screen") ||
                strstr(term, "linux") ||
                strstr(term, "rxvt") ||
                strstr(term, "vt100") ||
                strstr(term, "ansi")
            )
        ) {
            COLOR = true;
        }
    }

    // Try to find BPF object file and clients file in current directory.
    char cwd[PATH_MAX] = "";
    if (getcwd(cwd, sizeof(cwd))) {
        size_t cwd_len = strlen(cwd);

        if (cwd_len + 1 + sizeof(DEFAULT_BPF_FN) >= sizeof(BPF_PATH)) {
            log_error("Working directory is too long for BPF file.");
        } else {
            snprintf(BPF_PATH, sizeof(BPF_PATH), "%s/%s", cwd, DEFAULT_BPF_FN);
            FILE *fp = fopen(BPF_PATH, "r");
            if (fp) {
                fclose(fp);
            } else {
                dbg("Working directory BPF object file could not be opened.");
                BPF_PATH[0] = '\0';
            }
        }

        if (cwd_len + 1 + sizeof(DEFAULT_CLIENTS_FN) >= sizeof(CLIENTS_PATH)) {
            log_error("Working directory is too long for clients file.");
        } else {
            snprintf(CLIENTS_PATH, sizeof(CLIENTS_PATH), "%s/%s", cwd, DEFAULT_CLIENTS_FN);
            FILE *fp = fopen(CLIENTS_PATH, "r");
            if (fp) {
                fclose(fp);
            } else {
                dbg("Working directory clients file could not be opened.");
                CLIENTS_PATH[0] = '\0';
            }
        }
    } else {
        log_errno("getcwd");
        log_error("Failed to get working directory.");
    }

    // Get any prefix global options.
    do_global_getopt(argc, argv);

    // Setup some variables for tracking remaining args for proper subcommand parsing.
    int rem_argc = argc - optind;
    char **rem_argv = argv + optind;

    // Get the subcommand.
    if (rem_argc <= 0) {
        log_error("No subcommand specified.");
        log_info("%s", GLOBAL_USAGE_S);
        return 1;
    }
    char *subcommand = rem_argv[0];
    rem_argc -= 1;
    rem_argv += 1;

    bool success = true;
    if (!strcmp(subcommand, "start")) {
        do_start_getopt(&rem_argc, &rem_argv);

        if (rem_argc > 0) {
            log_error("Unexpected extra positional arguments.");
            log_info("%s", START_USAGE_S);
            return 1;
        }

        // Set default BPF object path and clients path if not set.
        if (!BPF_PATH[0]) {
            snprintf(BPF_PATH, sizeof(BPF_PATH), "%s", DEFAULT_BPF_PATH);
        }
        if (!CLIENTS_PATH[0]) {
            snprintf(CLIENTS_PATH, sizeof(CLIENTS_PATH), "%s", DEFAULT_CLIENTS_PATH);
        }

        success = start();
    } else if (!strcmp(subcommand, "client")) {
        do_client_getopt(&rem_argc, &rem_argv);

        if (rem_argc <= 0) {
            log_error("No client subcommand specified.");
            log_info("%s", CLIENT_USAGE_S);
            return 1;
        }

        char *client_subcommand = rem_argv[0];
        rem_argc -= 1;
        rem_argv += 1;

        if (!strcmp(client_subcommand, "insert")) {
            if (rem_argc <= 0) {
                log_error("No MAC address specified.");
                log_info("%s", CLIENT_INSERT_USAGE_S);
                return 1;
            }
            INSERT_REMOVE_MAC = rem_argv[0];
            rem_argc -= 1;
            rem_argv += 1;

            do_client_insert_getopt(&rem_argc, &rem_argv);
            if (rem_argc > 0) {
                log_error("Unexpected extra positional arguments.");
                log_info("%s", CLIENT_INSERT_USAGE_S);
                return 1;
            }
            success = client_insert();
        } else if (!strcmp(client_subcommand, "remove")) {
            if (rem_argc <= 0) {
                log_error("No MAC address specified.");
                log_info("%s", CLIENT_USAGE_S);
                return 1;
            }
            INSERT_REMOVE_MAC = rem_argv[0];
            rem_argc -= 1;
            rem_argv += 1;

            do_client_getopt(&rem_argc, &rem_argv);
            if (rem_argc > 0) {
                log_error("Unexpected extra positional arguments.");
                log_info("%s", CLIENT_USAGE_S);
                return 1;
            }
            success = client_remove();
        } else if (!strcmp(client_subcommand, "help")) {
            log_info("%s", CLIENT_USAGE_S);
        } else {
            log_error("Unknown client subcommand: `%s`.", client_subcommand);
            log_info("%s", CLIENT_USAGE_S);
            success = false;
        }
    } else if (!strcmp(subcommand, "help")) {
        log_info("%s", GLOBAL_USAGE_S);
    #ifdef UBUS
    } else if (!strcmp(subcommand, "ubus_list_objs")) {
        // Undocumented: for testing UBUS' ability to get hapd objs.
        const char **ubus_hapd_objs = ubus__hapd_list(NULL);
        if (ubus_hapd_objs) {
            for (unsigned i = 0; ubus_hapd_objs[i] != NULL; i++) {
                log_info("%s", ubus_hapd_objs[i]);
            }
        } else {
            success = false;
        }
    } else if (!strcmp(subcommand, "ubus_list_clients")) {
        // Undocumented: for testing UBUS' ability to get clients.
        List *clients = ubus__get_clients(NULL);
        if (clients) {
            list__free(clients);
        } else {
            return 1;
        }
    #endif  // UBUS
    } else if (!strcmp(subcommand, "version")) {
        log_info("%s", VERSION_S);
     } else {
        log_error("Unknown subcommand: `%s`.", subcommand);
        log_info("%s", GLOBAL_USAGE_S);
        return 1;
    }

    return success ? 0 : 1;
}
