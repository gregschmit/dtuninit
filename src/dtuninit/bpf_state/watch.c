/*
 * Logic for watching the clients file, network interface changes, and UBUS events to trigger BFP
 * mounting, unmounting, and data updates.
 */

#include <errno.h>
#include <libgen.h>
#include <limits.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "../log.h"

#include "watch.h"

#define EVENT_SIZE (sizeof(struct inotify_event))
#define BUF_LEN (EVENT_SIZE + NAME_MAX + 1)
#define TIMEOUT 1

// We need to statically know how many events we will poll for later.
#ifdef UBUS
#define N_EVENTS 3
#else
#define N_EVENTS 2
#endif

extern volatile bool INTERRUPT;

typedef struct {
    // For watching the clients file.
    char fn[NAME_MAX];
    char dpath[PATH_MAX];
    char fpath[PATH_MAX];
    int inotify_fd;
    int inotify_wd;
    bool inotify_wd_is_dir;

    // For watching the network interfaces.
    int socket_fd;

    #ifdef UBUS
    // For watching UBUS.
    struct ubus_context *ubus_ctx;
    int ubus_socket_fd;
    #endif
} WatchState;

static bool watch_file_init(BPFState *s, WatchState *ws) {
    if (!check_ptr("watch_file_init", "s", s)) { return false; }
    if (!check_ptr("watch_file_init", "ws", ws)) { return false; }

    // Extract the directory path and file name. We need them separately because we conditionally
    // watch either the file or the directory (if the file doesn't exist). We also re-create the
    // full file path so if the `clients_path` is just a bare filename, we get a more sensible
    // representation (e.g., `file.json` becomes `./file.json`).
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", s->clients_path);
    snprintf(ws->fn, sizeof(ws->fn), "%s", basename(tmp));
    snprintf(ws->dpath, sizeof(ws->dpath), "%s", dirname(tmp));
    snprintf(ws->fpath, sizeof(ws->fpath), "%s/%s", ws->dpath, ws->fn);

    // Initialize `inotify`.
    ws->inotify_fd = inotify_init();
    if (ws->inotify_fd < 0) {
        log_errno("inotify_init");
        return false;
    }
    ws->inotify_wd = -1;

    return true;
}

static bool watch_file_setup(BPFState *s, WatchState *ws) {
    if (!check_ptr("watch_file_setup", "s", s)) { return false; }
    if (!check_ptr("watch_file_setup", "ws", ws)) { return false; }

    // If `ws->inotify_wd < 0`, then try to watch the file.
    if (ws->inotify_wd < 0) {
        ws->inotify_wd_is_dir = false;
        ws->inotify_wd = inotify_add_watch(
            ws->inotify_fd, ws->fpath, IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF
        );
        if (ws->inotify_wd < 0) {
            if (errno == ENOENT) {
                // If file doesn't exist, then watch parent directory.
                dbg("Clients file not found; watching parent directory: %s", ws->dpath);
                ws->inotify_wd_is_dir = true;
                ws->inotify_wd = inotify_add_watch(
                    ws->inotify_fd, ws->dpath, IN_CREATE | IN_MOVED_TO
                );
                if (ws->inotify_wd < 0) {
                    log_errno("inotify_add_watch");
                    log_error("Failed to watch %s.", ws->dpath);
                    return false;
                }
            } else {
                log_errno("inotify_add_watch");
                log_error("Failed to watch %s.", ws->fpath);
                return false;
            }
        }
    }

    return true;
}

static void watch_file_cleanup(WatchState *ws) {
    if (!check_ptr("watch_file_cleanup", "ws", ws)) { return; }

    if (ws->inotify_wd >= 0) {
        inotify_rm_watch(ws->inotify_fd, ws->inotify_wd);
        ws->inotify_wd = -1;
    }

    if (ws->inotify_fd >= 0) {
        close(ws->inotify_fd);
        ws->inotify_fd = -1;
    }
}

static bool watch_file_handler(BPFState *s, WatchState *ws) {
    if (!check_ptr("watch_file_handler", "s", s)) { return false; }
    if (!check_ptr("watch_file_handler", "ws", ws)) { return false; }

    // Now read the event.
    char buf[BUF_LEN];
    int length = read(ws->inotify_fd, buf, sizeof(buf));
    if (length < 0) {
        log_errno("read");
        log_error("Failed to read inotify event.");
        return false;
    } else if (length == 0) {
        log_error("Failed to `read`; returned 0?!");
        return false;
    }

    // Assume positive length means buffer contains at least one event Also, assume events are
    // never fragmented.
    int offset = 0;
    bool reload = false;
    while (offset < length) {
        struct inotify_event *event = (struct inotify_event *)&buf[offset];
        if (ws->inotify_wd_is_dir) {
            if (event->len > 0 && !strcmp(event->name, ws->fn)) {
                if (event->mask & IN_CREATE) {
                    dbg("%s created.", event->name);
                    break;
                } else if (event->mask & IN_MOVED_TO) {
                    dbg("%s moved in.", event->name);
                    break;
                } else {
                    log_error("Unexpected event for %s in directory watch.", event->name);
                    return false;
                }

                reload = true;
                if (ws->inotify_wd >= 0) {
                    if (!inotify_rm_watch(ws->inotify_fd, ws->inotify_wd)) {
                        log_errno("inotify_rm_watch");
                        log_error("Failed to remove watch on %s.", ws->dpath);
                        return false;
                    }
                    ws->inotify_wd = -1;
                }
            }
        } else {
            if (event->mask & IN_MODIFY) {
                dbg("%s modified.", ws->fpath);
                reload = true;
            } else if (event->mask & IN_MOVE_SELF) {
                dbg("%s moved out.", ws->fpath);
                reload = true;
                if (ws->inotify_wd >= 0) {
                    if (!inotify_rm_watch(ws->inotify_fd, ws->inotify_wd)) {
                        log_errno("inotify_rm_watch");
                        log_error("Failed to remove watch on %s.", ws->fpath);
                        return false;
                    }
                    ws->inotify_wd = -1;
                }
                break;
            } else if (event->mask & IN_DELETE_SELF) {
                dbg("%s deleted.", ws->fpath);
                reload = true;
                if (ws->inotify_wd >= 0) {
                    if (!inotify_rm_watch(ws->inotify_fd, ws->inotify_wd)) {
                        log_errno("inotify_rm_watch");
                        log_error("Failed to remove watch on %s.", ws->fpath);
                        return false;
                    }
                    ws->inotify_wd = -1;
                }
                break;
            }
        }

        offset += EVENT_SIZE + event->len;
    }

    // Reload clients, if needed.
    if (reload) {
        log_info("Reloading clients.");
        if (bpf_state__reload_clients(s)) {
            log_info("Reloaded clients successfully.");
        } else {
            log_error("Failed to reload clients.");
            return false;
        }
    }

    return true;
}

static bool watch_network_init(BPFState *s, WatchState *ws) {
    if (!check_ptr("watch_network_init", "s", s)) { return false; }
    if (!check_ptr("watch_network_init", "ws", ws)) { return false; }

    ws->socket_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    struct sockaddr_nl addr = {.nl_family = AF_NETLINK, .nl_groups = RTMGRP_LINK};
    addr.nl_pid = getpid();
    if (bind(ws->socket_fd, (struct sockaddr *)&addr, sizeof(addr))) {
        log_errno("bind");
        log_error("Failed to bind netlink socket.");
        close(ws->socket_fd);
        return false;
    }

    return true;
}

static void watch_network_cleanup(WatchState *ws) {
    if (!check_ptr("watch_network_cleanup", "ws", ws)) { return; }

    if (ws->socket_fd >= 0) {
        close(ws->socket_fd);
        ws->socket_fd = -1;
    }
}

static bool watch_network_handler(BPFState *s, WatchState *ws) {
    if (!check_ptr("watch_network_handler", "s", s)) { return false; }
    if (!check_ptr("watch_network_handler", "ws", ws)) { return false; }

    bool reload = false;
    char buf[4096] = {0};

    ssize_t len = recv(ws->socket_fd, buf, sizeof(buf), 0);
    if (len < 0) {
        log_errno("recv");
        log_error("Failed to receive netlink message.");
        return false;
    } else if (len == 0) {
        log_error("Failed to `recv`; returned 0?!");
        return false;
    }

    for (
        struct nlmsghdr *nlh = (struct nlmsghdr*)buf; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)
    ) {
        if (nlh->nlmsg_type == RTM_NEWLINK || nlh->nlmsg_type == RTM_DELLINK) {
            reload = true;

            // Log this interface change.
            struct ifinfomsg *ifi = NLMSG_DATA(nlh);
            char ifname[IF_NAMESIZE] = {0};
            if_indextoname(ifi->ifi_index, ifname);
            log_info(
                "Interface %s: %s",
                ifname,
                nlh->nlmsg_type == RTM_NEWLINK ? (
                    (ifi->ifi_flags & IFF_UP) ? "UP" : "DOWN"
                ) : "REMOVED"
            );
        }
    }

    // Reload interfaces/clients, if needed.
    if (reload) {
        log_info("Reloading interfaces/clients.");
        if (bpf_state__reload_interfaces(s)) {
            log_info("Reloaded interfaces successfully.");
        } else {
            log_error("Failed to reload interfaces.");
            return false;
        }

        if (bpf_state__reload_clients(s)) {
            log_info("Reloaded clients successfully.");
        } else {
            log_error("Failed to reload clients.");
            return false;
        }
    }

    return true;
}

// Core UBUS integration.
#ifdef UBUS

#include "../ubus.h"

static void watch_ubus_handler_cb(
    struct ubus_context *ctx, struct ubus_event_handler *ev, const char *type, struct blob_attr *msg
) {
    if (!check_ptr("watch_ubus_handler_cb", "ctx", ctx)) { return; }
    if (!check_ptr("watch_ubus_handler_cb", "ev", ev)) { return; }
    if (!check_ptr("watch_ubus_handler_cb", "type", type)) { return; }
    if (!check_ptr("watch_ubus_handler_cb", "msg", msg)) { return; }

    // Watch for client authorized events. When one is detected, call `get_clients`,
    // and allow the file watcher to reload clients.

    return;
}

static bool watch_ubus_init(BPFState *s, WatchState *ws) {
    if (!check_ptr("watch_ubus_init", "s", s)) { return false; }
    if (!check_ptr("watch_ubus_init", "ws", ws)) { return false; }

    // Connect to the UBUS.
    ws->ubus_ctx = ubus_connect(NULL);
    if (!ws->ubus_ctx) {
        log_error("Failed to connect to UBUS.");
        return false;
    }
    ws->ubus_socket_fd = ws->ubus_ctx->sock.fd;

    // Register the event handler.
    struct ubus_event_handler listener = {.cb = watch_ubus_handler_cb};
    if (ubus_register_event_handler(ws->ubus_ctx, &listener, "client.authorized")) {
        log_error("Failed to register UBUS event handler.");
        return false;
    }

    return true;
}

static void watch_ubus_cleanup(WatchState *ws) {
    if (!check_ptr("watch_ubus_cleanup", "ws", ws)) { return; }

    if (ws->ubus_ctx) {
        ubus_free(ws->ubus_ctx);
        ws->ubus_ctx = NULL;
        ws->ubus_socket_fd = -1;
    }
}

#endif  // UBUS

bool bpf_state__watch(BPFState *s) {
    if (!check_ptr("watch_init", "s", s)) { return false; }

    WatchState ws = {0};

    log_info("Initializing watch state.");
    if (!watch_file_init(s, &ws)) { return false; }
    if (!watch_network_init(s, &ws)) {
        watch_file_cleanup(&ws);
        return false;
    }
    #ifdef UBUS
    if (!watch_ubus_init(s, &ws)) {
        watch_network_cleanup(&ws);
        watch_file_cleanup(&ws);
        return false;
    }
    #endif  // UBUS

    log_info("Starting watch loop.");
    bool success = false;
    while (1) {
        dbg("Watch loop executing.");
        if (INTERRUPT) {
            log_info("Stopping watch.");
            success = true;
            break;
        }

        if (!watch_file_setup(s, &ws)) { break; }

        // Setup event fds.
        struct pollfd pfds[N_EVENTS] = {
            {.fd = ws.inotify_fd, .events = POLLIN},
            {.fd = ws.socket_fd, .events = POLLIN},
            #ifdef UBUS
            {.fd = ws.ubus_socket_fd, .events = POLLIN},
            #endif  // UBUS
        };

        // Wait for events.
        int returned_fds = poll(pfds, N_EVENTS, TIMEOUT * 1000);
        if (returned_fds < 0) {
            dbg_errno("poll");
            break;
        } else if (returned_fds == 0) {
            // Timeout; continue to check for interrupt.
            continue;
        }

        // Handle events.
        int handled_fds = 0;
        if (pfds[0].revents & POLLIN) {
            handled_fds++;
            if (!watch_file_handler(s, &ws)) { break; }
        }
        if (pfds[1].revents & POLLIN) {
            handled_fds++;
            if (!watch_network_handler(s, &ws)) { break; }
        }
        #ifdef UBUS
        if (pfds[2].revents & POLLIN) {
            handled_fds++;
            ubus_handle_event(ws.ubus_ctx);
        }
        #endif  // UBUS

        // Check that we handled the expected number of fds.
        if (handled_fds != returned_fds) {
            log_error("Unexpected fds from `poll` (%d != %d).", handled_fds, returned_fds);
        }
    }

    log_info("Cleaning up watch state.");
    #ifdef UBUS
    watch_ubus_cleanup(&ws);
    #endif  // UBUS
    watch_network_cleanup(&ws);
    watch_file_cleanup(&ws);

    return success;
}
