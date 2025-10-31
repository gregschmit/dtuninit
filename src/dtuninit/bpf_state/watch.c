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
#include "clients_file.h"

#include "watch.h"

#ifdef UBUS
#include "../ubus.h"
#endif

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
    // For watching the UBUS.
    struct ubus_context *ubus_ctx;
    int ubus_socket_fd;
    struct ubus_event_handler ubus_object_handler;
    struct ubus_subscriber ubus_hapd_subscriber;
    bool ubus_reload_hapd_subscriber;
    bool ubus_load_clients;
    #endif
} WatchState;

// Use a single static instance for simplicity.
static WatchState WS = {
    .inotify_fd = -1,
    .inotify_wd = -1,
    .socket_fd = -1,
    #ifdef UBUS
    .ubus_socket_fd = -1,
    #endif
};

static bool watch_file_init(BPFState *s) {
    if (!check_ptr("watch_file_init", "s", s)) { return false; }

    // Extract the directory path and file name. We need them separately because we conditionally
    // watch either the file or the directory (if the file doesn't exist). We also re-create the
    // full file path so if the `clients_path` is just a bare filename, we get a more sensible
    // representation (e.g., `file.json` becomes `./file.json`).
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", s->clients_path);
    snprintf(WS.fn, sizeof(WS.fn), "%s", basename(tmp));
    snprintf(WS.dpath, sizeof(WS.dpath), "%s", dirname(tmp));
    snprintf(WS.fpath, sizeof(WS.fpath), "%s/%s", WS.dpath, WS.fn);

    // Initialize `inotify`.
    WS.inotify_fd = inotify_init();
    if (WS.inotify_fd < 0) {
        log_errno("inotify_init");
        return false;
    }
    WS.inotify_wd = -1;

    return true;
}

static bool watch_file_setup(BPFState *s) {
    if (!check_ptr("watch_file_setup", "s", s)) { return false; }

    // If `WS.inotify_wd < 0`, then try to watch the file.
    if (WS.inotify_wd < 0) {
        WS.inotify_wd_is_dir = false;
        WS.inotify_wd = inotify_add_watch(
            WS.inotify_fd, WS.fpath, IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF
        );
        if (WS.inotify_wd < 0) {
            if (errno == ENOENT) {
                // If file doesn't exist, then watch parent directory.
                dbg("Clients file not found; watching parent directory: %s", WS.dpath);
                WS.inotify_wd_is_dir = true;
                WS.inotify_wd = inotify_add_watch(
                    WS.inotify_fd, WS.dpath, IN_CREATE | IN_MOVED_TO
                );
                if (WS.inotify_wd < 0) {
                    log_errno("inotify_add_watch");
                    log_error("Failed to watch %s.", WS.dpath);
                    return false;
                }
            } else {
                log_errno("inotify_add_watch");
                log_error("Failed to watch %s.", WS.fpath);
                return false;
            }
        }
    }

    return true;
}

static void watch_file_cleanup() {
    if (WS.inotify_wd >= 0) {
        inotify_rm_watch(WS.inotify_fd, WS.inotify_wd);
        WS.inotify_wd = -1;
    }

    if (WS.inotify_fd >= 0) {
        close(WS.inotify_fd);
        WS.inotify_fd = -1;
    }
}

static bool watch_file_handler(BPFState *s) {
    if (!check_ptr("watch_file_handler", "s", s)) { return false; }

    // Now read the event.
    char buf[BUF_LEN];
    int length = read(WS.inotify_fd, buf, sizeof(buf));
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
        if (WS.inotify_wd_is_dir) {
            if (event->len > 0 && !strcmp(event->name, WS.fn)) {
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
                if (WS.inotify_wd >= 0) {
                    if (!inotify_rm_watch(WS.inotify_fd, WS.inotify_wd)) {
                        log_errno("inotify_rm_watch");
                        log_error("Failed to remove watch on %s.", WS.dpath);
                        return false;
                    }
                    WS.inotify_wd = -1;
                }
            }
        } else {
            if (event->mask & IN_MODIFY) {
                dbg("%s modified.", WS.fpath);
                reload = true;
            } else if (event->mask & IN_MOVE_SELF) {
                dbg("%s moved out.", WS.fpath);
                reload = true;
                if (WS.inotify_wd >= 0) {
                    if (!inotify_rm_watch(WS.inotify_fd, WS.inotify_wd)) {
                        log_errno("inotify_rm_watch");
                        log_error("Failed to remove watch on %s.", WS.fpath);
                        return false;
                    }
                    WS.inotify_wd = -1;
                }
                break;
            } else if (event->mask & IN_DELETE_SELF) {
                dbg("%s deleted.", WS.fpath);
                reload = true;
                if (WS.inotify_wd >= 0) {
                    if (!inotify_rm_watch(WS.inotify_fd, WS.inotify_wd)) {
                        log_errno("inotify_rm_watch");
                        log_error("Failed to remove watch on %s.", WS.fpath);
                        return false;
                    }
                    WS.inotify_wd = -1;
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

static bool watch_network_init(BPFState *s) {
    if (!check_ptr("watch_network_init", "s", s)) { return false; }

    WS.socket_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    struct sockaddr_nl addr = {.nl_family = AF_NETLINK, .nl_groups = RTMGRP_LINK};
    addr.nl_pid = getpid();
    if (bind(WS.socket_fd, (struct sockaddr *)&addr, sizeof(addr))) {
        log_errno("bind");
        log_error("Failed to bind netlink socket.");
        close(WS.socket_fd);
        return false;
    }

    return true;
}

static void watch_network_cleanup() {
    if (WS.socket_fd >= 0) {
        close(WS.socket_fd);
        WS.socket_fd = -1;
    }
}

static bool watch_network_handler(BPFState *s) {
    if (!check_ptr("watch_network_handler", "s", s)) { return false; }

    bool reload = false;
    char buf[4096] = {0};

    ssize_t len = recv(WS.socket_fd, buf, sizeof(buf), 0);
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

static void watch_ubus_object_handler_cb(
    struct ubus_context *_c, struct ubus_event_handler *_h, const char *type, struct blob_attr *_m
) {
    (void)_c;
    (void)_h;
    (void)_m;
    if (!check_ptr("watch_ubus_object_handler_cb", "type", type)) { return; }

    log_info("Received UBUS event: %s", type);
    if (!strcmp(type, "ubus.object.add") || !strcmp(type, "ubus.object.remove")) {
        WS.ubus_reload_hapd_subscriber = true;
    }

    return;
}

static int watch_ubus_hapd_subscriber_cb(
    struct ubus_context *_c,
    struct ubus_object *_o,
    struct ubus_request_data *_r,
    const char *method,
    struct blob_attr *_m
) {
    (void)_c;
    (void)_o;
    (void)_r;
    (void)_m;
    if (!check_ptr("watch_ubus_hapd_subscriber_cb", "method", method)) { return -1; }

    log_info("Received UBUS hostapd event: %s", method);

    if (
        !strcmp(method, "hostapd.sta-assoc") ||
        !strcmp(method, "hostapd.sta-authorized") ||
        !strcmp(method, "hostapd.sta-disassoc")
    ) {
        WS.ubus_load_clients = true;
    }

    return 0;
}

static void watch_ubus_hapd_subscribe_cb(
    struct ubus_context *ctx, struct ubus_object_data *obj, void *priv
) {
    if (!check_ptr("watch_ubus_hapd_subscribe_cb", "ctx", ctx)) { return; }
    if (!check_ptr("watch_ubus_hapd_subscribe_cb", "obj", obj)) { return; }
    if (!check_ptr("watch_ubus_hapd_subscribe_cb", "priv", priv)) { return; }

    struct ubus_subscriber *sub = priv;

    dbg("Subscribing to UBUS object %s (id: %u)\n", obj->path, obj->id);

    // Subscribe to this object
    int res = 0;
    if ((res = ubus_subscribe(ctx, sub, obj->id))) {
        log_error("UBUS error %d: %s", res, ubus_strerror(res));
    }
}

static bool watch_ubus_init(BPFState *s) {
    if (!check_ptr("watch_ubus_init", "s", s)) { return false; }

    // Connect to the UBUS.
    WS.ubus_ctx = ubus_connect(NULL);
    if (!WS.ubus_ctx) {
        log_error("Failed to connect to UBUS.");
        return false;
    }
    WS.ubus_socket_fd = WS.ubus_ctx->sock.fd;

    // Register the object event handler.
    WS.ubus_object_handler.cb = watch_ubus_object_handler_cb;
    int res = 0;
    if (
        (res = ubus_register_event_handler(WS.ubus_ctx, &WS.ubus_object_handler, "ubus.object.*"))
    ) {
        log_error("UBUS error %d: %s", res, ubus_strerror(res));
        log_error("Failed to register UBUS object event handler.");
        return false;
    }

    // Signal to subscribe to hostapd events.
    WS.ubus_reload_hapd_subscriber = true;

    return true;
}

static bool watch_ubus_setup() {
    // If needed, subscribe to hostapd events.
    if (WS.ubus_reload_hapd_subscriber) {
        WS.ubus_reload_hapd_subscriber = false;
        int res = 0;

        // Unregister existing subscriber, if any.
        if (WS.ubus_hapd_subscriber.cb) {
            ubus_unregister_subscriber(WS.ubus_ctx, &WS.ubus_hapd_subscriber);
        }

        // Register the hostapd subscriber.
        memset(&WS.ubus_hapd_subscriber, 0, sizeof(WS.ubus_hapd_subscriber));
        WS.ubus_hapd_subscriber.cb = watch_ubus_hapd_subscriber_cb;
        if ((res = ubus_register_subscriber(WS.ubus_ctx, &WS.ubus_hapd_subscriber))) {
            log_error("UBUS error %d: %s", res, ubus_strerror(res));
            log_error("Failed to register hostapd subscriber.");
            return false;
        }

        // Subscribe to all hostapd objects using the subscribe callback.
        if ((res = ubus_lookup(
            WS.ubus_ctx, "hostapd.*", watch_ubus_hapd_subscribe_cb, &WS.ubus_hapd_subscriber
        ))) {
            log_error("UBUS error %d: %s", res, ubus_strerror(res));
            log_error("Failed to subscribe to hostapd objects.");
            return false;
        }
    }

    return true;
}

static void watch_ubus_cleanup() {
    if (!WS.ubus_ctx) {
        return;
    }

    if (WS.ubus_hapd_subscriber.cb) {
        ubus_unregister_subscriber(WS.ubus_ctx, &WS.ubus_hapd_subscriber);
        memset(&WS.ubus_hapd_subscriber, 0, sizeof(WS.ubus_hapd_subscriber));
    }
    if (WS.ubus_object_handler.cb) {
        ubus_unregister_event_handler(WS.ubus_ctx, &WS.ubus_object_handler);
        memset(&WS.ubus_object_handler, 0, sizeof(WS.ubus_object_handler));
    }
    ubus_free(WS.ubus_ctx);
    WS.ubus_ctx = NULL;
    WS.ubus_socket_fd = -1;
}

static bool watch_ubus_handler(BPFState *s) {
    if (!check_ptr("watch_ubus_handler", "s", s)) { return false; }

    ubus_handle_event(WS.ubus_ctx);

    if (WS.ubus_load_clients) {
        WS.ubus_load_clients = false;
        log_info("Writing UBUS clients to the clients file.");
        List *clients = ubus__get_clients(WS.ubus_ctx);
        if (!clients) {
            log_error("Failed to get UBUS clients.");
            return false;
        }
        if (!bpf_state__clients_file__replace(s, clients)) {
            log_error("Failed to write UBUS clients to the clients file.");
            list__free(clients);
            return false;
        }
        list__free(clients);
    }

    return true;
}

#endif  // UBUS

bool bpf_state__watch(BPFState *s) {
    if (!check_ptr("watch_init", "s", s)) { return false; }

    log_info("Initializing watch state.");
    if (!watch_file_init(s)) { return false; }
    if (!watch_network_init(s)) {
        watch_file_cleanup();
        return false;
    }
    #ifdef UBUS
    if (!watch_ubus_init(s)) {
        watch_network_cleanup();
        watch_file_cleanup();
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

        if (!watch_file_setup(s)) { break; }
        if (!watch_ubus_setup()) { break; }

        // Setup event fds.
        struct pollfd pfds[N_EVENTS] = {
            {.fd = WS.inotify_fd, .events = POLLIN},
            {.fd = WS.socket_fd, .events = POLLIN},
            #ifdef UBUS
            {.fd = WS.ubus_socket_fd, .events = POLLIN},
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
        if (pfds[0].revents) {
            handled_fds++;

            if (pfds[0].revents & POLLERR) {
                log_error("File: POLLERR");
                break;
            } else if (pfds[0].revents & POLLHUP) {
                log_error("File: POLLHUP");
                break;
            } else if (pfds[0].revents & POLLNVAL) {
                log_error("File: POLLNVAL");
                break;
            } else if (pfds[0].revents & POLLIN) {
                if (!watch_file_handler(s)) { break; }
            }
        }
        if (pfds[1].revents) {
            handled_fds++;

            if (pfds[1].revents & POLLERR) {
                log_error("Network: POLLERR");
                break;
            } else if (pfds[1].revents & POLLHUP) {
                log_error("Network: POLLHUP");
                break;
            } else if (pfds[1].revents & POLLNVAL) {
                log_error("Network: POLLNVAL");
                break;
            } else if (pfds[1].revents & POLLIN) {
                if (!watch_network_handler(s)) { break; }
            }
        }
        #ifdef UBUS
        if (pfds[2].revents) {
            handled_fds++;

            if (pfds[2].revents & POLLERR) {
                log_error("UBUS: POLLERR");
                break;
            } else if (pfds[2].revents & POLLHUP) {
                log_error("UBUS: POLLHUP");
                break;
            } else if (pfds[2].revents & POLLNVAL) {
                log_error("UBUS: POLLNVAL");
                break;
            } else if (pfds[2].revents & POLLIN) {
                if (!watch_ubus_handler(s)) { break; }
            }
        }
        #endif  // UBUS

        // Check that we handled the expected number of fds.
        if (handled_fds != returned_fds) {
            log_error("Unexpected fds from `poll` (%d != %d).", handled_fds, returned_fds);
            break;
        }
    }

    log_info("Cleaning up watch state.");
    #ifdef UBUS
    watch_ubus_cleanup();
    #endif  // UBUS
    watch_network_cleanup();
    watch_file_cleanup();

    return success;
}
