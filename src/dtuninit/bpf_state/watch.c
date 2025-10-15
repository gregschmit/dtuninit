/*
 * Logic for watching the clients file and network interface changes to trigger BFP mounting,
 * unmounting, and map updates.
 */
#include <errno.h>
#include <libgen.h>
#include <limits.h>
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

extern volatile bool INTERRUPT;

/*
 * Watch for state changes (clients file, network interfaces, ubus events, etc), and call the
 * appropriate reload functions, as needed.
 */
bool bpf_state__watch(BPFState *state) {
    if (!state) { return false; }

    // Extract the directory name and file name without modifying `clients_path`.
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", state->clients_path);
    char *fn = basename(tmp);
    char *dn = dirname(tmp);

    // Initialize `inotify`.
    int fd = inotify_init();
    if (fd < 0) {
        log_errno("inotify_init");
        return false;
    }

    // Combine `dn` and `fn` to get the `fullpath`.
    char fullpath[PATH_MAX + 1];
    snprintf(fullpath, sizeof(fullpath), "%s/%s", dn, fn);

    log_info("Watching %s.", fullpath);

    int wd = -1;
    int wd_is_dir = 0;
    uint8_t buf[BUF_LEN];
    while (1) {
        if (INTERRUPT) {
            dbg("Stopping watch.");
            break;
        }

        // If `wd < 0`, then try to watch the file.
        if (wd < 0) {
            wd_is_dir = 0;
            wd = inotify_add_watch(fd, fullpath, IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF);
            if (wd < 0) {
                if (errno == ENOENT) {
                    // If file doesn't exist, then watch parent directory.
                    dbg("File not found; watching parent directory: %s", dn);
                    wd_is_dir = 1;
                    wd = inotify_add_watch(fd, dn, IN_CREATE | IN_MOVED_TO);
                    if (wd < 0) {
                        log_errno("inotify_add_watch");
                        log_error("Failed to watch %s.", dn);
                        sleep(TIMEOUT);
                        continue;
                    }
                } else {
                    log_errno("inotify_add_watch");
                    log_error("Failed to watch %s.", fullpath);
                    sleep(TIMEOUT);
                    continue;
                }
            }
        }

        // Now we definitely have a watch descriptor; wait for an event:
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        int res = poll(&pfd, 1, TIMEOUT * 1000);
        if (res < 0) {
            dbg_errno("poll");
            continue;
        } else if (res == 0) {
            // Continue to check for interrupt.
            continue;
        }

        // Now read the event.
        int length = read(fd, buf, BUF_LEN);
        if (length < 0) {
            log_errno("read");
            if (inotify_rm_watch(fd, wd) < 0) {
                log_errno("inotify_rm_watch");
                wd = -1;
                sleep(TIMEOUT);
                continue;
            }
            wd = -1;
            sleep(TIMEOUT);
            continue;
        } else if (length == 0) {
            log_error("Failed to `read`: returned 0?!");
            continue;
        }

        // Assume positive length means buffer contains at least one event Also, assume events are
        // never fragmented.
        int offset = 0;
        bool reload_clients = false;
        while (offset < length) {
            struct inotify_event *event = (struct inotify_event *)&buf[offset];
            if (wd_is_dir) {
                if (event->len > 0 && strcmp(event->name, fn) == 0) {
                    if (event->mask & IN_CREATE) {
                        dbg("%s created.", event->name);
                        reload_clients = true;
                        inotify_rm_watch(fd, wd);
                        wd = -1;
                        break;
                    } else if (event->mask & IN_MOVED_TO) {
                        dbg("%s moved in.", event->name);
                        reload_clients = true;
                        inotify_rm_watch(fd, wd);
                        wd = -1;
                        break;
                    }
                }
            } else {
                if (event->mask & IN_MODIFY) {
                    dbg("%s modified.", fullpath);
                    reload_clients = true;
                } else if (event->mask & IN_MOVE_SELF) {
                    dbg("%s moved out.", fullpath);
                    reload_clients = true;
                    inotify_rm_watch(fd, wd);
                    wd = -1;
                    break;
                } else if (event->mask & IN_DELETE_SELF) {
                    dbg("%s deleted.", fullpath);
                    reload_clients = true;
                    inotify_rm_watch(fd, wd);
                    wd = -1;
                    break;
                }
            }

            offset += EVENT_SIZE + event->len;
        }

        // Reload clients, if needed.
        if (reload_clients) {
            log_info("Reloading clients.");
            if (bpf_state__reload_clients(state)) {
                log_info("Reloaded clients successfully.");
            } else {
                log_error("Failed to reload clients.");
            }
        }
    }

    // Cleanup.
    if (wd >= 0) {
        inotify_rm_watch(fd, wd);
    }
    close(fd);

    return true;
}
