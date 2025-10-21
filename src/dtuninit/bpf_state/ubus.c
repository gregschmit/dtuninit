#include "../log.h"
#include "ubus.h"

static void list_append(const char *name) {
    // Append `name` to `UBUS_HAPD_LIST`, if there is space.
    for (size_t i = 0; i < UBUS_MAX_HAPD_LIST; i++) {
        if (!UBUS_HAPD_LIST[i][0]) {
            if (strlen(name) >= UBUS_MAX_HAPD_NAME_LEN) {
                log_error("UBUS object name too long; skipping: %s", name);
                return;
            }

            snprintf(UBUS_HAPD_LIST[i], UBUS_MAX_HAPD_NAME_LEN, "%s", name);

            // Clear next entry unless at end of list.
            if (i + 1 < UBUS_MAX_HAPD_LIST) {
                UBUS_HAPD_LIST[i + 1][0] = '\0';
            }

            return;
        }
    }

    log_error("UBUS_HAPD_LIST is full; skipping %s", name);
}

static void list_cb(struct ubus_context *ctx, struct ubus_object_data *obj, void *priv) {
    if (obj->path) {
        list_append(obj->path);
    } else {
        log_error("UBUS object with no path?");
    }
}

bool bpf_state__ubus__hapd_list() {
    struct ubus_context *ctx = ubus_connect(NULL);
    if (!ctx) {
        return false;
    }

    // Clear existing list by clearing the first entry.
    UBUS_HAPD_LIST[0][0] = '\0';

    int res;
    if ((res = ubus_lookup(ctx, "hostapd.*", list_cb, NULL)) != 0) {
        log_error("UBUS (%d): %s", res, ubus_strerror(res));
        log_error("Failed to list `hostapd` UBUS objects.");
        ubus_free(ctx);
        return false;
    }

    ubus_free(ctx);
    return true;
}
