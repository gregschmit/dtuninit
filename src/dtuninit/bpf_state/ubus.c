#include "../log.h"
#include "ubus.h"

#define UBUS_MAX_HAPD_OBJS 32
#define UBUS_MAX_HAPD_NAME_LEN 256

// Static storage for hostapd objects.
static unsigned UBUS_N_HAPD_OBJS = 0;
static char UBUS_HAPD_OBJS[UBUS_MAX_HAPD_OBJS][UBUS_MAX_HAPD_NAME_LEN] = {0};
static char *UBUS_HAPD_OBJS_PTRS[UBUS_MAX_HAPD_OBJS + 1] = {0};  // NULL-terminated.

static void ubus_hapd_objs_append(const char *name) {
    if (!check_ptr("ubus_hapd_objs_append", "name", name)) { return; }

    if (strlen(name) >= UBUS_MAX_HAPD_NAME_LEN) {
        log_error("UBUS object name too long; skipping %s", name);
        return;
    }

    // Append `name` to `UBUS_HAPD_OBJS`, if there is space.
    if (UBUS_N_HAPD_OBJS < UBUS_MAX_HAPD_OBJS) {
        snprintf(UBUS_HAPD_OBJS[UBUS_N_HAPD_OBJS], UBUS_MAX_HAPD_NAME_LEN, "%s", name);
        UBUS_HAPD_OBJS_PTRS[UBUS_N_HAPD_OBJS] = UBUS_HAPD_OBJS[UBUS_N_HAPD_OBJS];
        UBUS_N_HAPD_OBJS++;
        UBUS_HAPD_OBJS_PTRS[UBUS_N_HAPD_OBJS] = NULL;  // Ensure NULL-terminated.

        return;
    }

    log_error("UBUS_HAPD_OBJS is full; skipping %s", name);
}

static void ubus_hapd_objs_cb(struct ubus_context *ctx, struct ubus_object_data *obj, void *priv) {
    if (!check_ptr("ubus_hapd_objs_cb", "ctx", ctx)) { return; }
    if (!check_ptr("ubus_hapd_objs_cb", "obj", obj)) { return; }

    ubus_hapd_objs_append(obj->path);
}

const char **bpf_state__ubus__hapd_list() {
    struct ubus_context *ctx = ubus_connect(NULL);
    if (!ctx) {
        return NULL;
    }

    // Clear existing hapd objs.
    UBUS_N_HAPD_OBJS = 0;
    UBUS_HAPD_OBJS_PTRS[0] = NULL;

    int res;
    if ((res = ubus_lookup(ctx, "hostapd.*", ubus_hapd_objs_cb, NULL)) != 0) {
        log_error("UBUS (%d): %s", res, ubus_strerror(res));
        log_error("Failed to list `hostapd.*` UBUS objects.");
        ubus_free(ctx);
        return NULL;
    }

    ubus_free(ctx);
    return (const char **)UBUS_HAPD_OBJS_PTRS;
}
