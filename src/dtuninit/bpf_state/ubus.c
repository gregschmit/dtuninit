#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "../log.h"
#include "ubus.h"

#define UBUS_TIMEOUT_MS 3000

#define UBUS_MAX_HAPD_OBJS 64
#define UBUS_MAX_HAPD_NAME_LEN 128

// Static storage for hostapd objects.
static unsigned UBUS_N_HAPD_OBJS = 0;
static uint32_t UBUS_HAPD_OBJ_IDS[UBUS_MAX_HAPD_OBJS] = {0};
static char UBUS_HAPD_OBJ_NAMES[UBUS_MAX_HAPD_OBJS][UBUS_MAX_HAPD_NAME_LEN] = {0};
static char *UBUS_HAPD_OBJ_NAME_PTRS[UBUS_MAX_HAPD_OBJS + 1] = {0};  // NULL-terminated.

static void ubus_hapd_objs_push(const char *name, uint32_t id) {
    if (!check_ptr("ubus_hapd_objs_push", "name", name)) { return; }

    if (strlen(name) >= UBUS_MAX_HAPD_NAME_LEN) {
        log_error("UBUS object name too long; truncating %s", name);
    }

    // Push id and name, if there is space.
    if (UBUS_N_HAPD_OBJS < UBUS_MAX_HAPD_OBJS) {
        // Write id.
        UBUS_HAPD_OBJ_IDS[UBUS_N_HAPD_OBJS] = id;

        // Write name (truncate if needed; this is purely for display).
        snprintf(UBUS_HAPD_OBJ_NAMES[UBUS_N_HAPD_OBJS], UBUS_MAX_HAPD_NAME_LEN, "%s", name);
        UBUS_HAPD_OBJ_NAME_PTRS[UBUS_N_HAPD_OBJS] = UBUS_HAPD_OBJ_NAMES[UBUS_N_HAPD_OBJS];

        // Increment count and ensure name ptrs is NULL-terminated.
        UBUS_N_HAPD_OBJS++;
        UBUS_HAPD_OBJ_NAME_PTRS[UBUS_N_HAPD_OBJS] = NULL;

        return;
    }

    log_error("UBUS_HAPD_OBJS is full; skipping %s", name);
}

static void ubus_hapd_objs_cb(struct ubus_context *ctx, struct ubus_object_data *obj, void *priv) {
    if (!check_ptr("ubus_hapd_objs_cb", "ctx", ctx)) { return; }
    if (!check_ptr("ubus_hapd_objs_cb", "obj", obj)) { return; }

    ubus_hapd_objs_push(obj->path, obj->id);
}

static bool ubus_populate_hapd_objs(struct ubus_context *ctx) {
    if (!check_ptr("ubus_populate_hapd_objs", "ctx", ctx)) { return false; }

    // Clear existing hapd objs.
    UBUS_N_HAPD_OBJS = 0;
    UBUS_HAPD_OBJ_NAME_PTRS[0] = NULL;

    int res;
    if ((res = ubus_lookup(ctx, "hostapd.*", ubus_hapd_objs_cb, NULL)) != 0) {
        log_error("UBUS (%d): %s", res, ubus_strerror(res));
        log_error("Failed to list `hostapd.*` UBUS objects.");
        return false;
    }

    return true;
}

const char **bpf_state__ubus__hapd_list() {
    struct ubus_context *ctx = ubus_connect(NULL);
    if (!ctx) {
        return NULL;
    }

    if (!ubus_populate_hapd_objs(ctx)) {
        ubus_free(ctx);
        return NULL;
    }

    return (const char **)UBUS_HAPD_OBJ_NAME_PTRS;
}

static void ubus_get_clients_cb(struct ubus_request *req, int type, struct blob_attr *msg) {
    if (!check_ptr("ubus_get_clients_cb", "req", req)) { return; }
    if (!check_ptr("ubus_get_clients_cb", "msg", msg)) { return; }

    List *clients = (List *)req->priv;
    if (!check_ptr("ubus_get_clients_cb", "clients", clients)) { return; }

    char *json_str = blobmsg_format_json_indent(msg, true, 0);
    log_info("UBUS get_clients response:");
    log_info("%s\n", json_str);
    free(json_str);
}

static bool ubus_get_clients(struct ubus_context *ctx, uint32_t id, List *clients) {
    if (!check_ptr("ubus_get_clients", "ctx", ctx)) { return false; }
    if (!check_ptr("ubus_get_clients", "clients", clients)) { return false; }

    int res = ubus_invoke(
        ctx, id, "get_clients", NULL, ubus_get_clients_cb, (void *)clients, UBUS_TIMEOUT_MS
    );
    if (res) {
        log_error("UBUS (%d): %s", res, ubus_strerror(res));
        log_error("Failed to invoke `get_clients`.");
        return false;
    }

    return true;
}

List *bpf_state__ubus__get_clients() {
    struct ubus_context *ctx = ubus_connect(NULL);
    if (!ctx) {
        return NULL;
    }

    if (!ubus_populate_hapd_objs(ctx)) {
        ubus_free(ctx);
        return NULL;
    }

    // Initialize a list of Clients.
    List *clients = list__new(
        sizeof(Client), sizeof(uint8_t) * ETH_ALEN, (list__key_eq_t)client__key_eq
    );
    if (!clients) { return NULL; }

    // For each obj, get the clients and add to list.
    for (unsigned i = 0; i < UBUS_N_HAPD_OBJS; i++) {
        const char *obj_path = UBUS_HAPD_OBJS_PTRS[i];
        if (!obj_path) { break; }
        uint32_t obj_id = UBUS_HAPD_OBJ_IDS[i];

        log_info("Getting clients for obj %d (%s)", obj_id, obj_path);
        if (!ubus_get_clients(ctx, obj_id, clients)) {
            log_error("Failed to get clients.");
        }
    }

    ubus_free(ctx);
    return clients;
}
