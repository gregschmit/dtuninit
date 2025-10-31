#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "log.h"
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

static void ubus_hapd_objs_cb(struct ubus_context *ctx, struct ubus_object_data *obj, void *_priv) {
    (void)_priv;
    if (!check_ptr("ubus_hapd_objs_cb", "ctx", ctx)) { return; }
    if (!check_ptr("ubus_hapd_objs_cb", "obj", obj)) { return; }

    ubus_hapd_objs_push(obj->path, obj->id);
}

static bool ubus_populate_hapd_objs(struct ubus_context *ctx) {
    if (!check_ptr("ubus_populate_hapd_objs", "ctx", ctx)) { return false; }

    // Clear existing hapd objs.
    UBUS_N_HAPD_OBJS = 0;
    UBUS_HAPD_OBJ_NAME_PTRS[0] = NULL;

    int res = 0;
    if ((res = ubus_lookup(ctx, "hostapd.*", ubus_hapd_objs_cb, NULL))) {
        log_error("UBUS error %d: %s", res, ubus_strerror(res));
        log_error("Failed to lookup `hostapd.*` UBUS objects.");
        return false;
    }

    return true;
}

const char **ubus__hapd_list(struct ubus_context *ctx) {
    bool input_ctx = ctx;
    if (!ctx) { ctx = ubus_connect(NULL); }
    if (!ctx) {
        log_error("Failed to connect to UBUS (hapd_list).");
        return NULL;
    }

    if (!ubus_populate_hapd_objs(ctx)) {
        if (!input_ctx) { ubus_free(ctx); }
        return NULL;
    }

    if (!input_ctx) { ubus_free(ctx); }
    return (const char **)UBUS_HAPD_OBJ_NAME_PTRS;
}

static bool ubus_hex_to_u32(const char *hex, uint32_t *out) {
    if (!check_ptr("ubus_hex_to_u32", "hex", hex)) { return false; }

    char *endptr = NULL;
    unsigned long value = strtoul(hex, &endptr, 16);
    if (!endptr || *endptr != '\0' || value > UINT32_MAX) {
        log_error("Invalid ubus hex u32: %s", hex);
        return false;
    }
    *out = (uint32_t)value;
    return true;
}

static bool ubus_hex_to_string(const char *hex, char *out, size_t out_len) {
    if (!check_ptr("ubus_hex_to_string", "hex", hex)) { return false; }
    if (!check_ptr("ubus_hex_to_string", "out", out)) { return false; }

    size_t hex_len = strlen(hex);
    if (hex_len < 2) {
        log_error("Invalid ubus hex string (too short): %s", hex);
        return false;
    }
    if (hex_len % 2 != 0) {
        log_error("Invalid ubus hex string (odd length): %s", hex);
        return false;
    }
    if ((hex_len / 2) + 1 > out_len) {
        log_error("Invalid ubus hex string (too long): %s", hex);
        return false;
    }

    for (size_t i = 0; i < hex_len / 2; i++) {
        char byte[3] = { hex[i * 2], hex[i * 2 + 1], '\0' };
        char *endptr = NULL;
        out[i] = (char)strtol(byte, &endptr, 16);
        if (!endptr || *endptr != '\0') {
            log_error("Invalid byte in ubus hex string: %s", hex);
            return false;
        }
    }
    out[hex_len / 2] = '\0';

    return true;
}

static void ubus_get_clients_cb(struct ubus_request *req, int _type, struct blob_attr *msg) {
    (void)_type;
    if (!check_ptr("ubus_get_clients_cb", "req", req)) { return; }
    if (!check_ptr("ubus_get_clients_cb", "msg", msg)) { return; }

    List *clients = (List *)req->priv;
    if (!check_ptr("ubus_get_clients_cb", "clients", clients)) { return; }

    // Iterate top-level attrs.
    struct blob_attr *cur = NULL;
    size_t rem = 0;
    blobmsg_for_each_attr(cur, msg, rem) {
        // Find `clients` key.
        if (strcmp(blobmsg_name(cur), "clients")) {
            continue;
        }

        // Iterate `clients`.
        struct blob_attr *client_blob = NULL;
        size_t client_rem = 0;
        blobmsg_for_each_attr(client_blob, cur, client_rem) {
            Client client = {0};
            const char *mac = blobmsg_name(client_blob);
            char proto[MAX_PROTO_LEN] = {0};
            char peer_ip[INET_ADDRSTRLEN] = {0};
            long vlan = 0;

            // Iterate client attrs.
            struct blob_attr *attr = NULL;
            size_t attr_rem = 0;
            blobmsg_for_each_attr(attr, client_blob, attr_rem) {
                // Find `radius_attrs` key.
                if (strcmp(blobmsg_name(attr), "radius_attrs")) {
                    continue;
                }

                // Iterate `radius_attrs`.
                struct blob_attr *radius_attr = NULL;
                size_t radius_attr_rem = 0;
                blobmsg_for_each_attr(radius_attr, attr, radius_attr_rem) {
                    uint8_t type = 0;
                    char *value_hex = NULL;

                    // Populate type/length/value_hex values.
                    struct blob_attr *kv = NULL;
                    size_t kv_rem = 0;
                    blobmsg_for_each_attr(kv, radius_attr, kv_rem) {
                        const char *key = blobmsg_name(kv);
                        if (!strcmp(key, "type")) {
                            type = blobmsg_get_u8(kv);
                        } else if (!strcmp(key, "value_hex")) {
                            value_hex = blobmsg_get_string(kv);
                        }
                    }

                    // Parse known RADIUS types.
                    switch (type) {
                        // Tunnel-Type
                        case 64: {
                            uint32_t tunnel_type = 0;
                            if (ubus_hex_to_u32(value_hex, &tunnel_type)) {
                                switch (tunnel_type) {
                                    case 10: {
                                        strcpy(proto, "gre");
                                        break;
                                    }
                                    default: {
                                        dbg("Unknown UBUS RADIUS Tunnel-Type: %u", tunnel_type);
                                        break;
                                    }
                                }
                            }
                            break;
                        }
                        // Tunnel-Server-Endpoint
                        case 67: {
                            ubus_hex_to_string(value_hex, peer_ip, sizeof(peer_ip));
                            break;
                        }
                        // Tunnel-Private-Group-ID
                        case 81: {
                            char vlan_s[5] = {0};
                            ubus_hex_to_string(value_hex, vlan_s, sizeof(vlan_s));
                            char *endptr = NULL;
                            vlan = strtol(vlan_s, &endptr, 10);
                            if (!endptr || *endptr != '\0') {
                                vlan = 0;
                            }
                            break;
                        }
                    }
                }

                // After iterating `radius_attrs`, break.
                break;
            }

            // Skip if client is missing required fields.
            if (proto[0] == '\0' || peer_ip[0] == '\0') {
                continue;
            }

            // Parse client fields.
            if (!client__parse(&client, mac, proto, peer_ip, vlan)) {
                log_error("Failed to parse UBUS client: %s", mac);
                continue;
            }

            // Add to clients list.
            if (!list__add(clients, &client)) {
                log_error("Failed to add UBUS client: %s", mac);
                continue;
            }
        }

        // After iterating clients, break.
        break;
    }
}

static bool ubus_get_clients(struct ubus_context *ctx, uint32_t id, List *clients) {
    if (!check_ptr("ubus_get_clients", "ctx", ctx)) { return false; }
    if (!check_ptr("ubus_get_clients", "clients", clients)) { return false; }

    int res = ubus_invoke(
        ctx, id, "get_clients", NULL, ubus_get_clients_cb, (void *)clients, UBUS_TIMEOUT_MS
    );
    if (res) {
        log_error("UBUS error %d: %s", res, ubus_strerror(res));
        return false;
    }

    return true;
}

List *ubus__get_clients(struct ubus_context *ctx) {
    bool input_ctx = ctx;
    if (!ctx) { ctx = ubus_connect(NULL); }
    if (!ctx) {
        log_error("Failed to connect to UBUS (get_clients).");
        return NULL;
    }

    if (!ubus_populate_hapd_objs(ctx)) {
        if (!input_ctx) { ubus_free(ctx); }
        return NULL;
    }

    // Initialize a list of Clients.
    List *clients = list__new(
        sizeof(Client), sizeof(uint8_t) * ETH_ALEN, (list__key_eq_t)client__key_eq
    );
    if (!clients) {
        if (!input_ctx) { ubus_free(ctx); }
        return NULL;
    }

    // For each obj, get the clients and add to list.
    bool success = false;
    for (unsigned i = 0; i < UBUS_N_HAPD_OBJS; i++) {
        const char *obj_path = UBUS_HAPD_OBJ_NAME_PTRS[i];
        if (!obj_path) { break; }
        uint32_t obj_id = UBUS_HAPD_OBJ_IDS[i];

        dbg("Getting UBUS clients for obj %d (%s)", obj_id, obj_path);
        if (ubus_get_clients(ctx, obj_id, clients)) {
            success = true;
        } else {
            log_error("Failed to get UBUS clients for obj %d (%s).", obj_id, obj_path);
        }
    }

    if (!input_ctx) { ubus_free(ctx); }
    if (success) {
        return clients;
    }
    list__free(clients);
    return NULL;
}
