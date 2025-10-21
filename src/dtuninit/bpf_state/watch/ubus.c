#include "../../log.h"
#include "ubus.h"

char **bpf_state__watch__ubus__list(BPFState *s, char *path) {
    if (!check_ptr("bpf_state__watch__ubus__list", "s", s)) { return NULL; }
    if (!check_ptr("bpf_state__watch__ubus__list", "path", path)) { return NULL; }

    struct ubus_context *ctx = ubus_connect(NULL);
    if (!ctx) {
        return NULL;
    }

    ubus_free(ctx);
    return NULL;
}
