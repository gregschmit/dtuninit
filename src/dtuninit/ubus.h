#ifndef UBUS_H
#define UBUS_H

#include <libubus.h>

#include "list.h"

const char **bpf_state__ubus__hapd_list(struct ubus_context *ctx);
List *bpf_state__ubus__get_clients(struct ubus_context *ctx);

#endif  // UBUS_H
