#ifndef UBUS_H
#define UBUS_H

#include <libubus.h>

#include "list.h"

const char **ubus__hapd_list(struct ubus_context *ctx);
List *ubus__get_clients(struct ubus_context *ctx);

#endif  // UBUS_H
