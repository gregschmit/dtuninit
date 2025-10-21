#ifndef BPF_STATE__UBUS_H
#define BPF_STATE__UBUS_H

#include <libubus.h>

#include "../bpf_state.h"
#include "../list.h"

const char **bpf_state__ubus__hapd_list();
List *bpf_state__ubus__get_clients();

#endif  // BPF_STATE__UBUS_H
