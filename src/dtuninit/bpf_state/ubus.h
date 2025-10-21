#ifndef BPF_STATE__UBUS_H
#define BPF_STATE__UBUS_H

#include <libubus.h>

#include "../bpf_state.h"

#define UBUS_MAX_HAPD_LIST 32
#define UBUS_MAX_HAPD_NAME_LEN 256

static char UBUS_HAPD_LIST[UBUS_MAX_HAPD_LIST][UBUS_MAX_HAPD_NAME_LEN] = {0};

bool bpf_state__ubus__hapd_list();

#endif  // BPF_STATE__UBUS_H
