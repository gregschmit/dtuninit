#ifndef BPF_STATE__WATCH__UBUS_H
#define BPF_STATE__WATCH__UBUS_H

#include <libubus.h>

#include "../../bpf_state.h"

char **bpf_state__watch__ubus__list(BPFState *s, char *path);

#endif  // BPF_STATE__WATCH__UBUS_H
