#ifndef BPF_STATE__WATCH_H
#define BPF_STATE__WATCH_H

#include <stdbool.h>

#include "../bpf_state.h"
#include "../list.h"

bool bpf_state__watch(BPFState *s);

#endif  // BPF_STATE__WATCH_H
