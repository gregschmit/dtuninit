#ifndef WATCH_H
#define WATCH_H

#include <stdbool.h>

#include "../bpf_state.h"
#include "../list.h"

bool bpf_state__watch(BPFState *state);

#endif  // WATCH_H
