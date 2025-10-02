#ifndef WATCH_H
#define WATCH_H

#include <stdbool.h>

#include "list.h"
#include "bpf_state.h"

bool watch(BPFState *state);

#endif  // WATCH_H
