#ifndef BPF_STATE__CLIENTS_FILE_H
#define BPF_STATE__CLIENTS_FILE_H

#include <netinet/ether.h>
#include <stdbool.h>

#include "../../shared.h"
#include "../bpf_state.h"
#include "../list.h"

void bpf_state__clients_file__parse(BPFState *s, List *clients, List *ip_cfgs);
bool bpf_state__clients_file__insert(BPFState *s, List *clients);
bool bpf_state__clients_file__remove_s(BPFState *s, const char *mac_s);
bool bpf_state__clients_file__remove(BPFState *s, uint8_t mac[ETH_ALEN]);
bool bpf_state__clients_file__dump(BPFState *s);

#endif  // BPF_STATE__CLIENTS_FILE_H
