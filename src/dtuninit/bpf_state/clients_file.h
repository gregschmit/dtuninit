#ifndef BPF_STATE__CLIENTS_FILE_H
#define BPF_STATE__CLIENTS_FILE_H

#include <netinet/ether.h>
#include <stdbool.h>

#include "../../shared.h"
#include "../bpf_state.h"
#include "../list.h"

void bpf_state__parse_clients(BPFState *s, List *clients, List *ip_cfgs);
bool bpf_state__insert_clients(BPFState *s, List *clients);
bool bpf_state__remove_client(BPFState *s, uint8_t mac[ETH_ALEN]);

#endif  // BPF_STATE__CLIENTS_FILE_H
