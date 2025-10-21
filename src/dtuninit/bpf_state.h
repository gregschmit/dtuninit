#ifndef BPF_STATE_H
#define BPF_STATE_H

#include <limits.h>
#include <stdbool.h>

#include <bpf/libbpf.h>

#include "../shared.h"
#include "list.h"

typedef struct {
    // These properties are set once, when opening the state.
    char clients_path[PATH_MAX];
    unsigned n_input_ifs;
    char input_ifs[MAX_IFS][MAX_IF_NAME_LEN];
    struct bpf_object *obj;
    uint8_t cycle;  // For removing stale map entries efficiently.

    // These properties are set for each reload.
    unsigned n_ifs;
    unsigned ifindexes[MAX_IFS];
    char ifs[MAX_IFS][MAX_IF_NAME_LEN];
    unsigned n_links;
    struct bpf_link *links[(MAX_IFS * 2)];  // XDP + TCI per interface.
} BPFState;

void bpf_state__close_links(BPFState *s);
void bpf_state__close(BPFState *s);
BPFState *bpf_state__open(char *clients_path, char **input_ifs);
bool bpf_state__load_bpf(BPFState *s, const char *bpf_path);
bool bpf_state__reload_interfaces(BPFState *s);
bool bpf_state__reload_clients(BPFState *s);

struct bpf_program *bpf_state__get_xdp_program(BPFState *s);
struct bpf_program *bpf_state__get_tci_program(BPFState *s);

struct bpf_map *bpf_state__get_client_map(BPFState *s);
struct bpf_map *bpf_state__get_ip_cfg_map(BPFState *s);
struct bpf_map *bpf_state__get_vlan_cfg_map(BPFState *s);
void bpf_state__clear_client_map(BPFState *s);
void bpf_state__clear_ip_cfg_map(BPFState *s);
void bpf_state__clear_vlan_cfg_map(BPFState *s);
void bpf_state__remove_stale_clients(BPFState *s, List *clients);
void bpf_state__remove_stale_ip_cfgs(BPFState *s, List *ip_cfgs);

#endif  // BPF_STATE_H
