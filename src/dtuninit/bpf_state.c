/*
 * This module manages the lifecycle of the BPF programs, updating the shared BPF maps, and
 * providing reload hooks.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <linux/if_packet.h>

#include <bpf/libbpf.h>

#include "../shared.h"
#include "list.h"
#include "log.h"

#include "bpf_state.h"
#include "bpf_state/clients_file.h"

void bpf_state__close_links(BPFState *s) {
    if (!check_ptr("bpf_state__close_links", "s", s)) { return; }

    for (unsigned i = 0; i < s->n_links; i++) {
        bpf_link__destroy(s->links[i]);
    }
    s->n_links = 0;
}

void bpf_state__close(BPFState *s) {
    if (!check_ptr("bpf_state__close", "s", s)) { return; }

    bpf_state__close_links(s);

    if (s->obj) {
        bpf_object__close(s->obj);
    }

    free(s);
}

BPFState *bpf_state__open(char *clients_path, char **input_ifs) {
    if (!check_ptr("bpf_state__open", "clients_path", clients_path)) { return NULL; }
    if (!check_ptr("bpf_state__open", "input_ifs", input_ifs)) { return NULL; }

    BPFState *s = calloc(1, sizeof(BPFState));
    if (!s) {
        log_errno("calloc");
        log_error("Failed to allocate memory for BPF state.");
        return NULL;
    }

    // Copy the clients path.
    snprintf(s->clients_path, sizeof(s->clients_path), "%s", clients_path);

    // Copy the input interfaces.
    if (input_ifs && input_ifs[0]) {
        unsigned n = 0;
        while (n < MAX_IFS && input_ifs[n]) { n++; }
        s->n_input_ifs = n;
        for (unsigned i = 0; i < n; i++) {
            snprintf(s->input_ifs[i], sizeof(s->input_ifs[i]), "%s", input_ifs[i]);
        }
    }

    return s;
}

bool bpf_state__load_bpf(BPFState *s, const char *bpf_path) {
    // Open and load the BPF object file.
    if (!(s->obj = bpf_object__open(bpf_path))) {
        log_errno("bpf_object__open");
        log_error("Failed to open BPF object file: %s", bpf_path);
        return false;
    }

    // Load the BPF object into the kernel.
    if (bpf_object__load(s->obj)) {
        log_errno("bpf_object__load");
        log_error("Failed to load BPF object.");
        bpf_object__close(s->obj);
        s->obj = NULL;
        return false;
    }

    // Ensure the BPF programs exist.
    if (!bpf_state__get_xdp_program(s)) {
        log_error("Failed to find XDP program.");
        bpf_object__close(s->obj);
        s->obj = NULL;
        return false;
    }
    if (!bpf_state__get_tci_program(s)) {
        log_error("Failed to find TCI program.");
        bpf_object__close(s->obj);
        s->obj = NULL;
        return false;
    }

    // Find the client map and clear it.
    struct bpf_map *client_map = bpf_state__get_client_map(s);
    if (!client_map) {
        log_error("Failed to find client BPF map.");
        bpf_object__close(s->obj);
        s->obj = NULL;
        return false;
    }
    bpf_state__clear_client_map(s);

    // Find the IP config map and clear it.
    struct bpf_map *ip_cfg_map = bpf_state__get_ip_cfg_map(s);
    if (!ip_cfg_map) {
        log_error("Failed to find IP config BPF map.");
        bpf_object__close(s->obj);
        s->obj = NULL;
        return false;
    }
    bpf_state__clear_ip_cfg_map(s);

    // Find the VLAN Config map and clear it.
    struct bpf_map *vlan_cfg_map = bpf_state__get_vlan_cfg_map(s);
    if (!vlan_cfg_map) {
        log_error("Failed to find VLAN Config BPF map.");
        bpf_object__close(s->obj);
        s->obj = NULL;
        return false;
    }
    bpf_state__clear_vlan_cfg_map(s);

    return true;
}

static bool bpf_state__reload_ifdata(BPFState *s) {
    if (!s) { return false; }

    // Clear existing interfaces.
    s->n_ifs = 0;

    // Handle case where interfaces are provided as input.
    if (s->n_input_ifs) {
        // Copy valid input interfaces to state.
        for (unsigned i = 0; i < s->n_input_ifs; i++) {
            // Get ifindex.
            unsigned ifindex = if_nametoindex(s->input_ifs[i]);
            if (!ifindex) {
                log_errno("if_nametoindex");
                log_error("Failed to find interface %s.", s->input_ifs[i]);
                continue;
            }

            // Skip if ifindex already exists.
            bool found = false;
            for (unsigned j = 0; j < s->n_ifs; j++) {
                if (s->ifindexes[j] == ifindex) {
                    found = true;
                    break;
                }
            }
            if (found) { continue; }

            // Add this interface index/name to the list.
            s->ifindexes[s->n_ifs] = ifindex;
            snprintf(s->ifs[s->n_ifs], sizeof(s->ifs[s->n_ifs]), "%s", s->input_ifs[i]);
            s->n_ifs++;
        }

        return s->n_ifs;
    }

    // Otherwise, auto-detect interfaces.
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr)) {
        log_errno("getifaddrs");
        log_error("Failed to get network interfaces.");
        return false;
    }
    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (s->n_ifs >= MAX_IFS) {
            log_error("Exceeded max interfaces (%d); ignoring remaining.", MAX_IFS);
            break;
        }
        if (ifa->ifa_addr == NULL) { continue; }

        // Only consider L2 interfaces.
        if (ifa->ifa_addr->sa_family != AF_PACKET) { continue; }

        // Cast to sockaddr_ll to access hardware type.
        struct sockaddr_ll *sll = (struct sockaddr_ll *)ifa->ifa_addr;

        // Skip loopback and non-ethernet interfaces.
        if (sll->sll_hatype != ARPHRD_ETHER) { continue; }

        // Get ifindex.
        unsigned ifindex = if_nametoindex(ifa->ifa_name);
        if (!ifindex) {
            log_errno("if_nametoindex");
            log_error("Failed to find interface %s.", ifa->ifa_name);
            continue;
        }

        // Skip if ifindex already exists.
        bool found = false;
        for (unsigned i = 0; i < s->n_ifs; i++) {
            if (s->ifindexes[i] == ifindex) {
                found = true;
                break;
            }
        }
        if (found) { continue; }

        // Add this interface index/name to the list.
        s->ifindexes[s->n_ifs] = ifindex;
        snprintf(s->ifs[s->n_ifs], sizeof(s->ifs[s->n_ifs]), "%s", ifa->ifa_name);
        s->n_ifs++;
    }
    freeifaddrs(ifaddr);

    return s->n_ifs;
}

bool bpf_state__reload_interfaces(BPFState *s) {
    if (!s) {
        log_error("No BPF state!");
        return false;
    }
    if (!s->obj) {
        log_error("No BPF object loaded!");
        return false;
    }

    if (!bpf_state__reload_ifdata(s)) {
        log_error("No Ethernet interfaces available to attach to.");
        bpf_state__close_links(s);
        return false;
    }

    // Close links AFTER reloading interface data to reduce downtime.
    bpf_state__close_links(s);

    // Get handles for the BPF programs.
    struct bpf_program *prog_xdp = bpf_state__get_xdp_program(s);
    if (!prog_xdp) {
        log_error("Failed to find XDP program.");
        return false;
    }
    struct bpf_program *prog_tci = bpf_state__get_tci_program(s);
    if (!prog_tci) {
        log_error("Failed to find TCI program.");
        return false;
    }

    // Attach the BPF programs to each interface.
    for (unsigned i = 0; i < s->n_ifs; i++) {
        // Attach XDP program.
        s->links[s->n_links] = bpf_program__attach_xdp(prog_xdp, s->ifindexes[i]);
        if (s->links[s->n_links]) {
            log_info("Attached XDP prog to if %s (ifindex %d).", s->ifs[i], s->ifindexes[i]);
            s->n_links++;
        } else {
            log_errno("bpf_program__attach_xdp");
            log_error("Failed to attach XDP prog to if %s.", s->ifs[i]);
            continue;
        }

        // Attach TCI program.
        s->links[s->n_links] = bpf_program__attach_tcx(prog_tci, s->ifindexes[i], NULL);
        if (s->links[s->n_links]) {
            log_info("Attached TC ingress prog to if %s (ifindex %d).", s->ifs[i], s->ifindexes[i]);
            s->n_links++;
        } else {
            log_errno("bpf_program__attach_tcx");
            log_error("Failed to attach TC ingress prog to if %s.", s->ifs[i]);
            continue;
        }
    }

    if (s->n_links == 0) {
        log_info("Failed to attach BPF programs to any interface.");
        return false;
    }

    return true;
}

bool bpf_state__reload_clients(BPFState *s) {
    if (!check_ptr("bpf_state__reload_clients", "s", s)) { return false; }

    // Get the map objects.
    struct bpf_map *client_map = bpf_state__get_client_map(s);
    if (!client_map) {
        log_error("Failed to get client map.");
        return false;
    }
    struct bpf_map *ip_cfg_map = bpf_state__get_ip_cfg_map(s);
    if (!ip_cfg_map) {
        log_error("Failed to get IP config map.");
        return false;
    }

    // Create client and IP config lists.
    List *clients = list__new(
        sizeof(Client), sizeof(uint8_t) * ETH_ALEN, (list__key_eq_t)client__key_eq
    );
    if (!clients) { return false; }
    List *ip_cfgs = list__new(
        sizeof(IPCfg), sizeof(struct in_addr), (list__key_eq_t)ip_cfg__key_eq
    );
    if (!ip_cfgs) {
        list__free(clients);
        return false;
    }

    // Overflow is perfectly normal here.
    s->cycle++;

    // Parse map file to populate the lists.
    bpf_state__clients_file__parse(s, clients, ip_cfgs);

    // Update the IP config map.
    for (size_t i = 0; i < ip_cfgs->length; i++) {
        IPCfg ip_cfg = ((IPCfg *)ip_cfgs->items)[i];

        if (bpf_map__update_elem(
            ip_cfg_map, &ip_cfg.peer_ip, sizeof(ip_cfg.peer_ip), &ip_cfg, sizeof(ip_cfg), BPF_ANY
        )) {
            log_error("Failed to update IP map for %s", ip_cfg__peer_ip_s(&ip_cfg));
            continue;
        }
    }

    // Update the client map.
    for (size_t i = 0; i < clients->length; i++) {
        Client client = ((Client *)clients->items)[i];
        if (bpf_map__update_elem(
            client_map, &client.mac, sizeof(client.mac), &client, sizeof(client), BPF_ANY
        )) {
            log_error("Failed to update client map for %s", client__mac_s(&client));
            continue;
        }
    }

    // Remove stale entries.
    bpf_state__remove_stale_clients(s, clients);
    bpf_state__remove_stale_ip_cfgs(s, ip_cfgs);

    list__free(clients);
    list__free(ip_cfgs);

    return true;
}

struct bpf_program *bpf_state__get_xdp_program(BPFState *s) {
    if (!s || !s->obj) { return NULL; }
    return bpf_object__find_program_by_name(s->obj, "dtuninit_xdp");
}

struct bpf_program *bpf_state__get_tci_program(BPFState *s) {
    if (!s || !s->obj) { return NULL; }
    return bpf_object__find_program_by_name(s->obj, "dtuninit_tci");
}

struct bpf_map *bpf_state__get_client_map(BPFState *s) {
    if (!s || !s->obj) { return NULL; }
    return bpf_object__find_map_by_name(s->obj, "client_map");
}

struct bpf_map *bpf_state__get_ip_cfg_map(BPFState *s) {
    if (!s || !s->obj) { return NULL; }
    return bpf_object__find_map_by_name(s->obj, "ip_cfg_map");
}

struct bpf_map *bpf_state__get_vlan_cfg_map(BPFState *s) {
    if (!s || !s->obj) { return NULL; }
    return bpf_object__find_map_by_name(s->obj, "vlan_cfg_map");
}

void bpf_state__clear_client_map(BPFState *s) {
    struct bpf_map *client_map = bpf_state__get_client_map(s);
    if (!client_map) { return; }

    uint8_t key[ETH_ALEN], next_key[ETH_ALEN];

    // Get the first key.
    int res = bpf_map__get_next_key(client_map, NULL, key, ETH_ALEN);
    if (res) {
        if (res != -ENOENT) {
            log_error("Failed to get first key from client map (%d).", res);
        }

        return;
    }

    while (res == 0) {
        // Get the next key before deleting the current key.
        res = bpf_map__get_next_key(client_map, key, next_key, ETH_ALEN);

        // Delete the current key.
        if (bpf_map__delete_elem(client_map, key, ETH_ALEN, BPF_ANY) != 0) {
            log_errno("bpf_map__delete_elem");
            log_error("Failed to delete key from client map.");
            return;
        }

        // Copy next key to key for the next iteration.
        if (res == 0) {
            memcpy(key, next_key, ETH_ALEN);
        }
    }

    if (res != -ENOENT) {
        log_error("Failed to get next key from client map.");
    }
}

void bpf_state__clear_ip_cfg_map(BPFState *s) {
    struct bpf_map *ip_cfg_map = bpf_state__get_ip_cfg_map(s);
    if (!ip_cfg_map) { return; }

    struct in_addr key, next_key;

    // Get the first key.
    int res = bpf_map__get_next_key(ip_cfg_map, NULL, &key, sizeof(key));
    if (res) {
        if (res != -ENOENT) {
            log_error("Failed to get first key from IP config map (%d).", res);
        }

        return;
    }

    while (res == 0) {
        // Get the next key before deleting the current key.
        res = bpf_map__get_next_key(ip_cfg_map, &key, &next_key, sizeof(next_key));

        // Delete the current key.
        if (bpf_map__delete_elem(ip_cfg_map, &key, sizeof(key), BPF_ANY) != 0) {
            log_errno("bpf_map__delete_elem");
            log_error("Failed to delete key from IP config map.");
            return;
        }

        // Copy next key to key for the next iteration.
        if (res == 0) {
            key = next_key;
        }
    }

    if (res != -ENOENT) {
        log_error("Failed to get next key from IP config map.");
    }
}

void bpf_state__clear_vlan_cfg_map(BPFState *s) {
    struct bpf_map *vlan_cfg_map = bpf_state__get_vlan_cfg_map(s);
    if (!vlan_cfg_map) { return; }

    uint16_t key, next_key;

    // Get the first key.
    int res = bpf_map__get_next_key(vlan_cfg_map, NULL, &key, sizeof(key));
    if (res) {
        if (res != -ENOENT) {
            log_error("Failed to get first key from VLAN Config map (%d).", res);
        }

        return;
    }

    while (res == 0) {
        // Get the next key before deleting the current key.
        res = bpf_map__get_next_key(vlan_cfg_map, &key, &next_key, sizeof(next_key));

        // Delete the current key.
        if (bpf_map__delete_elem(vlan_cfg_map, &key, sizeof(key), BPF_ANY) != 0) {
            log_errno("bpf_map__delete_elem");
            log_error("Failed to delete key from VLAN config map.");
            return;
        }

        // Copy next key to key for the next iteration.
        if (res == 0) {
            key = next_key;
        }
    }

    if (res != -ENOENT) {
        log_error("Failed to get next key from VLAN config map.");
    }
}

void bpf_state__remove_stale_clients(BPFState *s, List *clients) {
    if (!s || !clients) { return; }

    struct bpf_map *client_map = bpf_state__get_client_map(s);
    if (!client_map) { return; }

    uint8_t key[ETH_ALEN], next_key[ETH_ALEN];

    // Get the first key.
    int res = bpf_map__get_next_key(client_map, NULL, key, ETH_ALEN);
    if (res) {
        if (res != -ENOENT) {
            log_error("Failed to get first key from client map (%d).", res);
        }

        return;
    }

    while (!res) {
        // Get the next key before possibly deleting the current key.
        res = bpf_map__get_next_key(client_map, key, next_key, ETH_ALEN);

        // Look up the client to check its cycle.
        Client client;
        if (bpf_map__lookup_elem(client_map, key, ETH_ALEN, &client, sizeof(client), 0)) {
            log_error("Failed to look up client in client map.");
            return;
        } else {
            if (client.cycle != s->cycle) {
                // Cycle doesn't match, so remove this stale entry.
                if (bpf_map__delete_elem(client_map, key, ETH_ALEN, BPF_ANY) != 0) {
                    log_error("Failed to delete stale key from client map.");
                    return;
                }
            }
        }

        // Copy next key to key for the next iteration.
        if (res == 0) {
            memcpy(key, next_key, ETH_ALEN);
        }
    }

    if (res != -ENOENT) {
        log_error("Failed to get next key from client map.");
    }
}

void bpf_state__remove_stale_ip_cfgs(BPFState *s, List *ip_cfgs) {
    if (!s || !ip_cfgs) { return; }

    struct bpf_map *ip_cfg_map = bpf_state__get_ip_cfg_map(s);
    if (!ip_cfg_map) { return; }

    struct in_addr key, next_key;

    // Get the first key.
    int res = bpf_map__get_next_key(ip_cfg_map, NULL, &key, sizeof(key));
    if (res) {
        if (res != -ENOENT) {
            log_error("Failed to get first key from IP config map (%d).", res);
        }

        return;
    }

    while (!res) {
        // Get the next key before possibly deleting the current key.
        res = bpf_map__get_next_key(ip_cfg_map, &key, &next_key, sizeof(next_key));

        // Look up the IP config to check its cycle.
        IPCfg ip_cfg;
        if (bpf_map__lookup_elem(ip_cfg_map, &key, sizeof(key), &ip_cfg, sizeof(ip_cfg), 0)) {
            log_error("Failed to look up IP config in IP config map.");
            return;
        } else {
            if (ip_cfg.cycle != s->cycle) {
                // Cycle doesn't match, so remove this stale entry.
                if (bpf_map__delete_elem(ip_cfg_map, &key, sizeof(key), BPF_ANY) != 0) {
                    log_error("Failed to delete stale key from IP config map.");
                    return;
                }
            }
        }

        // Copy next key to key for the next iteration.
        if (res == 0) {
            key = next_key;
        }
    }

    if (res != -ENOENT) {
        log_error("Failed to get next key from IP config map.");
    }
}

// static unsigned bpf_state__get_num_clients(BPFState *s) {
//     if (!s) { return 0; }

//     struct bpf_map *client_map = bpf_state__get_client_map(s);
//     if (!client_map) { return 0; }

//     uint8_t key[ETH_ALEN], next_key[ETH_ALEN];
//     unsigned count = 0;
//     int res = bpf_map__get_next_key(client_map, NULL, key, ETH_ALEN);
//     while (res == 0) {
//         count++;
//         res = bpf_map__get_next_key(client_map, key, next_key, ETH_ALEN);
//         if (res == 0) {
//             memcpy(key, next_key, ETH_ALEN);
//         }
//     }

//     return count;
// }

// static unsigned bpf_state__get_num_ip_cfgs(BPFState *s) {
//     if (!s) { return 0; }

//     struct bpf_map *ip_cfg_map = bpf_state__get_ip_cfg_map(s);
//     if (!ip_cfg_map) { return 0; }

//     struct in_addr key, next_key;
//     unsigned count = 0;
//     int res = bpf_map__get_next_key(ip_cfg_map, NULL, &key, sizeof(key));
//     while (res == 0) {
//         count++;
//         res = bpf_map__get_next_key(ip_cfg_map, &key, &next_key, sizeof(next_key));
//         if (res == 0) {
//             key = next_key;
//         }
//     }

//     return count;
// }
