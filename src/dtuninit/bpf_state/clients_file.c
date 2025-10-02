/*
 * This module provides facilities for the management of the Clients file.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdlib.h>
#include <unistd.h>

#include "../../shared.h"
#include "../bpf_state.h"
#include "../list.h"
#include "../log.h"

#include "clients_file.h"

static char *split(const char *s, char delim) {
    char *d = strchr(s, delim);
    if (!d) { return NULL; }
    if (d == s) { return NULL; }
    if (!*(d + 1)) { return NULL; }
    *d = '\0';
    return d + 1;
}

static bool populate_ip_cfg_src_ip(IPCfg *ip_cfg) {
    // Create UDP socket.
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        log_errno("socket");
        return false;
    }

    // Set up dst address.
    struct sockaddr_in dst_addr;
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(53);  // DNS port, but any port works.
    dst_addr.sin_addr = ip_cfg->peer_ip;

    // Connect to destination (this doesn't actually send packets for UDP).
    if (connect(sockfd, (struct sockaddr*)&dst_addr, sizeof(dst_addr)) < 0) {
        log_errno("connect");
        close(sockfd);
        return false;
    }

    // Get the local address the kernel assigned.
    struct sockaddr_in src_addr;
    socklen_t src_addr_len = sizeof(src_addr);
    if (getsockname(sockfd, (struct sockaddr*)&src_addr, &src_addr_len) < 0) {
        log_errno("getsockname");
        close(sockfd);
        return false;
    }

    // Copy the src IP.
    ip_cfg->src_ip = src_addr.sin_addr;

    close(sockfd);

    return true;
}

static bool populate_ip_cfg_ifindex(IPCfg *ip_cfg) {
    if (!ip_cfg) { return false; }

    struct ifaddrs *ifaddr;
    if (getifaddrs(&ifaddr) == -1) {
        log_errno("getifaddrs");
        return false;
    }

    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) { continue; }

        // If this is an IPv4 address and it matches, set ifindex and break.
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;

            if (sin->sin_addr.s_addr == ip_cfg->src_ip.s_addr) {
                ip_cfg->ifindex = if_nametoindex(ifa->ifa_name);
                break;
            }

            // NOTE: If needed in future, could also get netmask here with ifa->ifa_netmask.
        }
    }

    // NOTE: If needed in future, could also get L2 data here by:
    //   - Checking `ifa->ifa_addr->sa_family == AF_PACKET`.
    //   - Casting to `struct sockaddr_ll *` and copying `sll_addr` to `ip_cfg->src_mac`.
    //   - Inspecting `sll_ifindex`.
    // This would probably have to be done in a separate loop after the above loop, because
    // `AF_PACKET` is not guaranteed to come after `AF_INET` and in my experience it typically comes
    // before. But we would want to match the IP addr first.

    freeifaddrs(ifaddr);
    return ip_cfg->ifindex != 0;
}

// Ensure `src_ip` is set to 0 if any of the population steps fail.
static bool populate_ip_cfg(IPCfg *ip_cfg) {
    if (!ip_cfg || !ip_cfg->peer_ip.s_addr) { return false; }

    // Determine src IP for this GRE IP.
    if (!populate_ip_cfg_src_ip(ip_cfg)) {
        log_error("Failed to determine src IP for GRE IP: %s", inet_ntoa(ip_cfg->peer_ip));
        ip_cfg->src_ip.s_addr = 0;
        return false;
    }

    // Determine ifindex.
    if (!populate_ip_cfg_ifindex(ip_cfg)) {
        log_error("Failed to determine ifindex for src IP: %s", inet_ntoa(ip_cfg->src_ip));
        ip_cfg->src_ip.s_addr = 0;
        return false;
    }

    return true;
}

void bpf_state__parse_clients(BPFState *s, List *clients, List *ip_cfgs) {
    if (!s || !clients || !ip_cfgs) { return; }

    FILE *fp = fopen(s->clients_path, "r");
    if (!fp) {
        if (errno == ENOENT) {
            // It's actually a normal condition for the file to not exist.
            dbg_errno("fopen");
        } else {
            // Other errors should be logged.
            log_errno("fopen");
            log_error("Failed to open Clients file.");
        }
        return;
    }

    // Read file line by line into the client list.
    char linebuf[256] = "";
    while (fgets(linebuf, sizeof(linebuf), fp)) {
        // Ignore comments.
        if (linebuf[0] == '#') { continue; }

        // Parse the line, logging but otherwise disregarding any errors.
        Client client = {.cycle = s->cycle};
        char protocol[16] = "";
        char args[128] = "";
        int n = sscanf(
            linebuf,
            "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx %15s %127[^\n]",
            &client.mac[0],
            &client.mac[1],
            &client.mac[2],
            &client.mac[3],
            &client.mac[4],
            &client.mac[5],
            protocol,
            args
        );

        if (n != 8) {
            log_error("Failed to parse line: `%s`", linebuf);
            continue;
        }

        char *subprotocol = split(protocol, '/');

        if (strcmp(protocol, "gre")) {
            log_error("Unsupported protocol: `%s`", protocol);
            continue;
        }
        client.tun_config.proto = TUN_PROTO_GRE;

        if (!strcmp(subprotocol, "v0")) {
            client.tun_config.subproto.gre = TUN_GRE_SUBPROTO_V0;
        } else {
            log_error("Unsupported GRE subprotocol: `%s`", subprotocol);
            continue;
        }

        char *peer_ip = strtok(args, " ");
        if (!peer_ip) {
            log_error("Missing Peer IP in line: `%s`", linebuf);
            continue;
        }

        if (!inet_pton(AF_INET, peer_ip, &client.peer_ip)) {
            log_error("Failed to parse Peer IP: `%s`", peer_ip);
            continue;
        }

        while (1) {
            // Get next arg.
            char *key = strtok(NULL, " ");
            if (!key) { break; }

            // Parse into key/value.
            char *value = NULL;
            if (!(value = split(key, '='))) { break; }

            // For now, only support vlan key.
            if (!strcmp(key, "vlan")) {
                unsigned long vlan = strtoul(value, NULL, 10);
                if (!vlan || vlan > 4094) {
                    log_error("Invalid VLAN: `%s`", value);
                    continue;
                }
                client.vlan = (uint16_t)vlan;
            } else {
                log_error("Unsupported client argument: `%s`", key);
            }
        }

        // See if we already have an IP Config.
        IPCfg *ip_cfg = list__find(ip_cfgs, &client.peer_ip);
        if (ip_cfg) {
            // If the config is not valid, then we previously failed to populate it, so skip this
            // client.
            if (!ip_cfg__is_valid(ip_cfg)) {
                continue;
            }
        } else {
            // We haven't seen this GRE IP before, so populate a new IP config and add it to the
            // list. If we fail to populate it fully, then skip this client. But add the IP config
            // regardless so we don't try again for subsequent clients with the same GRE IP.
            IPCfg ip_cfg = {.peer_ip = client.peer_ip, .cycle = s->cycle};
            if (!populate_ip_cfg(&ip_cfg)) {
                log_error("Failed to populate IP config for IP: %s", peer_ip);
                continue;
            }

            if (!list__add(ip_cfgs, &ip_cfg)) {
                log_error("Failed to add IP config for IP: %s", peer_ip);
                continue;
            }
        }

        if (!list__add(clients, &client)) {
            log_error(
                "Failed to add client for MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                client.mac[0],
                client.mac[1],
                client.mac[2],
                client.mac[3],
                client.mac[4],
                client.mac[5]
            );
        }
    }

    fclose(fp);
}

bool bpf_state__insert_clients(BPFState *s, List *clients) {
    // TODO: Implement insertion of clients into the clients file.
    return false;
}

bool bpf_state__remove_client(BPFState *s, uint8_t mac[ETH_ALEN]) {
    // TODO: Implement removal of a client from the clients file.
    return false;
}
