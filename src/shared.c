/*
 * Code for shared definitions.
 *
 * NOTE: While the definitions are shared between kernel and userspace, the functions here are only
 * for the userspace daemon. Therefore, use of standard library is allowed.
 */

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <string.h>

#include "shared.h"

char *client__mac_s(Client *c) {
    if (!c) { return NULL; }

    // Re-use a static buffer to avoid allocations.
    static char mac_s[18];

    snprintf(
        mac_s,
        sizeof(mac_s),
        "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
        c->mac[0],
        c->mac[1],
        c->mac[2],
        c->mac[3],
        c->mac[4],
        c->mac[5]
    );

    return mac_s;
}

bool client__parse_mac(Client *c, const char *mac_s) {
    if (
        sscanf(
            mac_s,
            "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
            &c->mac[0],
            &c->mac[1],
            &c->mac[2],
            &c->mac[3],
            &c->mac[4],
            &c->mac[5]
        ) != ETH_ALEN
    ) { return false; }

    return true;
}

static char *split(const char *s, char delim) {
    char *d = strchr(s, delim);
    if (!d) { return NULL; }
    if (d == s) { return NULL; }
    if (!*(d + 1)) { return NULL; }
    *d = '\0';
    return d + 1;
}

bool client__parse_tun_config(Client *c, char *proto) {
    if (!c || !proto) { return false; }

    // Parse the protocol/subprotocol.
    char *subproto = split(proto, '/');

    // Validate the protocol.
    if (!strcmp(proto, "gre")) {
        c->tun_config.proto = TUN_PROTO_GRE;
        // TODO: Implement L2TP and VXLAN support.
        // } else if (!strcmp(proto, "l2tp")) {
        //     c->tun_config.proto = TUN_PROTO_L2TP;
        // } else if (!strcmp(proto, "vxlan")) {
        //     c->tun_config.proto = TUN_PROTO_VXLAN;
    } else {
        return false;
    }

    // Validate the subprotocol.
    if (subproto) {
        switch (c->tun_config.proto) {
            case TUN_PROTO_GRE: {
                if (!strcmp(subproto, "udp")) {
                    c->tun_config.subproto.gre = TUN_GRE_SUBPROTO_UDP;
                } else {
                    return false;
                }
                break;
            }
            case TUN_PROTO_L2TP: {
                if (!strcmp(subproto, "v3")) {
                    c->tun_config.subproto.l2tp = TUN_L2TP_SUBPROTO_V3;
                } else {
                    return false;
                }
                break;
            }
            case TUN_PROTO_VXLAN: {
                return false;
            }
        }
    }

    return true;
}

bool client__parse_peer_ip(Client *c, const char *peer_ip_s) {
    if (!c || !peer_ip_s) { return false; }

    if (inet_pton(AF_INET, peer_ip_s, &c->peer_ip) != 1) {
        return false;
    }

    return true;
}

bool client__key_eq(const uint8_t *key1, const uint8_t *key2) {
    return memcmp(key1, key2, ETH_ALEN) == 0;
}

bool ip_cfg__key_eq(const struct in_addr *key1, const struct in_addr *key2) {
    return key1->s_addr == key2->s_addr;
}

// Use the src_ip to determine validity. In the program logic, if there is a problem populating part
// of the config, then the src_ip should be set to 0.
bool ip_cfg__is_valid(const IPCfg *ip_cfg) {
    if (!ip_cfg) { return false; }
    if (ip_cfg->src_ip.s_addr == 0) { return false; }

    return true;
}
