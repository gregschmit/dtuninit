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

#include "dtuninit/log.h"

#include "shared.h"

const char *client__normalize_mac(const char *s) {
    if (!s) { return NULL; }

    // Use a static buffer to avoid allocations.
    static char normalized_mac[18] = {0};

    unsigned n = 0;
    unsigned i = 0;
    while (s[i]) {
        if (
            (s[i] >= '0' && s[i] <= '9') ||
            (s[i] >= 'a' && s[i] <= 'f') ||
            (s[i] >= 'A' && s[i] <= 'F')
        ) {
            // Return NULL if we find too many hex digits.
            if (n >= sizeof(normalized_mac) - 1) { return NULL; }

            // Store the digit and increment n.
            if ((s[i] >= 'A' && s[i] <= 'F')) {
                // Convert to lowercase.
                normalized_mac[n] = s[i] + ('a' - 'A');
            } else {
                normalized_mac[n] = s[i];
            }
            n++;

            // If n is now on a colon position (every 3rd), add a colon and increment n.
            if (n < sizeof(normalized_mac) - 1 && n % 3 == 2) {
                normalized_mac[n] = ':';
                n++;
            }
        }

        i++;
    }

    return n == 17 ? normalized_mac : NULL;
}

const char *client__mac_s(const Client *c) {
    if (!c) { return NULL; }

    // Re-use a static buffer to avoid allocations.
    static char mac_s[18] = {0};

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

const char *client__protocol_s(const Client *c) {
    if (!c) { return NULL; }

    // Re-use a static buffer to avoid allocations.
    static char proto_s[MAX_PROTO_LEN] = {0};

    switch (c->tun_config.proto) {
        case TUN_PROTO_GRE: {
            strcpy(proto_s, "gre");
            switch (c->tun_config.subproto.gre) {
                case TUN_GRE_SUBPROTO_DEFAULT: {
                    break;
                }
                case TUN_GRE_SUBPROTO_UDP: {
                    strcat(proto_s, "/udp");
                    break;
                }
                default: {
                    return NULL;
                }
            }
            break;
        }
        case TUN_PROTO_L2TP: {
            strcpy(proto_s, "l2tp");
            break;
        }
        case TUN_PROTO_VXLAN: {
            strcpy(proto_s, "vxlan");
            break;
        }
        default: {
            return NULL;
        }
    }

    return proto_s;
}

const char *client__peer_ip_s(const Client *c) {
    if (!c) { return NULL; }

    // Re-use a static buffer to avoid allocations.
    static char peer_ip_s[INET_ADDRSTRLEN] = {0};

    if (!inet_ntop(AF_INET, &c->peer_ip, peer_ip_s, sizeof(peer_ip_s))) {
        return NULL;
    }

    return peer_ip_s;
}

static bool parse_mac(Client *c, const char *mac) {
    if (!check_ptr("parse_mac", "c", c)) { return false; }
    if (!check_ptr("parse_mac", "mac", mac)) { return false; }

    const char *normalized_mac = client__normalize_mac(mac);
    if (!normalized_mac) {
        log_error("Invalid MAC: `%s`", mac);
        return false;
    }

    if (sscanf(
        normalized_mac,
        "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
        &c->mac[0],
        &c->mac[1],
        &c->mac[2],
        &c->mac[3],
        &c->mac[4],
        &c->mac[5]
    ) != ETH_ALEN) {
        log_error("Invalid MAC (sscanf): `%s`", mac);
        return false;
    }

    return true;
}

static char *split(char *s, char delim) {
    char *d = strchr(s, delim);
    if (!d) { return NULL; }
    if (d == s) { return NULL; }
    if (!*(d + 1)) { return NULL; }
    *d = '\0';
    return d + 1;
}

static bool parse_protocol(Client *c, const char *proto) {
    if (!check_ptr("parse_protocol", "c", c)) { return false; }
    if (!check_ptr("parse_protocol", "proto", proto)) { return false; }

    // Parse the protocol/subprotocol.
    static char proto_cpy[MAX_PROTO_LEN] = {0};
    snprintf(proto_cpy, sizeof(proto_cpy), "%s", proto);
    char *subproto = split(proto_cpy, '/');

    // Validate the protocol.
    if (!strcmp(proto_cpy, "gre")) {
        c->tun_config.proto = TUN_PROTO_GRE;
        // TODO: Implement L2TP and VXLAN support.
        // } else if (!strcmp(proto, "l2tp")) {
        //     c->tun_config.proto = TUN_PROTO_L2TP;
        // } else if (!strcmp(proto, "vxlan")) {
        //     c->tun_config.proto = TUN_PROTO_VXLAN;
    } else {
        log_error("Invalid protocol: `%s`", proto);
        return false;
    }

    // Validate the subprotocol.
    if (subproto) {
        switch (c->tun_config.proto) {
            case TUN_PROTO_GRE: {
                if (!strcmp(subproto, "udp")) {
                    c->tun_config.subproto.gre = TUN_GRE_SUBPROTO_UDP;
                } else {
                    log_error("Invalid GRE subprotocol: `%s`", subproto);
                    return false;
                }
                break;
            }
            case TUN_PROTO_L2TP: {
                if (!strcmp(subproto, "v3")) {
                    c->tun_config.subproto.l2tp = TUN_L2TP_SUBPROTO_V3;
                } else {
                    log_error("Invalid L2TP subprotocol: `%s`", subproto);
                    return false;
                }
                break;
            }
            case TUN_PROTO_VXLAN: {
                log_error("Invalid VXLAN subprotocol: `%s`", subproto);
                return false;
                break;
            }
            default: {
                log_error("Invalid protocol `%s` when parsing subprotocol `%s`.", proto, subproto);
                return false;
            }
        }
    }

    return true;
}

static bool parse_peer_ip(Client *c, const char *peer_ip) {
    if (!check_ptr("parse_peer_ip", "c", c)) { return false; }
    if (!check_ptr("parse_peer_ip", "peer_ip", peer_ip)) { return false; }

    if (inet_pton(AF_INET, peer_ip, &c->peer_ip) != 1) {
        log_error("Invalid peer IP: `%s`", peer_ip);
        return false;
    }

    return true;
}

static bool parse_vlan(Client *c, long vlan) {
    if (!check_ptr("parse_vlan", "c", c)) { return false; }

    if (vlan < 0 || vlan > 4094) {
        log_error("Invalid VLAN ID: %ld", vlan);
        return false;
    }

    c->vlan = (uint16_t)vlan;
    return true;
}

bool client__parse(Client *c, const char *mac, const char *proto, const char *peer_ip, long vlan) {
    if (!parse_mac(c, mac)) { return false; }
    if (!parse_protocol(c, proto)) { return false; }
    if (!parse_peer_ip(c, peer_ip)) { return false; }
    if (!parse_vlan(c, vlan)) { return false; }

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

const char *ip_cfg__src_ip_s(const IPCfg *ip_cfg) {
    if (!ip_cfg) { return NULL; }

    // Re-use a static buffer to avoid allocations.
    static char src_ip_s[INET_ADDRSTRLEN] = {0};

    if (!inet_ntop(AF_INET, &ip_cfg->src_ip, src_ip_s, sizeof(src_ip_s))) {
        return NULL;
    }

    return src_ip_s;
}

const char *ip_cfg__peer_ip_s(const IPCfg *ip_cfg) {
    if (!ip_cfg) { return NULL; }

    // Re-use a static buffer to avoid allocations.
    static char peer_ip_s[INET_ADDRSTRLEN] = {0};

    if (!inet_ntop(AF_INET, &ip_cfg->peer_ip, peer_ip_s, sizeof(peer_ip_s))) {
        return NULL;
    }

    return peer_ip_s;
}
