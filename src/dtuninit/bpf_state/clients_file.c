/*
 * This module provides facilities for the management of the Clients file.
 *
 * The format of the Clients file is JSON, where the top level structure is an object where MAC
 * addresses (in the form of `xx:xx:xx:xx:xx:xx`, LOWERCASE hex digits separated by colons) are the
 * keys and the values are objects containing client structure data.
 *
 * For the MAC addresses, sticking to this convention makes it easy to avoid duplicates and easy to
 * lookup clients by MAC address.
 *
 * NOTE: The methods `serialize` and `deserialize` are tightly coupled.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdlib.h>
#include <unistd.h>

#include "cJSON.h"

#include "../../shared.h"
#include "../bpf_state.h"
#include "../list.h"
#include "../log.h"

#include "clients_file.h"

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

static bool check_mac(const char *s) {
    static const bool fmt_hex[17] = {
        true, true, false,
        true, true, false,
        true, true, false,
        true, true, false,
        true, true, false,
        true, true
    };

    for (unsigned i = 0; i < sizeof(fmt_hex); i++) {
        if (!s[i]) { return false; }  // Too short.
        if (fmt_hex[i]) {
            // Return false if char is not 0-9 or a-z (LOWERCASE ONLY).
            if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) {
                return false;
            }
        } else {
            // Return false if char is not ':'.
            if (s[i] != ':') {
                return false;
            }
        }
    }

    return s[sizeof(fmt_hex)] == '\0';  // Return false if too long.
}

static cJSON *read_clients_json(const char *path) {
    // Open file and read it in.
    FILE *fp = fopen(path, "r");
    if (!fp) {
        if (errno == ENOENT) {
            // It's actually a normal condition for the file to not exist.
            dbg_errno("fopen");
        } else {
            // Other errors should be logged.
            log_errno("fopen");
            log_error("Failed to open clients file.");
        }
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    if (file_size < 0) {
        log_errno("ftell");
        log_error("Failed to determine size of clients file.");
        fclose(fp);
        return NULL;
    } else if (file_size == 0) {
        fclose(fp);
        return NULL;
    }
    rewind(fp);
    char *text = malloc(file_size + 1);
    if (!text) {
        log_errno("malloc");
        log_error("Failed to allocate memory for clients file.");
        fclose(fp);
        return NULL;
    }
    size_t n_read = fread(text, 1, file_size, fp);
    if (n_read != (size_t)file_size) {
        if (ferror(fp)) {
            log_errno("fread");
        }
        log_error("Failed to read clients file.");
        fclose(fp);
        free(text);
        return NULL;
    }

    // Close file now that we're done with it.
    fclose(fp);

    // Parse as JSON.
    cJSON *json = cJSON_Parse(text);
    free(text);
    if (!json) {
        log_error("Failed to parse clients file as JSON.");
        return NULL;
    }

    // Ensure it's a JSON object.
    if (!cJSON_IsObject(json)) {
        log_error("Clients file is not a JSON object.");
        cJSON_Delete(json);
        return NULL;
    }

    return json;
}

// Special helper to format the clients JSON with indentation and newlines. It will look like this:
//   {
//     "xx:xx:xx:xx:xx:xx": {...},
//     ...
//   }
static char *format_clients_json(cJSON *json) {
    if (!json) { return NULL; }

    // Initialize a buffer.
    size_t size = 256;
    size_t idx = 0;
    char *buf = calloc(size, sizeof(*buf));
    if (!buf) {
        log_error("Failed to allocate memory for clients JSON string.");
        return NULL;
    }
    strcpy(buf, "{\n");
    idx += 2;

    // Iterate through entries, outputting each key/value on a line, expanding the buffer as needed
    // by doubling the size.
    cJSON *client_json = NULL;
    cJSON_ArrayForEach(client_json, json) {
        // Format the key (MAC address).
        const char *mac_s = client_json->string;
        if (!mac_s) {
            log_error("Client has no MAC address.");
            continue;
        }
        if (!check_mac(mac_s)) {
            log_error("Invalid MAC address: `%s`", mac_s);
            continue;
        }

        // Convert the value to a string.
        char *value_json = cJSON_PrintUnformatted(client_json);
        if (!value_json) {
            log_error("Failed to convert client JSON to string for %s.", mac_s);
            continue;
        }

        // Determine size of this new entry. This should include:
        // - 4 (two initial spaces and quotes around MAC)
        // - size of MAC address
        // - 2 (colon and space)
        // - size of value_json
        // - 2 (trailing comma and newline)
        size_t entry_len = 4 + strlen(mac_s) + 2 + strlen(value_json) + 2;

        // Expand the buffer if needed.
        while (idx + entry_len > size) {
            size *= 2;
            char *new_buf = realloc(buf, size);
            if (!new_buf) {
                log_error("Failed to allocate memory for clients JSON string.");
                free(value_json);
                free(buf);
                return NULL;
            }
            buf = new_buf;
        }

        // Format the entry and copy it into the buffer.
        sprintf(buf + idx, "  \"%s\": %s,\n", mac_s, value_json);
        idx += entry_len;

        free(value_json);
    }

    // Remove trailing comma, if we added any entries.
    if (idx > 2) {
        buf[idx - 2] = '\n';
        idx -= 1;
    }

    // Add closing brace.
    while (idx + 2 > size) {
        size += 2;
        char *new_buf = realloc(buf, size);
        if (!new_buf) {
            log_error("Failed to allocate memory for clients JSON string.");
            free(buf);
            return NULL;
        }
        buf = new_buf;
    }
    strcpy(buf + idx, "}\n");

    return buf;
}

static bool write_clients_json(const char *path, cJSON *json) {
    if (!path || !json) { return false; }

    // Convert to string.
    char *text = format_clients_json(json);
    if (!text) { return false; }

    // Open file for writing (create or truncate).
    FILE *fp = fopen(path, "w");
    if (!fp) {
        log_errno("fopen");
        log_error("Failed to open clients file for writing.");
        free(text);
        return false;
    }

    // Write to file.
    size_t text_len = strlen(text);
    size_t n_written = fwrite(text, 1, text_len, fp);
    if (n_written != text_len) {
        if (ferror(fp)) {
            log_errno("fwrite");
        }
        log_error("Failed to write to clients file.");
        fclose(fp);
        free(text);
        return false;
    }

    // Close file now that we're done with it.
    if (fclose(fp) != 0) {
        log_errno("fclose");
        log_error("Failed to close clients file after writing.");
        free(text);
        return false;
    }

    free(text);
    return true;
}

static bool deserialize(cJSON *client_json, Client *client) {
    if (!client_json || !client) { return false; }

    // Parse the MAC address (the key).
    const char *mac_s = client_json->string;
    if (!mac_s) {
        log_error("Client has no MAC address.");
        return false;
    }
    if (!check_mac(mac_s)) {
        log_error("Invalid MAC address format: `%s`", mac_s);
        return false;
    }
    if (!client__parse_mac(client, mac_s)) {
        log_error("Invalid MAC address: `%s`", mac_s);
        return false;
    }

    // Parse the protocol/subprotocol.
    cJSON *proto_json = cJSON_GetObjectItemCaseSensitive(client_json, "protocol");
    if (!proto_json || !cJSON_IsString(proto_json) || !proto_json->valuestring) {
        log_error("Missing protocol for %s", mac_s);
        return false;
    }
    if (!client__parse_tun_config(client, proto_json->valuestring)) {
        log_error("Invalid tunnel config `%s` for %s", proto_json->valuestring, mac_s);
        return false;
    }

    // Parse and validate the peer IP.
    cJSON *peer_ip_json = cJSON_GetObjectItemCaseSensitive(client_json, "peer_ip");
    if (!peer_ip_json || !cJSON_IsString(peer_ip_json) || !peer_ip_json->valuestring) {
        log_error("Missing peer IP for %s", mac_s);
        return false;
    }
    if (!client__parse_peer_ip(client, peer_ip_json->valuestring)) {
        log_error("Invalid peer IP `%s` for %s", peer_ip_json->valuestring, mac_s);
        return false;
    }

    // Parse and validate the VLAN (optional).
    cJSON *vlan_json = cJSON_GetObjectItemCaseSensitive(client_json, "vlan");
    if (vlan_json) {
        if (!cJSON_IsNumber(vlan_json)) {
            log_error("Invalid VLAN for %s: not a number", mac_s);
            return false;
        }
        if (vlan_json->valueint < 1 || vlan_json->valueint > 4094) {
            log_error("Invalid VLAN `%d` for %s", vlan_json->valueint, mac_s);
            return false;
        }
        client->vlan = (uint16_t)vlan_json->valueint;
    }

    return true;
}

void bpf_state__clients_file__parse(BPFState *s, List *clients, List *ip_cfgs) {
    if (!s || !clients || !ip_cfgs) { return; }

    cJSON *json = read_clients_json(s->clients_path);
    if (!json) { return; }

    // Iterate through entries, printing the key and value JSON.
    cJSON *client_json = NULL;
    cJSON_ArrayForEach(client_json, json) {
        Client client = {.cycle = s->cycle};
        if (!deserialize(client_json, &client)) {
            continue;
        }

        // For logging.
        const char *mac_s = client_json->string;
        const char *peer_ip_s = inet_ntoa(client.peer_ip);

        // Ensure there is a corresponding IP config for this client's peer IP.
        IPCfg *ip_cfg = list__find(ip_cfgs, &client.peer_ip);
        if (ip_cfg) {
            // If the config is not valid, then we previously failed to populate it, so skip this
            // client.
            if (!ip_cfg__is_valid(ip_cfg)) {
                log_error("Skipping %s for previous IP config failure.", mac_s);
                continue;
            }
        } else {
            // We haven't seen this peer IP before, so populate a new IP config and add it to the
            // list. If we fail to populate it fully, then skip this client. But add the IP config
            // regardless so we don't try again for subsequent clients with the same peer IP.
            IPCfg ip_cfg = {.peer_ip = client.peer_ip, .cycle = s->cycle};
            if (!populate_ip_cfg(&ip_cfg)) {
                log_error("Failed to populate IP config for %s (%s).", mac_s, peer_ip_s);
                continue;
            }

            if (!list__add(ip_cfgs, &ip_cfg)) {
                log_error("Failed to add IP config for %s (%s).", mac_s, peer_ip_s);
                continue;
            }
        }

        // Add the client if we get here.
        if (!list__add(clients, &client)) {
            log_error("Failed to add client %s.", mac_s);
        }
    }

    cJSON_Delete(json);
}

static void serialize(cJSON *json, const Client *client) {
    // Format the MAC address as a string.
    char mac_s[18];
    snprintf(
        mac_s,
        sizeof(mac_s),
        "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
        client->mac[0],
        client->mac[1],
        client->mac[2],
        client->mac[3],
        client->mac[4],
        client->mac[5]
    );

    // Create the JSON object for this client.
    cJSON *client_json = cJSON_CreateObject();
    if (!client_json) {
        log_error("Failed to create JSON object for %s.", mac_s);
        return;
    }

    // Add the protocol/subprotocol.
    char proto[16];
    switch (client->tun_config.proto) {
        case TUN_PROTO_GRE: {
            strcpy(proto, "gre");
            switch (client->tun_config.subproto.gre) {
                case TUN_GRE_SUBPROTO_UDP: {
                    strcat(proto, "/udp");
                    break;
                }
                default: { break; }
            }
            break;
        }
        case TUN_PROTO_L2TP: {
            strcpy(proto, "l2tp");
            break;
        }
        case TUN_PROTO_VXLAN: {
            strcpy(proto, "vxlan");
            break;
        }
    }
    cJSON *proto_json = cJSON_CreateString(proto);
    if (!proto_json) {
        log_error("Failed to create protocol string for %s.", mac_s);
        cJSON_Delete(client_json);
        return;
    }
    if (!cJSON_AddItemToObject(client_json, "protocol", proto_json)) {
        log_error("Failed to add protocol to JSON object for %s.", mac_s);
        cJSON_Delete(proto_json);
        cJSON_Delete(client_json);
        return;
    }

    // Add the peer IP.
    char peer_ip_s[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &client->peer_ip, peer_ip_s, sizeof(peer_ip_s))) {
        log_errno("inet_ntop");
        log_error("Failed to convert peer IP to string for %s.", mac_s);
        cJSON_Delete(client_json);
        return;
    }
    cJSON *peer_ip_json = cJSON_CreateString(peer_ip_s);
    if (!peer_ip_json) {
        log_error("Failed to create peer IP string for %s.", mac_s);
        cJSON_Delete(client_json);
        return;
    }
    if (!cJSON_AddItemToObject(client_json, "peer_ip", peer_ip_json)) {
        log_error("Failed to add peer IP to JSON object for %s.", mac_s);
        cJSON_Delete(peer_ip_json);
        cJSON_Delete(client_json);
        return;
    }

    // Add the VLAN, if set.
    if (client->vlan) {
        cJSON *vlan_json = cJSON_CreateNumber(client->vlan);
        if (!vlan_json) {
            log_error("Failed to create VLAN number for %s.", mac_s);
            cJSON_Delete(client_json);
            return;
        }
        if (!cJSON_AddItemToObject(client_json, "vlan", vlan_json)) {
            log_error("Failed to add VLAN to JSON object for %s.", mac_s);
            cJSON_Delete(vlan_json);
            cJSON_Delete(client_json);
            return;
        }
    }

    // Before inserting, remove any existing entries (cJSON allows multiple).
    while (cJSON_HasObjectItem(json, mac_s)) {
        cJSON_DeleteItemFromObject(json, mac_s);
    }

    // Add the client JSON object to the main JSON object.
    if (!cJSON_AddItemToObject(json, mac_s, client_json)) {
        log_error("Failed to add payload to JSON object for %s.", mac_s);
        cJSON_Delete(client_json);
        return;
    }
}

bool bpf_state__clients_file__insert(BPFState *s, List *clients) {
    if (!s || !clients) { return false; }

    cJSON *json = read_clients_json(s->clients_path);
    if (!json) {
        // If the file doesn't exist or is empty/invalid, start with an empty JSON object.
        json = cJSON_CreateObject();
        if (!json) {
            log_error("Failed to create clients JSON object.");
            return false;
        }
    }

    // Insert each client into the JSON object.
    for (size_t i = 0; i < clients->length; i++) {
        Client client = ((Client *)clients->items)[i];
        serialize(json, &client);
    }

    // Write the updated JSON back to the file.
    bool success = write_clients_json(s->clients_path, json);

    cJSON_Delete(json);
    return success;
}

bool bpf_state__clients_file__remove_s(BPFState *s, const char *mac_s) {
    if (!s || !mac_s) { return false; }
    if (!check_mac(mac_s)) {
        log_error("Invalid MAC address: `%s`", mac_s);
        return false;
    }

    cJSON *json = read_clients_json(s->clients_path);
    if (!json) { return false; }

    // Remove the entry for this MAC address.
    cJSON_DeleteItemFromObjectCaseSensitive(json, mac_s);

    // Write the updated JSON back to the file.
    bool success = write_clients_json(s->clients_path, json);

    cJSON_Delete(json);
    return success;
}

bool bpf_state__clients_file__remove(BPFState *s, uint8_t mac[ETH_ALEN]) {
    if (!s || !mac) { return false; }

    char mac_s[18];
    snprintf(
        mac_s,
        sizeof(mac_s),
        "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );

    return bpf_state__clients_file__remove_s(s, mac_s);
}

bool bpf_state__clients_file__dump(BPFState *s) {
    if (!s) { return false; }

    cJSON *json = read_clients_json(s->clients_path);
    if (!json) { return false; }

    char *text = cJSON_Print(json);
    if (!text) {
        cJSON_Delete(json);
        return false;
    }
    log_info("%s", text);

    free(text);
    cJSON_Delete(json);
    return true;
}
