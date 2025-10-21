# dtuninit (Dynamic Tunnel Initiator)

This project implements a tunnel initiator using a userspace daemon and a set of BPF programs. The
daemon mounts the BPF programs to the configured interfaces (should at minimum be mounted to the
WLAN interface and the interface that wires the AP into the network). The BPF program then manages
the encapsulation and decapsulation of packets between the client and the peer (responder).

## TODO

- Modify watch logic to reload when interfaces change (needed for being a reasonable daemon).
- Add ubus support to support conversion of clients with radius attributes to clients file entries.
- Fix cross compiling with ubox/ubus libs.
- Fix static building on Debian: `undefined symbol: eu_search_tree_init`.
- Implement GRE over UDP to support NAT.
- Implement VXLAN.
- Implement L2TPv3.
- Add support for IPv6 endpoints.

## Development

Ensure you clone using the `--recurse-submodules` flag, or initialize the submodules afterwards:

```sh
git submodule update --init --recursive
```

### Coding Guidelines

- Adhere to the style defined in the `.clang-format` file.
- Use types from `stdbool.h` and `stdint.h` rather than vaguely-sized types. If a standard/external
  library takes or returns specific types, then use those types.
- Use `bool` for function returns where only success/failure is needed (rather than `int`).
- Validate input pointers are not `NULL` with `check_ptr` to hopefully ensure production segfaults
  are paired with a useful log message to help debugging.
- Use the logging facilities provided by `log.h` rather than `printf` or `fprintf`.
- Use `snprintf` rather than `strncpy` to avoid forgetting to null-terminate strings.
- Use typedef structs for brevity.
