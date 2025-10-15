# dtuninit (Dynamic Tunnel Initiator)

This project implements a tunnel initiator using a userspace daemon and a set of BPF programs. The
daemon mounts the BPF programs to the configured interfaces (should at minimum be mounted to the
WLAN interface and the interface that wires the AP into the network). The BPF program then manages
the encapsulation and decapsulation of packets between the client and the peer (responder).

## TODO

- Modify watch logic to reload when interfaces change (needed for being a reasonable daemon).
- Add ubus support to support conversion of clients with radius attributes to clients file entries.
- Implement GRE over UDP to support NAT.
- Implement VXLAN.
- Implement L2TPv3.
- Add support for IPv6 endpoints.

## Development

Ensure you clone using the `--recurse-submodules` flag, or initialize the submodules afterwards:

```sh
git submodule update --init --recursive
```
