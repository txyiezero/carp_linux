# CARP for Linux

**Common Address Redundancy Protocol (CARP) - Linux Kernel Port**

Ported from FreeBSD 14.4-RELEASE (ip_carp.c) to Linux 6.12 (Debian 13.6).

## Overview

CARP allows multiple hosts on the same local network to share a set of
IPv4 and/or IPv6 addresses. Its primary purpose is to ensure that these
addresses are always available, providing host-level redundancy.

This is a **full kernel-level implementation** of CARP for Linux, maintaining
**wire-level compatibility** with FreeBSD and OpenBSD CARP implementations.

## Architecture

```
carp_linux/
├── kmod/              Kernel module sources
│   ├── carp_internal.h   Internal header (structs, macros, declarations)
│   ├── carp_main.c       Module init/exit, state machine, lifecycle
│   ├── carp_input.c      Packet reception, HMAC-SHA1, loop detection
│   ├── carp_output.c     Advertisement sending, source MAC, NF hook
│   ├── carp_route.c      Route management (IPv4/IPv6)
│   ├── carp_netlink.c    Netlink interface, multicast, ARP/NDP hooks
│   └── Makefile          Kbuild Makefile
├── tools/             Userspace management
│   ├── carpctl           CLI management tool (netlink-based)
│   └── Makefile
├── include/           Shared headers
│   └── carp.h            UAPI header (kernel ↔ userspace)
├── tests/             Test scripts
│   ├── carp_basic.sh     Integration test (ip netns)
│   └── Makefile
├── doc/
│   ├── README.md         This file
│   └── PORTABILITY.md    Portability analysis
├── DKMS/
│   └── dkms.conf         DKMS configuration
├── .github/workflows/
│   └── build.yml         CI build pipeline
└── Makefile               Top-level build
```

## Building

### Kernel Module

```bash
cd kmod
make
sudo insmod carp.ko
```

### Userspace Tool

```bash
cd tools
make
sudo make install
```

## Usage

### Loading the Module

```bash
# Load with default settings
sudo modprobe carp

# Load with custom settings
sudo insmod carp.ko carp_allow=1 carp_preempt=0 carp_dscp=56

# Module parameters:
#   carp_allow      - Accept incoming CARP packets (0/1, default: 1)
#   carp_preempt    - Preempt slower masters (0/1, default: 0)
#   carp_log        - Log level (0/1/2, default: 1)
#   carp_dscp       - DSCP for outgoing packets (0-63, default: 56)
#   carp_senderr_adj - Send error demotion factor (default: 240)
#   carp_ifdown_adj  - Interface down demotion factor (default: 240)
```

### Using carpctl

```bash
# Add a CARP VHID
sudo carpctl add eth0 1

# Add with options
sudo carpctl add eth0 1 --advbase 1 --advskew 0 --password mysecret

# Set state
sudo carpctl set eth0 1 --state MASTER

# Check status
sudo carpctl status
sudo carpctl status eth0
sudo carpctl status eth0 1

# Delete
sudo carpctl del eth0 1
```

### Monitoring

```bash
# View statistics
cat /proc/net/carp/stats

# View interfaces
cat /proc/net/carp/interfaces

# Watch for state changes
udevadm monitor | grep CARP
```

## Features

### Perfectly Ported (Same Behavior as FreeBSD)
- CARP state machine (INIT → BACKUP → MASTER)
- HMAC-SHA1 authentication
- Advertisement interval (advbase + advskew)
- Master-down detection (3× advbase timeout)
- Send error demotion (3 failures → demote, 3 successes → undemote)
- Interface down demotion
- Virtual MAC (00:00:5e:00:01:XX)
- Source MAC replacement on outgoing traffic (NF hook)
- Loop detection (VHID=0 self-packet detection)
- Route management (IPv4 + IPv6) on state change
- Gratuitous ARP/NA on MASTER transition
- Multicast group management (224.0.0.18 / ff02::12)
- ARP/NDP address matching hooks (EXPORT_SYMBOL)
- Bridge MAC matching (carp_forus)
- Netlink configuration interface

### Ported With Different API (Same Behavior)
- Protocol 112 registration (net_protocol vs ipproto_register)
- Sysctl → module_param + /proc/net/carp/
- FreeBSD ioctl → Generic Netlink
- VNET → global list + RCU
- callout → timer_list
- taskqueue → workqueue (schedule_work)
- mbuf → sk_buff
- NET_EPOCH → RCU
- ifpromisc → dev_set_promiscuity
- ifa_ref → in_dev_hold

## Compatibility

### Wire Compatibility

100% wire-compatible with FreeBSD/OpenBSD CARP:
- IP protocol 112
- Multicast: 224.0.0.18 (IPv4), ff02::12 (IPv6)
- CARP header: 36 bytes, identical layout
- Virtual MAC: 00:00:5e:00:01:XX
- HMAC-SHA1 authentication

### Cross-Platform Testing

```bash
# Linux side
sudo modprobe carp
sudo carpctl add eth0 1 --advbase 1 --password sharedkey

# FreeBSD side
ifconfig eth0 vhid 1 advbase 1 pass sharedkey 192.168.1.100/24
```

## Module Source Files

| File | Lines | Purpose |
|------|-------|---------|
| `carp_internal.h` | 158 | Shared header: structs, macros, declarations |
| `carp_main.c` | 702 | Module init/exit, state machine, lifecycle, NF hook, /proc |
| `carp_input.c` | 395 | HMAC-SHA1, packet reception, loop detection |
| `carp_output.c` | 482 | Advertisement sending, demotion, source address selection |
| `carp_route.c` | 85 | IPv4/IPv6 route management |
| `carp_netlink.c` | 392 | Netlink interface, multicast, ARP/NDP/bridge hooks |

## License

BSD-2-Clause (matching original FreeBSD CARP license)
